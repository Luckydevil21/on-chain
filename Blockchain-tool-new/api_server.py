"""
====================================================================
 API SERVER - a JSON API in front of your four investigation tools
====================================================================

WHAT THIS IS:
A FastAPI web server that wraps wallet_watcher.py, victim_collator.py,
link_tracer.py, and crypto_address_watcher.py so a web frontend (a
Base44 app, or anything else that can call a REST API) can use them,
instead of running each script by hand.

It does NOT reimplement any of the blockchain-fetching logic - every
endpoint here calls the SAME functions already tested in those four
files (imported as modules). If you fix a bug or add a chain to
wallet_watcher.py, this API picks it up automatically next restart -
there's no separate copy of that logic to keep in sync.

====================================================================
 HOW TO RUN THIS LOCALLY
====================================================================
STEP 1 - Install the extra library this needs on top of what the
    other four scripts already require:
        pip install fastapi "uvicorn[standard]"

STEP 2 - Set a private API key (REQUIRED - this protects every
    endpoint below, since some of them read your case data and all
    of them make real outbound network calls on your behalf):
        export TOOLKIT_API_KEY="choose-a-long-random-string-here"
    (Windows PowerShell: $env:TOOLKIT_API_KEY = "...")
    If you skip this, the server will generate a temporary one and
    print it to the console every time it starts - fine for a quick
    local test, useless for anything you leave running.

STEP 3 - Also set ETHERSCAN_API_KEY, same as the other scripts, if
    you'll be querying Ethereum wallets.

STEP 4 - Run it:
        uvicorn api_server:app --reload --port 8000
    Then open http://127.0.0.1:8000/docs in a browser - that's a
    free interactive test page FastAPI builds for you automatically.
    Click "Authorize" and paste in your TOOLKIT_API_KEY to try any
    endpoint from the browser.

====================================================================
 CONNECTING THIS TO BASE44
====================================================================
Once this is running somewhere reachable over HTTPS (see DEPLOYING
below), the URL you need is:
        https://your-server-address/openapi.json
FastAPI builds this file automatically - it's a full machine-readable
description of every endpoint below. In Base44, a workspace admin
imports that URL as a "Custom Integration" (Connect to Third-Party
APIs), enters your TOOLKIT_API_KEY as the credential, and every app
in the workspace can then call these endpoints through the Base44
SDK - your API key is proxied through Base44's own backend and never
reaches the browser.

====================================================================
 DEPLOYING (making this reachable from the internet, not just your PC)
====================================================================
Any host that can run a long-lived Python process works - Railway,
Render, Fly.io, or a small VPS are all reasonable, cheap options for
a solo/small-team tool like this. In broad strokes:
    1. Push this folder (all five .py files + requirements.txt) to
       a Git repository.
    2. Point your chosen host at it, with this as the start command:
            uvicorn api_server:app --host 0.0.0.0 --port $PORT
    3. Set TOOLKIT_API_KEY and ETHERSCAN_API_KEY as environment
       variables on the host - the exact same names as locally.
    4. Once it's live, use ITS url (not localhost) as the OpenAPI
       URL you give Base44.

====================================================================
 A HONEST NOTE ON DATA STORAGE
====================================================================
case_watchlist.json and known_entities.json remain the single source
of truth - the SAME files wallet_watcher.py, link_tracer.py, and the
desktop dashboard already read from, so nothing gets out of sync
between your desktop tools and the web app. Every write here goes
through a lock so two requests can't corrupt the file at the same
moment. This is the right amount of engineering for a solo/small-team
tool - but flat JSON files are not built to handle many concurrent
users. If this ever grows into a bigger team tool, that's the point
to migrate these two files into a real database (SQLite to start).
====================================================================
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import time
import secrets
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Optional

import requests
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

# ---- The four existing scripts, imported as modules. Importing them
# does NOT run their CLI/__main__ sections - only their top-level
# constants and function definitions execute. ----
import wallet_watcher as ww
import victim_collator as vc
import link_tracer as lt
import crypto_address_watcher as caw
import auth
import email_sender


# ====================================================================
# SECTION 1: AUTH - user logins (roles) + the original static API key
# ====================================================================
# Two ways in, both supported at once:
#   1. A logged-in browser session (see auth.py) - real usernames,
#      two roles: "admin" (full read/write) and "read_only" (can run
#      wallet checks/traces/collation and view every list, but can't
#      add/delete watchlist entries, known entities, or start a scan).
#   2. The original TOOLKIT_API_KEY header - kept working exactly as
#      before, for scripts/automation/Base44 integrations. Always
#      treated as full admin access.
# ====================================================================

_configured_api_key = os.environ.get("TOOLKIT_API_KEY")
if not _configured_api_key:
    _configured_api_key = secrets.token_urlsafe(32)
    print("=" * 70)
    print("⚠️  TOOLKIT_API_KEY was not set - generated a TEMPORARY one for")
    print("    this run only (it will be different next time you start the")
    print("    server, and anyone reading these logs can see it):")
    print(f"        {_configured_api_key}")
    print("    Set the TOOLKIT_API_KEY environment variable before relying")
    print("    on this, and definitely before deploying it anywhere.")
    print("=" * 70)

auth.bootstrap_admin_from_env()

# --------------------------------------------------------------
# Basic brute-force protection: after too many failed login/API-key
# attempts from the same IP within the window, further attempts are
# blocked for a while. This is IN-MEMORY and PER-PROCESS - it resets
# if the server restarts, and does NOT share state across multiple
# server instances/workers. Acceptable for a single-instance
# deployment (what this toolkit is built for); move it to a shared
# store (e.g. Redis) if you ever run multiple replicas.
# --------------------------------------------------------------
_RATE_LIMIT_WINDOW_SECONDS = 300   # 5 minutes
_RATE_LIMIT_MAX_FAILURES = 10      # block further attempts after this many failures in the window
_failed_auth_attempts = defaultdict(list)  # {client_ip: [timestamp, ...]}


def _check_rate_limit(client_ip):
    """Raises 429 if this IP has failed too many auth attempts recently."""
    now = time.time()
    recent_failures = [t for t in _failed_auth_attempts[client_ip] if now - t < _RATE_LIMIT_WINDOW_SECONDS]
    _failed_auth_attempts[client_ip] = recent_failures
    if len(recent_failures) >= _RATE_LIMIT_MAX_FAILURES:
        raise HTTPException(
            status_code=429,
            detail="Too many failed authentication attempts from this address. Try again in a few minutes.",
        )


def _record_auth_failure(client_ip):
    _failed_auth_attempts[client_ip].append(time.time())


def require_read(request: Request):
    """Any logged-in user (either role) or a valid API key. Use for read-only endpoints."""
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    user = auth.get_current_user_from_request(request, _configured_api_key)
    if not user:
        _record_auth_failure(client_ip)
        raise HTTPException(status_code=401, detail="Not authenticated - log in or provide a valid X-API-Key.")
    return user


def require_write(request: Request):
    """Admin role (or a valid API key) only. Use for anything that adds/deletes/triggers something."""
    user = require_read(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="This action requires admin access.")
    return user


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = Field(..., description='"admin" or "read_only"')
    email: str = Field(default="", description="Needed for that user to use 'forgot password'.")


class Verify2FARequest(BaseModel):
    temp_token: str
    code: str


class Confirm2FASetupRequest(BaseModel):
    code: str


class Disable2FARequest(BaseModel):
    password: str


class ForgotPasswordRequest(BaseModel):
    identifier: str = Field(..., description="Username or email")


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


# ====================================================================
# SECTION 2: APP SETUP
# ====================================================================

app = FastAPI(
    title="On-Chain Investigations Toolkit API",
    description=(
        "JSON API wrapping wallet_watcher.py, victim_collator.py, "
        "link_tracer.py, and crypto_address_watcher.py for use by a web "
        "frontend such as a Base44 app. Every endpoint (except /health) "
        "requires an X-API-Key header."
    ),
    version="1.0.0",
)

_allowed_origins_setting = os.environ.get("TOOLKIT_ALLOWED_ORIGINS", "*")
_allowed_origins = (
    ["*"] if _allowed_origins_setting == "*"
    else [origin.strip() for origin in _allowed_origins_setting.split(",")]
)
if _allowed_origins == ["*"]:
    print("=" * 70)
    print("⚠️  TOOLKIT_ALLOWED_ORIGINS was not set - CORS is wide open (any")
    print("    website can call this API from a browser, though a valid")
    print("    X-API-Key is still required for every real endpoint). Fine")
    print("    for local testing; before running this anywhere reachable")
    print("    over the network, set it to your actual frontend's origin:")
    print("        TOOLKIT_ALLOWED_ORIGINS=https://your-app.up.railway.app")
    print("=" * 70)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    PLAIN ENGLISH: Adds a handful of standard browser-security headers
    to every response. These don't replace HTTPS (get that from your
    hosting platform or a reverse proxy like Caddy) - they're
    additional, cheap protections against a few common attacks:
      - X-Content-Type-Options: stops the browser "guessing" a file's
        type in a way that could be exploited.
      - X-Frame-Options: stops this site being loaded inside a hidden
        iframe on someone else's page (clickjacking).
      - Referrer-Policy: stops the URL of this app leaking to other
        sites via the referrer header.
      - Strict-Transport-Security: once you ARE being served over
        HTTPS, tells the browser to only ever connect via HTTPS from
        now on. Harmless to send even before you have HTTPS set up -
        browsers ignore it entirely over a plain HTTP connection.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response

# Guards every write to case_watchlist.json / known_entities.json, since
# several endpoints (and crypto_address_watcher.py's own sync function)
# can write to the same file.
_file_lock = threading.Lock()


STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@app.get("/", include_in_schema=False)
def serve_frontend():
    """Serves the web frontend (static/index.html) at the root URL."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return {
        "service": "On-Chain Investigations Toolkit API",
        "note": "static/index.html not found - place the frontend file there to serve it here.",
        "docs": "/docs",
        "openapi_spec": "/openapi.json",
    }


@app.get("/api", include_in_schema=False)
def api_info():
    return {
        "service": "On-Chain Investigations Toolkit API",
        "docs": "/docs",
        "openapi_spec": "/openapi.json",
    }


@app.get("/health")
def health():
    """Unauthenticated - for hosting-platform health checks."""
    return {"status": "ok"}


# ====================================================================
# SECTION 2B: AUTH ENDPOINTS (login/logout/whoami/user management)
# ====================================================================

@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    user = auth.authenticate(req.username, req.password)
    if not user:
        _record_auth_failure(client_ip)
        raise HTTPException(status_code=401, detail="Incorrect username or password.")

    if user["totp_enabled"]:
        # Correct password, but 2FA is on - do NOT issue a real session
        # yet. Hand back a short-lived pending token that must be
        # combined with a valid TOTP code at /api/auth/2fa/verify.
        pending_token = auth.create_totp_pending_token(user["username"])
        return {"requires_totp": True, "temp_token": pending_token}

    auth.set_session_cookie(response, user["username"], user["role"])
    return {"requires_totp": False, "username": user["username"], "role": user["role"]}


@app.post("/api/auth/2fa/verify")
def verify_2fa_login(req: Verify2FARequest, request: Request, response: Response):
    """Second step of login when 2FA is enabled - exchanges a valid
    pending token + current TOTP code for a real session cookie."""
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    username = auth.verify_totp_pending_token(req.temp_token)
    if not username:
        _record_auth_failure(client_ip)
        raise HTTPException(status_code=401, detail="That login attempt has expired - please sign in again.")

    user_record = auth._get_user_record(username)
    if not user_record or not auth.verify_totp_code(user_record.get("totp_secret"), req.code):
        _record_auth_failure(client_ip)
        raise HTTPException(status_code=401, detail="Incorrect code.")

    auth.set_session_cookie(response, user_record["username"], user_record["role"])
    return {"username": user_record["username"], "role": user_record["role"]}


@app.post("/api/auth/logout")
def logout(response: Response):
    auth.clear_session_cookie(response)
    return {"logged_out": True}


@app.get("/api/auth/me")
def get_me(current_user=Depends(require_read)):
    """Tells the frontend who's logged in and what they can do, so it can show/hide admin-only controls."""
    full_record = auth._get_user_record(current_user["username"]) or {}
    return {
        "username": current_user["username"],
        "role": current_user["role"],
        "totp_enabled": bool(full_record.get("totp_enabled")),
    }


# ---- Two-factor authentication setup (for your OWN logged-in account) ----

@app.post("/api/auth/2fa/setup")
def setup_2fa(current_user=Depends(require_read)):
    """Starts 2FA setup for the CURRENTLY LOGGED IN account. Not yet
    active - call /api/auth/2fa/confirm with a code from your
    authenticator app to actually turn it on."""
    if current_user["username"] == "api-key":
        raise HTTPException(400, "2FA doesn't apply to API-key access - it's only for user logins.")
    secret, uri, qr_base64 = auth.begin_totp_setup(current_user["username"])
    return {"secret": secret, "otpauth_uri": uri, "qr_code_base64": qr_base64}


@app.post("/api/auth/2fa/confirm")
def confirm_2fa(req: Confirm2FASetupRequest, current_user=Depends(require_read)):
    if not auth.confirm_totp_setup(current_user["username"], req.code):
        raise HTTPException(400, "Incorrect code - check your authenticator app and try again.")
    return {"enabled": True}


@app.post("/api/auth/2fa/disable")
def disable_2fa(req: Disable2FARequest, current_user=Depends(require_read)):
    if current_user["username"] == "api-key":
        raise HTTPException(400, "2FA doesn't apply to API-key access.")
    if not auth.disable_totp(current_user["username"], req.password):
        raise HTTPException(401, "Incorrect password.")
    return {"disabled": True}


# ---- Forgot / reset password ----

@app.post("/api/auth/forgot-password")
def forgot_password(req: ForgotPasswordRequest, request: Request):
    """
    Always returns the SAME response whether or not the account
    exists - this is deliberate, so this endpoint can't be used to
    check which usernames/emails are registered. If an account with
    an email address on file is found, a reset link is emailed to it.
    """
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)  # this endpoint could otherwise be used to spam an inbox

    username = auth.find_username_by_identifier(req.identifier)
    if username:
        user_record = auth._get_user_record(username)
        email = user_record.get("email") if user_record else None
        if email:
            token = auth.generate_password_reset_token(username)
            email_sender.send_password_reset_email(email, username, token)
        # If the account has no email on file, we silently do nothing -
        # still returning the same generic response below either way.

    return {"message": "If an account matching that username or email exists and has an email address on file, a reset link has been sent."}


@app.post("/api/auth/reset-password")
def reset_password(req: ResetPasswordRequest):
    try:
        success = auth.reset_password_with_token(req.token, req.new_password)
    except ValueError as error:
        raise HTTPException(400, str(error))
    if not success:
        raise HTTPException(400, "That reset link is invalid or has expired - request a new one.")
    return {"reset": True}


@app.get("/api/users")
def get_users(_admin=Depends(require_write)):
    return auth.list_users()


@app.post("/api/users")
def add_user(req: CreateUserRequest, _admin=Depends(require_write)):
    try:
        auth.create_user(req.username, req.password, req.role, email=req.email)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    return {"added": True}


@app.delete("/api/users/{username}")
def remove_user(username: str, current_user=Depends(require_write)):
    if username.lower() == current_user["username"].lower():
        raise HTTPException(status_code=400, detail="You can't delete your own account while logged in as it.")
    if not auth.delete_user(username):
        raise HTTPException(status_code=404, detail="No user with that username.")
    return {"deleted": True}


# ====================================================================
# SECTION 3: WALLET WATCHER
# ====================================================================

class WalletWatchRequest(BaseModel):
    wallets: Optional[List[str]] = Field(
        default=None,
        description="Wallets to check. Leave empty to check wallet_watcher.py's "
                    "built-in list plus everything on the shared case watchlist.",
    )
    lookback_hours: Optional[int] = Field(
        default=None, description="Overrides wallet_watcher.py's default lookback window."
    )


def _default_watchlist():
    combined = list(ww.WATCHLIST_WALLETS)
    existing_lowercase = {w.lower() for w in combined}
    for address in ww.load_case_watchlist_addresses():
        if address.lower() not in existing_lowercase:
            combined.append(address)
            existing_lowercase.add(address.lower())
    return combined


@app.post("/api/wallet-watch")
def wallet_watch(req: WalletWatchRequest, _auth=Depends(require_read)):
    """Checks each wallet for movement within the lookback window. One result per wallet."""
    wallets = req.wallets if req.wallets else _default_watchlist()
    lookback_hours = req.lookback_hours or ww.LOOKBACK_HOURS

    results = []
    for address in wallets:
        chain = ww.detect_chain(address)
        if chain is None:
            results.append({
                "address": address, "chain": None, "valid": False, "alert": False,
                "message": "Not a recognized Ethereum, Bitcoin, XRP, or Tron address.",
            })
            continue

        try:
            if chain == "ethereum":
                transactions = ww.get_recent_eth_transactions(address, ww.ETHERSCAN_API_KEY)
                tx, tx_time = ww.eth_moved_money_recently(transactions, lookback_hours)
                if tx:
                    eth_value = int(tx["value"]) / 1_000_000_000_000_000_000
                    results.append({
                        "address": address, "chain": chain, "valid": True, "alert": True,
                        "amount": f"{eth_value:.6f} ETH", "counterparty": tx.get("to"),
                        "tx_hash": tx.get("hash"),
                        "tx_time_utc": tx_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "explorer_url": f"https://etherscan.io/tx/{tx.get('hash')}",
                    })
                else:
                    results.append({
                        "address": address, "chain": chain, "valid": True, "alert": False,
                        "message": "No activity in the lookback window." if transactions
                                   else "No transaction history found for this wallet.",
                    })

            elif chain == "bitcoin":
                transactions = ww.get_recent_bitcoin_transactions(address)
                tx, tx_time, is_pending = ww.bitcoin_moved_recently(transactions, lookback_hours)
                if tx:
                    received_sats = sum(
                        output.get("value", 0) for output in tx.get("vout", [])
                        if output.get("scriptpubkey_address", "").lower() == address.lower()
                    )
                    spent_sats = sum(
                        (tx_input.get("prevout") or {}).get("value", 0)
                        for tx_input in tx.get("vin", [])
                        if (tx_input.get("prevout") or {}).get("scriptpubkey_address", "").lower() == address.lower()
                    )
                    amount_parts = []
                    if received_sats:
                        amount_parts.append(f"received {received_sats / 100_000_000:.8f} BTC")
                    if spent_sats:
                        amount_parts.append(f"spent {spent_sats / 100_000_000:.8f} BTC")
                    results.append({
                        "address": address, "chain": chain, "valid": True, "alert": True,
                        "amount": "; ".join(amount_parts) or "unknown",
                        "status": "pending" if is_pending else "confirmed",
                        "tx_hash": tx.get("txid"),
                        "tx_time_utc": tx_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "explorer_url": f"https://mempool.space/tx/{tx.get('txid')}",
                    })
                else:
                    results.append({
                        "address": address, "chain": chain, "valid": True, "alert": False,
                        "message": "No activity in the lookback window." if transactions
                                   else "No transaction history found for this wallet.",
                    })

            elif chain == "xrp":
                transactions = ww.get_recent_xrp_transactions(address)
                tx_entry, tx_time = ww.xrp_moved_money_recently(transactions, lookback_hours)
                if tx_entry:
                    tx = tx_entry.get("tx", {})
                    meta = tx_entry.get("meta", {})
                    delivered = meta.get("delivered_amount", tx.get("Amount"))
                    if isinstance(delivered, str):
                        amount_label = f"{int(delivered) / 1_000_000:.6f} XRP"
                    elif isinstance(delivered, dict):
                        amount_label = f"{delivered.get('value')} {delivered.get('currency')} (issued token)"
                    else:
                        amount_label = "unknown"
                    results.append({
                        "address": address, "chain": chain, "valid": True, "alert": True,
                        "amount": amount_label, "counterparty": tx.get("Destination"),
                        "tx_hash": tx.get("hash"),
                        "tx_time_utc": tx_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "explorer_url": f"https://livenet.xrpl.org/transactions/{tx.get('hash')}",
                    })
                else:
                    results.append({
                        "address": address, "chain": chain, "valid": True, "alert": False,
                        "message": "No activity in the lookback window." if transactions
                                   else "No transaction history found for this wallet.",
                    })

            else:  # tron
                transactions = ww.get_recent_tron_transactions(address)
                tx, tx_time = ww.tron_moved_money_recently(transactions, lookback_hours)
                if tx:
                    decimals = (tx.get("token_info") or {}).get("decimals", 6)
                    try:
                        amount = int(tx.get("value", 0)) / (10 ** decimals)
                    except (TypeError, ValueError):
                        amount = 0.0
                    results.append({
                        "address": address, "chain": chain, "valid": True, "alert": True,
                        "amount": f"{amount:.6f} USDT", "counterparty": tx.get("to"),
                        "tx_hash": tx.get("transaction_id"),
                        "tx_time_utc": tx_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "explorer_url": f"https://tronscan.org/#/transaction/{tx.get('transaction_id')}",
                    })
                else:
                    results.append({
                        "address": address, "chain": chain, "valid": True, "alert": False,
                        "message": "No activity in the lookback window." if transactions
                                   else "No USDT transaction history found for this wallet.",
                    })

        except requests.exceptions.RequestException as error:
            results.append({
                "address": address, "chain": chain, "valid": True, "alert": False,
                "message": f"Network error while checking this wallet: {error}",
            })

    return results


# ====================================================================
# SECTION 4: VICTIM COLLATOR
# ====================================================================

class VictimCollateRequest(BaseModel):
    target_wallet: str


@app.post("/api/victim-collate")
def victim_collate(req: VictimCollateRequest, _auth=Depends(require_read)):
    """Returns everyone who sent funds INTO target_wallet, with amounts and known-entity labels."""
    chain = vc.detect_chain(req.target_wallet)
    if chain is None:
        raise HTTPException(400, "Not a recognized Ethereum, Bitcoin, XRP, or Tron address.")

    token_transfer_report = {}

    if chain == "ethereum":
        normal_transactions = vc.get_normal_transactions(req.target_wallet, vc.ETHERSCAN_API_KEY)
        time.sleep(vc.SECONDS_BETWEEN_REQUESTS)
        token_transactions = vc.get_token_transfers(req.target_wallet, vc.ETHERSCAN_API_KEY)

        senders, total_received = vc.collate_incoming_senders_ethereum(normal_transactions, req.target_wallet)

        transactions_by_token_symbol = {}
        for tx in token_transactions:
            transactions_by_token_symbol.setdefault(tx.get("tokenSymbol", "UNKNOWN"), []).append(tx)
        for symbol, tx_list in transactions_by_token_symbol.items():
            token_senders, _ = vc.collate_incoming_senders_ethereum(tx_list, req.target_wallet)
            if token_senders:
                token_transfer_report[symbol] = token_senders

        currency = "ETH"

    elif chain == "bitcoin":
        transactions = vc.get_bitcoin_transactions(req.target_wallet, vc.BITCOIN_MAX_PAGES)
        senders, total_received = vc.collate_incoming_senders_bitcoin(transactions, req.target_wallet)
        currency = "BTC"

    elif chain == "xrp":
        transactions = vc.get_xrp_transactions(req.target_wallet, vc.XRP_MAX_PAGES)
        senders, total_received = vc.collate_incoming_senders_xrp(transactions, req.target_wallet)
        currency = "XRP"

    else:  # tron
        transactions = vc.get_tron_transactions(req.target_wallet, vc.TRON_MAX_PAGES)
        senders, total_received = vc.collate_incoming_senders_tron(transactions, req.target_wallet)
        currency = "USDT"

    sender_list = [
        {"address": address, "amount": amount, "known_entity": lt.check_known_entity(address)}
        for address, amount in sorted(senders.items(), key=lambda item: item[1], reverse=True)
    ]

    return {
        "wallet": req.target_wallet,
        "chain": chain,
        "currency": currency,
        "total_received": total_received,
        "unique_senders": len(senders),
        "senders": sender_list,
        "token_transfers": {
            symbol: [{"address": address, "amount": amount} for address, amount in symbol_senders.items()]
            for symbol, symbol_senders in token_transfer_report.items()
        },
    }


# ====================================================================
# SECTION 5: LINK TRACER
# ====================================================================

class LinkTraceRequest(BaseModel):
    wallet: str = Field(..., description="Wallet to trace from (forward) or trace back from (backward).")
    direction: str = Field(default="forward", description='"forward" or "backward"')
    target_wallets: Optional[List[str]] = Field(
        default=None, description="Extra wallets to check for a link, beyond the shared case watchlist."
    )
    include_case_watchlist: bool = Field(
        default=True, description="Also check against every address on the shared case watchlist."
    )
    max_hops: Optional[int] = Field(default=None, description="Overrides link_tracer.py's default hop limit.")
    starting_amount: Optional[float] = Field(
        default=None, description="Turns on amount-filtering, tracking this starting amount."
    )


def _hop_out(hop):
    return {
        "from_address": hop["from"],
        "to_address": hop["to"],
        "amount": hop["amount_label"],
        "tx_time_utc": hop["tx_time"].strftime("%Y-%m-%d %H:%M:%S"),
        "tx_hash": hop["tx_hash"],
        "explorer_url": hop["explorer_url"],
        "from_known_entity": lt.check_known_entity(hop["from"]),
        "to_known_entity": lt.check_known_entity(hop["to"]),
    }


def _path_out(path, reason=None, swap_candidates=None):
    output = {"hops": [_hop_out(hop) for hop in path], "reason": reason}
    if swap_candidates is not None:
        output["swap_correlation_candidates"] = [
            {
                "chain": candidate["chain"],
                "counterparty": candidate["counterparty"],
                "amount": candidate["amount_label"],
                "tx_time_utc": candidate["tx_time"].strftime("%Y-%m-%d %H:%M:%S"),
                "tx_hash": candidate["tx_hash"],
                "explorer_url": candidate["explorer_url"],
                "minutes_diff": candidate["minutes_diff"],
                "usd_match_ratio": candidate["usd_match_ratio"],
            }
            for candidate in swap_candidates
        ]
    return output


def _swap_candidates_for_flagged_path(path, search_direction):
    """
    Returns find_correlated_counterpart()'s results for a flagged
    trail-end path, or None if it didn't stop at an "instant_swap"
    entity (or ENABLE_SWAP_CORRELATION is off) - None means "not
    applicable", distinct from [] which means "checked, found nothing".
    """
    if not lt.ENABLE_SWAP_CORRELATION:
        return None

    reference_hop = path[-1] if search_direction == "outgoing" else path[0]
    entity_address = reference_hop["to"] if search_direction == "outgoing" else reference_hop["from"]
    entity = lt.check_known_entity(entity_address)
    if not entity or entity.get("type") != "instant_swap":
        return None

    reference_chain = lt.detect_chain(entity_address)
    return lt.find_correlated_counterpart(
        entity["name"], reference_hop["amount_label"], reference_chain,
        reference_hop["tx_time"], search_direction,
    )


@app.post("/api/link-trace")
def link_trace(req: LinkTraceRequest, _auth=Depends(require_read)):
    """
    Traces forward (who did this wallet send to, hop by hop) or backward
    (who funded this wallet, hop by hop) looking for a link to a flagged
    wallet. Every branch is reported, not just matches - see
    flagged_end_paths (hit a known exchange/mixer or high fan-out wallet)
    and amount_filtered_paths (didn't match a tracked starting_amount).
    """
    if req.direction not in ("forward", "backward"):
        raise HTTPException(400, 'direction must be "forward" or "backward".')

    chain = lt.detect_chain(req.wallet)
    if chain is None:
        raise HTTPException(400, "Not a recognized Ethereum, Bitcoin, XRP, or Tron address.")

    targets = list(req.target_wallets or [])
    if req.include_case_watchlist:
        existing_lowercase = {t.lower() for t in targets}
        for address in lt.load_case_watchlist_addresses():
            if address.lower() not in existing_lowercase:
                targets.append(address)
                existing_lowercase.add(address.lower())
    target_lowercase_set = {t.lower() for t in targets}

    max_hops = req.max_hops or lt.MAX_HOPS

    if req.direction == "backward":
        matched_paths, flagged_end_paths, addresses_visited, amount_filtered_paths = lt.trace_backward(
            req.wallet, target_lowercase_set, max_hops, req.starting_amount
        )
    else:
        matched_paths, flagged_end_paths, addresses_visited, amount_filtered_paths = lt.trace_forward(
            req.wallet, target_lowercase_set, max_hops, req.starting_amount
        )

    all_paths_for_summary = (
        matched_paths
        + [path for path, _reason in flagged_end_paths]
        + [path for path, _reason in amount_filtered_paths]
    )
    clean_summary = (
        lt.dedupe_clean_rows(lt.build_clean_rows(all_paths_for_summary, req.wallet))
        if all_paths_for_summary else []
    )

    search_direction = "incoming" if req.direction == "backward" else "outgoing"

    return {
        "wallet": req.wallet,
        "direction": req.direction,
        "chain": chain,
        "targets_checked": len(targets),
        "addresses_visited": addresses_visited,
        "matched_paths": [_path_out(path) for path in matched_paths],
        "flagged_end_paths": [
            _path_out(path, reason, _swap_candidates_for_flagged_path(path, search_direction))
            for path, reason in flagged_end_paths
        ],
        "amount_filtered_paths": [_path_out(path, reason) for path, reason in amount_filtered_paths],
        "clean_summary": clean_summary,
    }


# ====================================================================
# SECTION 6: SHARED CASE WATCHLIST (CRUD)
# ====================================================================

class CaseWatchlistEntryIn(BaseModel):
    address: str
    chain: Optional[str] = Field(default=None, description="Auto-detected if omitted.")
    source: Optional[str] = None
    context: Optional[str] = None


def _read_case_watchlist():
    if not os.path.isfile(lt.CASE_WATCHLIST_FILE):
        return []
    with open(lt.CASE_WATCHLIST_FILE, "r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def _write_case_watchlist(entries):
    with open(lt.CASE_WATCHLIST_FILE, "w", encoding="utf-8") as file_handle:
        json.dump(entries, file_handle, indent=2)


@app.get("/api/case-watchlist")
def get_case_watchlist(_auth=Depends(require_read)):
    with _file_lock:
        return _read_case_watchlist()


@app.post("/api/case-watchlist")
def add_case_watchlist_entry(entry: CaseWatchlistEntryIn, _auth=Depends(require_write)):
    chain = entry.chain or lt.detect_chain(entry.address)
    if chain is None:
        raise HTTPException(400, "Not a recognized Ethereum, Bitcoin, XRP, or Tron address.")

    with _file_lock:
        entries = _read_case_watchlist()
        if any(e["address"].lower() == entry.address.lower() for e in entries):
            return {"added": False, "message": "Already on the shared case watchlist."}

        entries.append({
            "address": entry.address,
            "chain": chain,
            "coin_type": chain,
            "first_seen_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "discovered_via": "api_server.py (manual/API entry)",
            "source": entry.source or "",
            "context": entry.context or "",
        })
        _write_case_watchlist(entries)

    return {"added": True}


@app.delete("/api/case-watchlist/{address}")
def delete_case_watchlist_entry(address: str, _auth=Depends(require_write)):
    with _file_lock:
        entries = _read_case_watchlist()
        remaining = [e for e in entries if e["address"].lower() != address.lower()]
        if len(remaining) == len(entries):
            raise HTTPException(404, "That address isn't on the shared case watchlist.")
        _write_case_watchlist(remaining)
    return {"deleted": True}


# ====================================================================
# SECTION 7: KNOWN ENTITIES (exchanges/mixers) (CRUD)
# ====================================================================

class KnownEntityIn(BaseModel):
    address: str
    name: str
    type: str = Field(default="exchange", description='e.g. "exchange", "mixer", "custodial"')


def _read_known_entities():
    if not os.path.isfile(lt.KNOWN_ENTITIES_FILE):
        return []
    with open(lt.KNOWN_ENTITIES_FILE, "r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def _write_known_entities(entries):
    with open(lt.KNOWN_ENTITIES_FILE, "w", encoding="utf-8") as file_handle:
        json.dump(entries, file_handle, indent=2)
    # Refresh link_tracer's in-memory cache so the change applies to the
    # very next request, without needing a server restart.
    lt.KNOWN_ENTITIES = lt.load_known_entities()


@app.get("/api/known-entities")
def get_known_entities(_auth=Depends(require_read)):
    with _file_lock:
        return _read_known_entities()


@app.post("/api/known-entities")
def add_known_entity(entry: KnownEntityIn, _auth=Depends(require_write)):
    with _file_lock:
        entries = [e for e in _read_known_entities() if e.get("address", "").lower() != entry.address.lower()]
        entries.append({"address": entry.address, "name": entry.name, "type": entry.type})
        _write_known_entities(entries)
    return {"added": True}


@app.delete("/api/known-entities/{address}")
def delete_known_entity(address: str, _auth=Depends(require_write)):
    with _file_lock:
        entries = _read_known_entities()
        remaining = [e for e in entries if e.get("address", "").lower() != address.lower()]
        if len(remaining) == len(entries):
            raise HTTPException(404, "That address isn't in the known entities list.")
        _write_known_entities(remaining)
    return {"deleted": True}


# ====================================================================
# SECTION 7B: DEPOSIT & CONSOLIDATION MAP
# ====================================================================

class DepositCheckRequest(BaseModel):
    address: str = Field(..., description="Address to check for a sweep into a known exchange wallet.")


@app.get("/api/deposit-map")
def get_deposit_map(_auth=Depends(require_read)):
    """Every address confirmed so far as an exchange deposit address, via consolidation sweeps."""
    with _file_lock:
        return lt.load_deposit_map()


@app.post("/api/deposit-map/check")
def check_deposit_consolidation(req: DepositCheckRequest, _auth=Depends(require_write)):
    """
    Checks whether a SPECIFIC address has swept funds into a known
    exchange wallet - i.e. confirms/denies it as a deposit address for
    that exchange. On Bitcoin, a confirmed match also reveals and
    registers every sibling deposit address swept in the same
    transaction. Any new discovery is saved to the shared deposit map
    immediately (guarded by the same file lock as the other shared
    files, since this can write to it).
    """
    with _file_lock:
        return lt.manual_check_deposit_consolidation(req.address)


# ====================================================================
# SECTION 8: CRYPTO ADDRESS WATCHER (background scan, since it can be slow)
# ====================================================================

_last_scan_result = {
    "status": "never_run",   # never_run | running | complete | error
    "started_at": None,
    "completed_at": None,
    "result": None,
}
_scan_state_lock = threading.Lock()


def _run_address_scan_background():
    with _scan_state_lock:
        _last_scan_result["status"] = "running"
        _last_scan_result["started_at"] = datetime.now(timezone.utc).isoformat()

    try:
        all_text_blocks = []

        for feed_url in caw.RSS_FEED_URLS:
            all_text_blocks.extend(caw.fetch_rss_articles(feed_url))
            time.sleep(caw.SECONDS_BETWEEN_REQUESTS)

        for channel in caw.TELEGRAM_CHANNELS_TO_MONITOR:
            all_text_blocks.extend(caw.fetch_telegram_channel_posts(channel))
            time.sleep(caw.SECONDS_BETWEEN_REQUESTS)

        for handle in caw.TWITTER_HANDLES_TO_MONITOR:
            all_text_blocks.extend(caw.fetch_twitter_posts(handle, caw.TWITTER_BEARER_TOKEN))
            time.sleep(caw.SECONDS_BETWEEN_REQUESTS)

        all_findings = []
        for block in all_text_blocks:
            all_findings.extend(caw.extract_addresses_with_patterns(block["text"], block["source"]))

        known_lowercase_baseline = {address.lower() for address in caw.KNOWN_ADDRESSES}
        grouped_findings = caw.group_findings_by_address(all_findings, known_lowercase_baseline)

        with _file_lock:
            newly_added = caw.sync_new_addresses_to_case_watchlist(grouped_findings)

        with _scan_state_lock:
            _last_scan_result.update({
                "status": "complete",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "result": {
                    "text_blocks_scanned": len(all_text_blocks),
                    "total_matches": len(all_findings),
                    "unique_addresses": len(grouped_findings),
                    "newly_added_to_case_watchlist": newly_added,
                    "findings": [
                        {
                            "address": entry["address"],
                            "coin_type": entry["coin_type"],
                            "is_new": entry["is_new"],
                            "sightings": entry["sightings"],
                        }
                        for entry in grouped_findings.values()
                    ],
                },
            })

    except Exception as error:  # noqa: BLE001 - a background task must never crash silently
        with _scan_state_lock:
            _last_scan_result.update({
                "status": "error",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "result": {"error": str(error)},
            })


@app.post("/api/address-scan/start")
def start_address_scan(background_tasks: BackgroundTasks, _auth=Depends(require_write)):
    """
    Starts a scan of the configured RSS/Telegram/X sources in the
    background (this can take a while, so it doesn't block the
    request). Poll GET /api/address-scan/latest for the result.
    """
    with _scan_state_lock:
        if _last_scan_result["status"] == "running":
            return {"started": False, "message": "A scan is already running."}
    background_tasks.add_task(_run_address_scan_background)
    return {"started": True, "message": "Scan started - poll GET /api/address-scan/latest for the result."}


@app.get("/api/address-scan/latest")
def get_latest_address_scan(_auth=Depends(require_read)):
    with _scan_state_lock:
        return dict(_last_scan_result)

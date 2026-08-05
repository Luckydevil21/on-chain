"""
====================================================================
 API SERVER - a JSON API in front of your investigation toolkit
====================================================================

WHAT THIS IS:
A FastAPI web server that wraps link_tracer.py so a web frontend (a
Base44 app, or anything else that can call a REST API) can use it,
instead of running the script by hand.

It does NOT reimplement any of the blockchain-fetching logic - every
endpoint here calls the SAME functions already tested in link_tracer.py
(imported as a module). If you fix a bug or add a chain to
link_tracer.py, this API picks it up automatically next restart -
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
of truth - the SAME files link_tracer.py and the desktop dashboard
already read from, so nothing gets out of sync
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
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

# ---- link_tracer.py, imported as a module. Importing it does NOT run
# its CLI/__main__ section - only its top-level constants and function
# definitions execute. ----
import link_tracer as lt
import ai_assist
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
        "JSON API wrapping link_tracer.py for use by a web frontend such as "
        "a Base44 app. Every endpoint (except /health) requires either a "
        "logged-in session (see /api/auth/login) or an X-API-Key header."
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
# several endpoints (and the desktop dashboard) can write to the same file.
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
    exact_amount_only: bool = Field(
        default=False,
        description="If true, only follows hops matching starting_amount almost exactly (a razor-thin "
                    "buffer for network fees only) instead of the default 10%-105% fuzzy band. Has no "
                    "effect unless starting_amount is also set.",
    )
    continue_past_match: bool = Field(
        default=False,
        description="By default, the trace stops exploring a branch the moment it reaches a target "
                    "wallet - the match itself is treated as the goal. If true, it keeps tracing that "
                    "wallet's own onward activity too, up to the normal hop limit.",
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
            req.wallet, target_lowercase_set, max_hops, req.starting_amount, req.exact_amount_only, req.continue_past_match
        )
    else:
        matched_paths, flagged_end_paths, addresses_visited, amount_filtered_paths = lt.trace_forward(
            req.wallet, target_lowercase_set, max_hops, req.starting_amount, req.exact_amount_only, req.continue_past_match
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

    # Sort every list of paths by when each one actually LEFT the
    # traced wallet (the FIRST hop's real transaction time) - not the
    # order the BFS happened to discover them in, and NOT the last
    # hop's time either. Every one of these paths starts from the same
    # wallet, so a reader scanning top-to-bottom expects the date on
    # the FIRST box of each row to increase steadily. Sorting by the
    # last hop instead would put a multi-hop chain's position based on
    # when its trail concluded, which can be completely disconnected
    # from when it actually started - producing exactly the same
    # "jumps around" confusion this sort was meant to fix in the first
    # place, just for a different reason.
    def _first_hop_time(path):
        return path[0]["tx_time"] if path else datetime.min.replace(tzinfo=timezone.utc)

    # When continue_past_match extends a matched lineage across several
    # hops, EVERY stopping point along the way gets recorded (see
    # link_tracer.py's is_post_match tracking) - correct data, but
    # showing the 1-hop match AND the 2-hop extension AND the 3-hop
    # extension as separate boxes means the same early hop(s) appear
    # redundantly in more than one place. A shorter path here is
    # always a strict PREFIX of the longer one it belongs to (same
    # hops, same order, just fewer of them) - so it adds nothing a
    # reader doesn't already see in the longer version. Keep only the
    # longest path per lineage.
    def _drop_prefix_paths(paths):
        def is_strict_prefix(shorter, longer):
            if len(shorter) >= len(longer):
                return False
            return all(shorter[i]["tx_hash"] == longer[i]["tx_hash"] for i in range(len(shorter)))

        return [
            path for index, path in enumerate(paths)
            if not any(is_strict_prefix(path, other) for other_index, other in enumerate(paths) if other_index != index)
        ]

    matched_paths = _drop_prefix_paths(matched_paths)

    matched_paths.sort(key=_first_hop_time)
    flagged_end_paths.sort(key=lambda item: _first_hop_time(item[0]))
    amount_filtered_paths.sort(key=lambda item: _first_hop_time(item[0]))

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
    type: str = Field(default="exchange", description='e.g. "exchange", "mixer", "instant_swap", "bridge"')
    chain: Optional[str] = Field(default=None, description="Auto-detected if omitted.")


def _read_known_entities():
    if not os.path.isfile(lt.KNOWN_ENTITIES_FILE):
        return []
    with open(lt.KNOWN_ENTITIES_FILE, "r", encoding="utf-8") as file_handle:
        entries = json.load(file_handle)
    # Backfill a computed "chain" for any entry that doesn't already have
    # one stored (e.g. added by hand, or created before this field
    # existed) - so the frontend always has something to display,
    # without needing to duplicate address-format detection itself.
    for entry in entries:
        if not entry.get("chain") and entry.get("address"):
            entry["chain"] = lt.detect_chain(entry["address"])
    return entries


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
    chain = entry.chain or lt.detect_chain(entry.address)
    if chain is None:
        raise HTTPException(400, "Not a recognized Ethereum, Bitcoin, XRP, or Tron address.")

    with _file_lock:
        entries = [e for e in _read_known_entities() if e.get("address", "").lower() != entry.address.lower()]
        entries.append({"address": entry.address, "name": entry.name, "type": entry.type, "chain": chain})
        _write_known_entities(entries)
    return {"added": True}


class BulkKnownEntityIn(BaseModel):
    addresses: List[str] = Field(..., description="One address per entry - e.g. pasted lines from a CSV or list.")
    name: str
    type: str = Field(default="exchange", description='e.g. "exchange", "mixer", "instant_swap", "bridge"')


@app.post("/api/known-entities/bulk")
def add_known_entities_bulk(payload: BulkKnownEntityIn, _auth=Depends(require_write)):
    """
    Adds many addresses at once under the SAME name/type - e.g. a
    batch of exchange cold-wallet addresses pasted from a CSV or a
    community-maintained list. Each address gets its own chain
    auto-detected individually (a batch can freely mix chains).
    Skips blank lines and duplicates already on file; unrecognized
    addresses are reported back, not silently dropped.
    """
    with _file_lock:
        entries = _read_known_entities()
        existing_lower = {e.get("address", "").lower() for e in entries}

        added, skipped_duplicate, skipped_invalid = [], [], []
        for raw_address in payload.addresses:
            address = raw_address.strip()
            if not address:
                continue
            if address.lower() in existing_lower:
                skipped_duplicate.append(address)
                continue
            chain = lt.detect_chain(address)
            if chain is None:
                skipped_invalid.append(address)
                continue
            entries.append({"address": address, "name": payload.name, "type": payload.type, "chain": chain})
            existing_lower.add(address.lower())
            added.append(address)

        if added:
            _write_known_entities(entries)

    return {
        "added_count": len(added), "added": added,
        "skipped_duplicate_count": len(skipped_duplicate), "skipped_duplicate": skipped_duplicate,
        "skipped_invalid_count": len(skipped_invalid), "skipped_invalid": skipped_invalid,
    }


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
# SECTION 7F: AI-ASSISTED NARRATIVE REPORT + TYPOLOGY DESCRIPTION
# ====================================================================
# Both take the SAME structured result a completed /api/link-trace
# call already returned - no separate lookup, no new fact-finding.
# See ai_assist.py for the full explanation of why these are
# deliberately grounded-only, never attribution generators.

class AIAssistRequest(BaseModel):
    wallet: str
    direction: str
    trace_data: dict = Field(..., description="The full response body a completed /api/link-trace call already returned.")


@app.post("/api/ai/draft-report")
def ai_draft_report(req: AIAssistRequest, _auth=Depends(require_read)):
    text, error = ai_assist.draft_narrative_report(req.trace_data, req.wallet, req.direction)
    if error:
        raise HTTPException(503, error)
    return {"report": text}


@app.post("/api/ai/describe-typology")
def ai_describe_typology(req: AIAssistRequest, _auth=Depends(require_read)):
    text, error = ai_assist.describe_typology(req.trace_data, req.wallet, req.direction)
    if error:
        raise HTTPException(503, error)
    return {"description": text}


class AIServiceTraceRequest(BaseModel):
    address: str
    trace_data: dict = Field(..., description="The response body a completed /api/deposit-map/check call already returned.")


@app.post("/api/ai/draft-service-trace")
def ai_draft_service_trace(req: AIServiceTraceRequest, _auth=Depends(require_read)):
    text, error = ai_assist.draft_service_trace_narrative(req.trace_data, req.address)
    if error:
        raise HTTPException(503, error)
    return {"report": text}


# ====================================================================
# SECTION 7D: TRANSACTION HASH LOOKUP + DATE-ANCHORED SEARCH
# ====================================================================

class TxLookupRequest(BaseModel):
    tx_hash: str = Field(..., description="Transaction hash - any chain, auto-detected/tried.")


@app.post("/api/tx-lookup")
def tx_lookup(req: TxLookupRequest, _auth=Depends(require_read)):
    """
    Given a transaction hash from anywhere (another tool, a
    screenshot, a colleague), fetches its full details directly.
    Ethereum hashes are unambiguous (0x prefix). Bitcoin/XRP/Tron
    hashes are format-identical - tried in turn until one matches.
    """
    return lt.lookup_transaction_across_chains(req.tx_hash)


class WalletDateSearchRequest(BaseModel):
    address: str
    target_datetime: str = Field(..., description="ISO format, e.g. 2025-05-15T15:00:00")
    window_hours: float = Field(default=24, description="Search +/- this many hours around the target.")


@app.post("/api/wallet-date-search")
def wallet_date_search(req: WalletDateSearchRequest, _auth=Depends(require_read)):
    """
    Searches a SPECIFIC wallet's activity around a known date/time,
    instead of relying on the automatic trace's most-recent-pages-only
    approach - the fix for a transaction that's genuinely buried deep
    in a high-volume wallet's history. See link_tracer.py SECTION 3E
    for the honest per-chain capability differences.
    """
    if req.window_hours <= 0 or req.window_hours > 24 * 30:
        raise HTTPException(400, "window_hours must be a positive number, capped at 720 (30 days).")
    return lt.search_wallet_near_date(req.address, req.target_datetime, req.window_hours)


# ====================================================================
# SECTION 7C: SWAP / BRIDGE CORRELATION (standalone, single-wallet check)
# ====================================================================

class SwapCorrelationCheckRequest(BaseModel):
    address: str = Field(..., description="Wallet to check.")
    direction: str = Field(
        default="both",
        description='"outgoing" (did it deposit into a known service?), '
                    '"incoming" (did it receive a payout from one?), or "both".',
    )


@app.post("/api/swap-correlation/check")
def check_swap_correlation(req: SwapCorrelationCheckRequest, _auth=Depends(require_read)):
    """
    Checks whether a SPECIFIC wallet went through a known no-KYC
    instant-swap service or cross-chain bridge - without needing to
    run a full multi-hop link-trace first. Read-only (doesn't persist
    anything, unlike /api/deposit-map/check) - so read_only users can
    use this freely.
    """
    if req.direction not in ("outgoing", "incoming", "both"):
        raise HTTPException(400, 'direction must be "outgoing", "incoming", or "both".')
    return lt.manual_check_swap_correlation(req.address, req.direction)


# ====================================================================
# SECTION 7G: GAS-FUNDING-SOURCE CLUSTERING
# ====================================================================
# See link_tracer.py's matching section comment for the full
# explanation - Ethereum and XRP only, Bitcoin/Tron have no
# equivalent concept or aren't wired up yet.

class FundingSourceCheckRequest(BaseModel):
    addresses: List[str] = Field(..., description="2 or more addresses to check for a shared funding source.")


@app.post("/api/funding-source-check")
def funding_source_check(req: FundingSourceCheckRequest, _auth=Depends(require_read)):
    cleaned = [a.strip() for a in req.addresses if a.strip()]
    if len(cleaned) < 2:
        raise HTTPException(400, "Enter at least 2 addresses to check for a shared funding source.")
    return lt.check_common_funding_source(cleaned)


# ====================================================================
# SECTION 7E: KNOWN MESSAGE PATTERNS (rotating-address services)
# ====================================================================
# For services that use a NEW receiving address every transaction (so
# known_entities.json's exact-address matching can never keep up),
# this recognizes the service by a consistent message it embeds in the
# transaction instead - Bitcoin's OP_RETURN, Ethereum's input data, or
# XRP's Memos field. Tron isn't covered - standard USDT-TRC20 transfers
# have no equivalent free-text field.

class OpReturnPatternIn(BaseModel):
    pattern: str = Field(..., description='A substring to look for in the decoded OP_RETURN text, e.g. "to:USDT(TRON):"')
    name: str
    type: str = Field(default="bridge", description='"bridge" or "instant_swap"')


@app.get("/api/op-return-patterns")
def get_op_return_patterns(_auth=Depends(require_read)):
    with _file_lock:
        return lt.load_known_op_return_patterns()


@app.post("/api/op-return-patterns")
def add_op_return_pattern(entry: OpReturnPatternIn, _auth=Depends(require_write)):
    if not entry.pattern.strip():
        raise HTTPException(400, "Pattern can't be empty.")
    with _file_lock:
        patterns = lt.load_known_op_return_patterns()
        if any(p.get("pattern") == entry.pattern for p in patterns):
            raise HTTPException(400, "That exact pattern is already registered.")
        patterns.append({"pattern": entry.pattern, "name": entry.name, "type": entry.type})
        lt.save_known_op_return_patterns(patterns)
    return {"added": True}


@app.delete("/api/op-return-patterns/{pattern_index}")
def delete_op_return_pattern(pattern_index: int, _auth=Depends(require_write)):
    with _file_lock:
        patterns = lt.load_known_op_return_patterns()
        if pattern_index < 0 or pattern_index >= len(patterns):
            raise HTTPException(404, "No pattern at that index.")
        patterns.pop(pattern_index)
        lt.save_known_op_return_patterns(patterns)
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


"""
====================================================================
 AUTH - multi-user login with roles, on top of the existing API key
====================================================================

WHAT THIS ADDS: real user accounts (username + password) with two
roles - "admin" (full read/write) and "read_only" (can run wallet
checks/traces/collation and view every list, but can't add/delete
watchlist entries, known entities, or trigger a scan).

Logging in sets a secure, httpOnly session cookie - NOT something
JavaScript can read, which is deliberately more secure than storing
a token in browser storage (protects against a whole class of
token-theft attacks via a compromised page script).

The original TOOLKIT_API_KEY still works exactly as before, for
scripts/automation/Base44 integrations - it's always treated as full
admin access, alongside the new per-user logins.

====================================================================
 ONE-TIME SETUP: creating your first admin account
====================================================================
There's a chicken-and-egg problem on a fresh deploy: you can't log
in to create a user if no users exist yet. Solve it by setting these
two environment variables ONCE, alongside your other settings:

    TOOLKIT_ADMIN_USERNAME=paul
    TOOLKIT_ADMIN_PASSWORD=choose-a-real-password-not-this-one

On startup, if that username doesn't already exist as a user, it's
created automatically as an admin. After that first login, create
everyone else through the app's Users panel (admin-only) instead -
you can remove these two environment variables once you've done
that, or leave them (they only ever create the account, never
overwrite an existing one's password).

====================================================================
 SESSION SECRET
====================================================================
Set TOOLKIT_JWT_SECRET to a long random string (same idea as
TOOLKIT_API_KEY - make one up, keep it private). If you don't set
it, one is generated for this run only, which means everyone gets
logged out the next time the server restarts. Fine for testing,
not for anything you want people to stay logged into.
====================================================================
"""

import os
import io
import json
import base64
import secrets
from datetime import datetime, timezone, timedelta

import bcrypt
import jwt
import pyotp
import qrcode
import psycopg2
import psycopg2.extras
from contextlib import contextmanager

DATABASE_URL = os.environ.get("DATABASE_URL")

@contextmanager
def _get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        conn.close()
TOOLKIT_DATA_DIR = os.environ.get(
    "TOOLKIT_DATA_DIR", os.path.dirname(os.path.abspath(__file__))
)
USERS_FILE = os.path.join(TOOLKIT_DATA_DIR, "users.json")

SESSION_COOKIE_NAME = "toolkit_session"
SESSION_DURATION_HOURS = 12
VALID_ROLES = ("admin", "read_only")

TOTP_ISSUER_NAME = "On-Chain Investigations"
TOTP_PENDING_TOKEN_MINUTES = 5   # how long you have to enter your 2FA code after a correct password
RESET_TOKEN_HOURS = 1            # how long a "forgot password" email link stays valid

_jwt_secret = os.environ.get("TOOLKIT_JWT_SECRET")
if not _jwt_secret:
    _jwt_secret = secrets.token_urlsafe(32)
    print("=" * 70)
    print("⚠️  TOOLKIT_JWT_SECRET was not set - generated a TEMPORARY one for")
    print("    this run only. Every logged-in session will be signed out the")
    print("    next time the server restarts. Set TOOLKIT_JWT_SECRET to a long")
    print("    random string to keep people logged in across restarts.")
    print("=" * 70)

# Cookies are marked Secure by default (HTTPS-only) - correct for any real
# deployment. Set TOOLKIT_COOKIE_SECURE=false ONLY for local http:// testing,
# since browsers refuse to send a Secure cookie back over plain HTTP.
COOKIE_SECURE = os.environ.get("TOOLKIT_COOKIE_SECURE", "true").strip().lower() != "false"


# ====================================================================
# USER STORAGE
# ====================================================================

def _load_users():
    if not os.path.isfile(USERS_FILE):
        return []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as file_handle:
            return json.load(file_handle)
    except (json.JSONDecodeError, OSError):
        return []


def _save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as file_handle:
        json.dump(users, file_handle, indent=2)


def _hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(password, password_hash):
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _get_user_record(username):
    """Internal use only - returns the FULL record (password hash, TOTP
    secret, reset token, everything) or None. Never expose this
    directly to the frontend - use list_users() for that."""
    for user in _load_users():
        if user["username"].lower() == username.lower():
            return user
    return None


def _update_user_record(username, **fields):
    """Internal use only - merges the given fields into a user's stored
    record. Returns True if the user was found and updated."""
    users = _load_users()
    updated = False
    for user in users:
        if user["username"].lower() == username.lower():
            user.update(fields)
            updated = True
            break
    if updated:
        _save_users(users)
    return updated


def bootstrap_admin_from_env():
    """Creates the first admin account from TOOLKIT_ADMIN_USERNAME/PASSWORD
    (and optionally TOOLKIT_ADMIN_EMAIL, needed if you want password-reset
    emails to work for this account), if set and that username doesn't
    already exist. See module docstring."""
    username = os.environ.get("TOOLKIT_ADMIN_USERNAME")
    password = os.environ.get("TOOLKIT_ADMIN_PASSWORD")
    email = os.environ.get("TOOLKIT_ADMIN_EMAIL", "")
    if not username or not password:
        return

    users = _load_users()
    if any(user["username"].lower() == username.lower() for user in users):
        return

    users.append({
        "username": username,
        "password_hash": _hash_password(password),
        "role": "admin",
        "email": email,
        "totp_secret": None,
        "totp_enabled": False,
        "reset_token": None,
        "reset_token_expires": None,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    })
    _save_users(users)
    print(f"👤 Bootstrapped admin account '{username}' from TOOLKIT_ADMIN_USERNAME/PASSWORD.")


def create_user(username, password, role, email=""):
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {VALID_ROLES}")
    if not username or not username.strip():
        raise ValueError("username can't be empty")
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    if email and ("@" not in email or "." not in email.split("@")[-1]):
        raise ValueError("that doesn't look like a valid email address")

    users = _load_users()
    if any(user["username"].lower() == username.lower() for user in users):
        raise ValueError("a user with that username already exists")

    users.append({
        "username": username,
        "password_hash": _hash_password(password),
        "role": role,
        "email": email,
        "totp_secret": None,
        "totp_enabled": False,
        "reset_token": None,
        "reset_token_expires": None,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    })
    _save_users(users)


def delete_user(username):
    users = _load_users()
    remaining = [user for user in users if user["username"].lower() != username.lower()]
    if len(remaining) == len(users):
        return False
    _save_users(remaining)
    return True


def list_users():
    """Returns users WITHOUT password hashes/TOTP secrets/reset tokens - safe to hand to the frontend."""
    return [
        {
            "username": user["username"],
            "role": user["role"],
            "email": user.get("email", ""),
            "totp_enabled": bool(user.get("totp_enabled")),
            "created_utc": user.get("created_utc"),
        }
        for user in _load_users()
    ]


def authenticate(username, password):
    """Returns {"username", "role", "totp_enabled"} if the password is
    correct, else None. Does NOT issue a session - if totp_enabled is
    True, the caller must still collect and verify a TOTP code (see
    create_totp_pending_token / verify_totp_code) before a real session
    is created."""
    for user in _load_users():
        if user["username"].lower() == username.lower():
            if _verify_password(password, user["password_hash"]):
                return {
                    "username": user["username"],
                    "role": user["role"],
                    "totp_enabled": bool(user.get("totp_enabled")),
                }
            return None
    return None


# ====================================================================
# SESSIONS (JWT inside a secure httpOnly cookie)
# ====================================================================

def create_session_token(username, role):
    now = datetime.now(timezone.utc)
    payload = {"sub": username, "role": role, "iat": now, "exp": now + timedelta(hours=SESSION_DURATION_HOURS)}
    return jwt.encode(payload, _jwt_secret, algorithm="HS256")


def verify_session_token(token):
    try:
        payload = jwt.decode(token, _jwt_secret, algorithms=["HS256"])
        return {"username": payload["sub"], "role": payload["role"]}
    except jwt.PyJWTError:
        return None


def set_session_cookie(response, username, role):
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=create_session_token(username, role),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_DURATION_HOURS * 3600,
    )


def clear_session_cookie(response):
    response.delete_cookie(SESSION_COOKIE_NAME)


def get_current_user_from_request(request, static_api_key):
    """
    PLAIN ENGLISH: Figures out who's making this request, checking in
    order: (1) a valid session cookie - the normal logged-in-browser
    case, (2) the X-API-Key header matching the configured static key
    - for scripts/automation, always treated as full admin. Returns
    {"username", "role"}, or None if neither is present/valid.
    """
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        user = verify_session_token(session_token)
        if user:
            return user

    api_key = request.headers.get("X-API-Key")
    if api_key and static_api_key and api_key == static_api_key:
        return {"username": "api-key", "role": "admin"}

    return None


# ====================================================================
# TWO-FACTOR AUTHENTICATION (TOTP - Google Authenticator / Authy style)
# ====================================================================
# Setup flow: generate a secret (not yet active) -> user scans the QR
# code or enters the secret manually into their authenticator app ->
# user enters the 6-digit code it's currently showing to CONFIRM setup
# (proves they actually captured the secret correctly) -> only then is
# 2FA actually turned on for the account.
#
# Login flow once enabled: correct password gets you a short-lived
# "pending" token (NOT a real session) -> you then submit that pending
# token plus your current 6-digit code -> only then do you get a real
# session cookie. A real session is never issued on password alone
# once 2FA is on.
# ====================================================================

def generate_totp_secret():
    return pyotp.random_base32()


def get_totp_provisioning_uri(username, secret):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=TOTP_ISSUER_NAME)


def generate_totp_qr_code_base64(otpauth_uri):
    """Returns a base64-encoded PNG (no 'data:image/png;base64,' prefix) of a QR code for this URI."""
    qr_image = qrcode.make(otpauth_uri)
    buffer = io.BytesIO()
    qr_image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def verify_totp_code(secret, code):
    if not secret or not code:
        return False
    try:
        # valid_window=1 allows the code from one 30-second step
        # before/after the current one, to tolerate ordinary clock drift
        # between the server and the user's phone.
        return pyotp.totp.TOTP(secret).verify(str(code).strip(), valid_window=1)
    except Exception:
        return False


def begin_totp_setup(username):
    """
    PLAIN ENGLISH: Generates a new TOTP secret for this user and stores
    it as PENDING (totp_enabled stays False until confirm_totp_setup
    succeeds - so a half-finished setup never accidentally locks the
    account out). Returns (secret, otpauth_uri, qr_code_base64).
    """
    secret = generate_totp_secret()
    _update_user_record(username, totp_secret=secret, totp_enabled=False)
    uri = get_totp_provisioning_uri(username, secret)
    qr_base64 = generate_totp_qr_code_base64(uri)
    return secret, uri, qr_base64


def confirm_totp_setup(username, code):
    """Verifies the code against the PENDING secret and, if correct,
    actually turns 2FA on. Returns True/False."""
    user = _get_user_record(username)
    if not user or not user.get("totp_secret"):
        return False
    if not verify_totp_code(user["totp_secret"], code):
        return False
    _update_user_record(username, totp_enabled=True)
    return True


def disable_totp(username, password):
    """Requires re-entering the CURRENT password (not just an active
    session) before turning 2FA off - a hijacked browser session alone
    shouldn't be enough to weaken the account's protection."""
    user = _get_user_record(username)
    if not user or not _verify_password(password, user["password_hash"]):
        return False
    _update_user_record(username, totp_secret=None, totp_enabled=False)
    return True


def is_totp_enabled(username):
    user = _get_user_record(username)
    return bool(user and user.get("totp_enabled"))


def create_totp_pending_token(username):
    """A short-lived, single-purpose token proving 'this username just
    supplied the correct password' - NOT a real session. Must be
    exchanged (along with a valid TOTP code) for a real session token
    via verify_totp_pending_token + create_session_token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "purpose": "totp_pending",
        "iat": now,
        "exp": now + timedelta(minutes=TOTP_PENDING_TOKEN_MINUTES),
    }
    return jwt.encode(payload, _jwt_secret, algorithm="HS256")


def verify_totp_pending_token(token):
    """Returns the username if this is a valid, unexpired 'totp_pending'
    token, else None. Deliberately checks the "purpose" claim so a
    normal session token can never be reused here (and vice versa)."""
    try:
        payload = jwt.decode(token, _jwt_secret, algorithms=["HS256"])
        if payload.get("purpose") != "totp_pending":
            return None
        return payload["sub"]
    except jwt.PyJWTError:
        return None


# ====================================================================
# FORGOT PASSWORD (email a time-limited reset link)
# ====================================================================

def find_username_by_identifier(identifier):
    """Matches on username OR email (case-insensitive). Returns the
    username if found, else None. Used by the forgot-password flow,
    which deliberately gives the SAME response either way (see
    api_server.py) to avoid revealing whether an account exists."""
    identifier_lower = identifier.strip().lower()
    for user in _load_users():
        if user["username"].lower() == identifier_lower:
            return user["username"]
        if user.get("email", "").lower() == identifier_lower and identifier_lower:
            return user["username"]
    return None


def generate_password_reset_token(username):
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=RESET_TOKEN_HOURS)
    _update_user_record(username, reset_token=token, reset_token_expires=expires.isoformat())
    return token


def verify_password_reset_token(token):
    """Returns the username if this token is valid and not expired, else None."""
    for user in _load_users():
        if user.get("reset_token") == token:
            expires_str = user.get("reset_token_expires")
            if not expires_str:
                return None
            expires = datetime.fromisoformat(expires_str)
            if datetime.now(timezone.utc) > expires:
                return None
            return user["username"]
    return None


def reset_password_with_token(token, new_password):
    """Validates the token, sets the new password, and invalidates the
    token (single use). Returns True/False."""
    username = verify_password_reset_token(token)
    if not username:
        return False
    if len(new_password) < 8:
        raise ValueError("password must be at least 8 characters")
    _update_user_record(
        username,
        password_hash=_hash_password(new_password),
        reset_token=None,
        reset_token_expires=None,
    )
    return True

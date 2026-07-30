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
import json
import secrets
from datetime import datetime, timezone, timedelta

import bcrypt
import jwt

TOOLKIT_DATA_DIR = os.environ.get(
    "TOOLKIT_DATA_DIR", os.path.dirname(os.path.abspath(__file__))
)
USERS_FILE = os.path.join(TOOLKIT_DATA_DIR, "users.json")

SESSION_COOKIE_NAME = "toolkit_session"
SESSION_DURATION_HOURS = 12
VALID_ROLES = ("admin", "read_only")

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


def bootstrap_admin_from_env():
    """Creates the first admin account from TOOLKIT_ADMIN_USERNAME/PASSWORD,
    if set and that username doesn't already exist. See module docstring."""
    username = os.environ.get("TOOLKIT_ADMIN_USERNAME")
    password = os.environ.get("TOOLKIT_ADMIN_PASSWORD")
    if not username or not password:
        return

    users = _load_users()
    if any(user["username"].lower() == username.lower() for user in users):
        return

    users.append({
        "username": username,
        "password_hash": _hash_password(password),
        "role": "admin",
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    })
    _save_users(users)
    print(f"👤 Bootstrapped admin account '{username}' from TOOLKIT_ADMIN_USERNAME/PASSWORD.")


def create_user(username, password, role):
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {VALID_ROLES}")
    if not username or not username.strip():
        raise ValueError("username can't be empty")
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")

    users = _load_users()
    if any(user["username"].lower() == username.lower() for user in users):
        raise ValueError("a user with that username already exists")

    users.append({
        "username": username,
        "password_hash": _hash_password(password),
        "role": role,
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
    """Returns users WITHOUT password hashes - safe to hand to the frontend."""
    return [
        {"username": user["username"], "role": user["role"], "created_utc": user.get("created_utc")}
        for user in _load_users()
    ]


def authenticate(username, password):
    """Returns {"username", "role"} if the password is correct, else None."""
    for user in _load_users():
        if user["username"].lower() == username.lower():
            if _verify_password(password, user["password_hash"]):
                return {"username": user["username"], "role": user["role"]}
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

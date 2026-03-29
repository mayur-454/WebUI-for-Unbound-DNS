import json
import os
import hashlib
import secrets
import threading
from functools import wraps

CREDS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")

# ── Single-session enforcement ──────────────────────────────────────────────
# Maps username → current valid session token.
# When a new login happens the token is replaced, invalidating the previous session.
_active_sessions: dict[str, str] = {}
_sessions_lock = threading.Lock()


def get_active_sessions() -> dict[str, str]:
    with _sessions_lock:
        return dict(_active_sessions)


def set_active_session(username: str, token: str) -> None:
    with _sessions_lock:
        _active_sessions[username] = token


def clear_active_session(username: str) -> None:
    with _sessions_lock:
        _active_sessions.pop(username, None)


# ── Password helpers ──────────────────────────────────────────────────────────

def _hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 260_000
    ).hex()


def init_creds() -> None:
    """Create default admin/admin credentials file if it doesn't exist."""
    if not os.path.exists(CREDS_FILE):
        salt = secrets.token_hex(16)
        data = {
            "username": "admin",
            "salt": salt,
            "hash": _hash("admin", salt),
        }
        with open(CREDS_FILE, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[auth] Created default credentials at {CREDS_FILE}")
        print("[auth] Default login: admin / admin  — CHANGE THIS IMMEDIATELY")


def check_creds(username: str, password: str) -> bool:
    if not os.path.exists(CREDS_FILE):
        return False
    try:
        with open(CREDS_FILE) as f:
            data = json.load(f)
    except Exception:
        return False
    stored_user = data.get("username", "")
    stored_hash = data.get("hash", "")
    salt        = data.get("salt", "")
    # Constant-time comparisons to prevent timing attacks
    user_ok = secrets.compare_digest(username, stored_user)
    hash_ok = secrets.compare_digest(_hash(password, salt), stored_hash)
    return user_ok and hash_ok


def change_password(username: str, new_password: str) -> None:
    salt = secrets.token_hex(16)
    data = {
        "username": username,
        "salt": salt,
        "hash": _hash(new_password, salt),
    }
    with open(CREDS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def change_username(new_username: str, current_password: str) -> bool:
    """Change username — requires current password to confirm."""
    if not os.path.exists(CREDS_FILE):
        return False
    try:
        with open(CREDS_FILE) as f:
            data = json.load(f)
    except Exception:
        return False
    if not secrets.compare_digest(
        _hash(current_password, data.get("salt", "")),
        data.get("hash", ""),
    ):
        return False
    data["username"] = new_username
    with open(CREDS_FILE, "w") as f:
        json.dump(data, f, indent=2)
    return True

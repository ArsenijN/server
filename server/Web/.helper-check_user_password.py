#!/usr/bin/env python3
"""Check whether a plaintext password matches a stored hash for a given user.

Usage:
    python _helper-check_user_password.py <username> <password>

Exit codes:
    0 — password matches
    1 — password does not match or user not found
    2 — usage / environment error
"""
import sys
import sqlite3
import hashlib
import secrets as _secrets

# ---------------------------------------------------------------------------
# Bootstrap: load config so we find the DB regardless of working directory
# ---------------------------------------------------------------------------
try:
    from config import DB_FILE
except ImportError:
    print("ERROR: Could not import config.py. Run this script from the Web/ directory.", file=sys.stderr)
    sys.exit(2)

try:
    import bcrypt
except ImportError:
    print("ERROR: bcrypt not installed. Activate the venv first.", file=sys.stderr)
    sys.exit(2)


def _sha256_check(password: str, salt: str, stored_hash: str) -> bool:
    """Legacy SHA-256 verification path."""
    candidate = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return _secrets.compare_digest(candidate, stored_hash)


def check_password(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB_FILE, timeout=10)
    try:
        row = conn.execute(
            "SELECT password_hash, salt FROM users WHERE username = ?", (username,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        print(f"User '{username}' not found.", file=sys.stderr)
        return False

    stored_hash, salt = row

    if stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$'):
        # bcrypt path
        result = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    else:
        # Legacy SHA-256 path
        result = _sha256_check(password, salt, stored_hash)

    return result


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <username> <password>", file=sys.stderr)
        sys.exit(2)

    username, password = sys.argv[1], sys.argv[2]
    match = check_password(username, password)
    print("MATCH" if match else "NO MATCH")
    sys.exit(0 if match else 1)

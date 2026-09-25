#!/usr/bin/env python3
"""Check whether a plaintext password matches a stored hash for a given user.

Mirrors the server's login check (server_cdn.py → handle_login), so it
recognises all three hash generations still found in the DB:
    bcrypt(base64(sha256(pw)))   — current scheme (P6)
    bcrypt(pw)                   — pre-P6 bcrypt, upgraded on next login
    sha256(salt + pw)            — legacy, upgraded on next login

Usage:
    python .helper-check_user_password.py <username> <password>

Exit codes:
    0 — password matches
    1 — password does not match or user not found
    2 — usage / environment error
"""
import sys
import secrets as _secrets

# ---------------------------------------------------------------------------
# Bootstrap: import the server's own auth code so the hash scheme can never
# drift out of sync with what the login endpoint actually checks.
# ---------------------------------------------------------------------------
try:
    import bcrypt
    from core.db import _db_connect
    from core.auth import _prepare_password, _sha256_hash
except ImportError as e:
    print(f"ERROR: {e}. Run this script from the Web/ directory with the venv active.", file=sys.stderr)
    sys.exit(2)


def check_password(username: str, password: str) -> str | None:
    """Return the matching scheme name, or None if the password is wrong."""
    with _db_connect() as conn:
        row = conn.execute(
            "SELECT password_hash, salt FROM users WHERE username = ?", (username,)
        ).fetchone()

    if not row:
        print(f"User '{username}' not found.", file=sys.stderr)
        return None

    stored_hash, salt = row

    if stored_hash.startswith(('$2b$', '$2a$')):
        if bcrypt.checkpw(_prepare_password(password), stored_hash.encode('utf-8')):
            return 'bcrypt (current)'
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            return 'bcrypt (pre-P6, upgraded on next login)'
        return None

    legacy_hash, _ = _sha256_hash(password, salt)
    if _secrets.compare_digest(legacy_hash, stored_hash):
        return 'sha256 (legacy, upgraded on next login)'
    return None


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <username> <password>", file=sys.stderr)
        sys.exit(2)

    username, password = sys.argv[1], sys.argv[2]
    scheme = check_password(username, password)
    print(f"MATCH — {scheme}" if scheme else "NO MATCH")
    sys.exit(0 if scheme else 1)

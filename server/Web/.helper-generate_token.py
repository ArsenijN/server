#!/usr/bin/env python3
"""Generate a file-scoped download token for a given user and path.

Useful for minting a token via CLI, for example to share a protected file
without going through the web UI.

Usage:
    python _helper-generate_token.py <username> <password> <relative_file_path>

    relative_file_path -- path relative to SERVE_ROOT, starting with /
                          e.g. /FluxDrop/3/documents/report.pdf

The token is printed to stdout. It is valid for DOWNLOAD_TOKEN_TTL_SECONDS
(default 1 hour).

Exit codes:
    0 -- token printed successfully
    1 -- authentication failure
    2 -- usage / environment error
"""
import sys
import sqlite3
import hashlib
import secrets as _secrets
from datetime import datetime, timedelta

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

DOWNLOAD_TOKEN_TTL_SECONDS = 3600  # 1 hour, mirrors server_cdn.py default


def _verify_credentials(username: str, password: str, conn: sqlite3.Connection):
    """Return user_id if credentials are valid, else None."""
    row = conn.execute(
        "SELECT id, password_hash, salt FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not row:
        return None

    user_id, stored_hash, salt = row

    if stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$'):
        ok = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    else:
        # Legacy SHA-256 path
        candidate = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
        ok = _secrets.compare_digest(candidate, stored_hash)

    return user_id if ok else None


def generate_token(username: str, password: str, relative_path: str) -> str:
    conn = sqlite3.connect(DB_FILE, timeout=10)
    try:
        user_id = _verify_credentials(username, password, conn)
        if user_id is None:
            print("ERROR: Invalid credentials.", file=sys.stderr)
            sys.exit(1)

        raw = _secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        expires_at = (datetime.now() + timedelta(seconds=DOWNLOAD_TOKEN_TTL_SECONDS)).isoformat()

        conn.execute(
            "INSERT INTO download_tokens "
            "(token_hash, relative_path, user_id, expires_at, bytes_confirmed) "
            "VALUES (?, ?, ?, ?, 0)",
            (token_hash, relative_path, user_id, expires_at)
        )
        conn.commit()
    finally:
        conn.close()

    return raw


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <username> <password> <relative_file_path>", file=sys.stderr)
        sys.exit(2)

    username, password, rel_path = sys.argv[1], sys.argv[2], sys.argv[3]
    token = generate_token(username, password, rel_path)
    print(token)
    print(f"(expires in {DOWNLOAD_TOKEN_TTL_SECONDS // 60} minutes)", file=sys.stderr)

#!/usr/bin/env python3
"""Set (or reset) a user's password directly in the database.

Useful when a user is locked out and cannot use the email-reset flow,
or when bootstrapping the first admin account.

Usage:
    python _helper-set_user_password.py <username> <new_password>

This always writes a bcrypt hash (rounds=12). The legacy SHA-256 path is
intentionally not used here — any account touched by this tool is fully
migrated to bcrypt.

All existing sessions for the user are invalidated so no stale tokens survive.
"""
import sys
import sqlite3

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

_MIN_PASSWORD_LEN = 8
_MAX_PASSWORD_LEN = 1024


def set_password(username: str, new_password: str) -> None:
    if len(new_password) < _MIN_PASSWORD_LEN:
        print(f"ERROR: Password must be at least {_MIN_PASSWORD_LEN} characters.", file=sys.stderr)
        sys.exit(1)
    if len(new_password) > _MAX_PASSWORD_LEN:
        print(f"ERROR: Password must be at most {_MAX_PASSWORD_LEN} characters.", file=sys.stderr)
        sys.exit(1)

    new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

    conn = sqlite3.connect(DB_FILE, timeout=10)
    try:
        row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            print(f"ERROR: User '{username}' not found.", file=sys.stderr)
            sys.exit(1)

        user_id = row[0]
        conn.execute(
            "UPDATE users SET password_hash = ?, salt = '' WHERE id = ?",
            (new_hash, user_id)
        )
        deleted = conn.execute(
            "DELETE FROM sessions WHERE user_id = ?", (user_id,)
        ).rowcount
        conn.commit()
    finally:
        conn.close()

    print(f"Password updated for '{username}' (bcrypt, rounds=12).")
    if deleted:
        print(f"{deleted} active session(s) invalidated — user must log in again.")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <username> <new_password>", file=sys.stderr)
        sys.exit(2)

    set_password(sys.argv[1], sys.argv[2])

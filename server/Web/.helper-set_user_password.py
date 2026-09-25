#!/usr/bin/env python3
"""Set (or reset) a user's password directly in the database.

Useful when a user is locked out and cannot use the email-reset flow,
or when bootstrapping the first admin account.

Usage:
    python .helper-set_user_password.py <username> <new_password>

The hash is produced by the server's own core.auth.hash_password(), so it is
always the current scheme (bcrypt over a SHA-256 pre-hash, rounds=12) — any
account touched by this tool is fully migrated.

All existing sessions for the user are invalidated so no stale tokens survive.
"""
import sys

try:
    from core.db import _db_connect
    from core.auth import hash_password
except ImportError as e:
    print(f"ERROR: {e}. Run this script from the Web/ directory with the venv active.", file=sys.stderr)
    sys.exit(2)

# Same limits the register / change-password endpoints enforce.
_MIN_PASSWORD_LEN = 8
_MAX_PASSWORD_LEN = 1024


def set_password(username: str, new_password: str) -> None:
    if len(new_password) < _MIN_PASSWORD_LEN:
        print(f"ERROR: Password must be at least {_MIN_PASSWORD_LEN} characters.", file=sys.stderr)
        sys.exit(1)
    if len(new_password) > _MAX_PASSWORD_LEN:
        print(f"ERROR: Password must be at most {_MAX_PASSWORD_LEN} characters.", file=sys.stderr)
        sys.exit(1)

    new_hash, salt = hash_password(new_password)

    with _db_connect() as conn:
        row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            print(f"ERROR: User '{username}' not found.", file=sys.stderr)
            sys.exit(1)

        user_id = row[0]
        conn.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
            (new_hash, salt, user_id)
        )
        deleted = conn.execute(
            "DELETE FROM sessions WHERE user_id = ?", (user_id,)
        ).rowcount
        conn.commit()

    print(f"Password updated for '{username}' (bcrypt, rounds=12).")
    if deleted:
        print(f"{deleted} active session(s) invalidated — user must log in again.")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <username> <new_password>", file=sys.stderr)
        sys.exit(2)

    set_password(sys.argv[1], sys.argv[2])

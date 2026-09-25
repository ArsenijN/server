#!/usr/bin/env python3
"""Generate a file-scoped download token for a given user and path.

Useful for minting a token via CLI, for example to share a protected file
without going through the web UI.

Usage:
    python .helper-generate_token.py <username> <password> <file_path>

    file_path -- either user-relative, as the web UI lists it
                     e.g. /documents/report.pdf
                 or the absolute FluxDrop form
                     e.g. /FluxDrop/3/documents/report.pdf

The token is printed to stdout, followed by the download URL on stderr. It is
valid for DOWNLOAD_TOKEN_TTL seconds (default 1 hour), same as tokens minted
by /api/v1/download_token.

Exit codes:
    0 -- token printed successfully
    1 -- authentication failure / file not found
    2 -- usage / environment error
"""
import os
import sys
from urllib.parse import quote

try:
    from config import SERVE_ROOT, PUBLIC_BASE_URL
    from core.db import _db_connect
    # The server's own minting function, so the token's expires_at format and
    # path key always match what the download handler validates.
    from core.auth import _mint_download_token, DOWNLOAD_TOKEN_TTL_SECONDS
except ImportError as e:
    print(f"ERROR: {e}. Run this script from the Web/ directory with the venv active.", file=sys.stderr)
    sys.exit(2)

# Credential check lives in the sibling helper (its filename starts with a dot,
# so it can't be imported by name).
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location(
    '_check_pw', os.path.join(os.path.dirname(os.path.abspath(__file__)), '.helper-check_user_password.py'))
_check_pw = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_check_pw)


def _canonical_path(path: str, user_id: int) -> str | None:
    """Normalise to the user-relative form the download handler keys tokens on
    (same rules as handle_mint_download_token). None if it's another user's."""
    if not path.startswith('/'):
        path = '/' + path
    if path.lower().startswith('/fluxdrop/'):
        parts = path.lstrip('/').split('/', 2)   # ['FluxDrop', '<id>', 'rest...']
        if len(parts) < 2 or parts[1] != str(user_id):
            return None
        return '/' + parts[2] if len(parts) > 2 else '/'
    return path


def generate_token(username: str, password: str, path: str) -> tuple[str, str]:
    if not _check_pw.check_password(username, password):
        print("ERROR: Invalid credentials.", file=sys.stderr)
        sys.exit(1)

    with _db_connect() as conn:
        user_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]

    rel = _canonical_path(path, user_id)
    if rel is None:
        print("ERROR: Path belongs to a different user.", file=sys.stderr)
        sys.exit(1)

    user_root = os.path.realpath(os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))
    fs_path = os.path.realpath(os.path.join(user_root, rel.lstrip('/')))
    if os.path.commonpath([user_root, fs_path]) != user_root:
        print("ERROR: Path is outside the user's FluxDrop folder.", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(fs_path):
        print(f"ERROR: File not found: {fs_path}", file=sys.stderr)
        sys.exit(1)

    return _mint_download_token(rel, user_id), rel


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <username> <password> <file_path>", file=sys.stderr)
        sys.exit(2)

    token, rel = generate_token(sys.argv[1], sys.argv[2], sys.argv[3])
    print(token)
    print(f"URL: {PUBLIC_BASE_URL.rstrip('/')}/api/v1/download{quote(rel)}?dl_token={token}", file=sys.stderr)
    print(f"(expires in {DOWNLOAD_TOKEN_TTL_SECONDS // 60} minutes)", file=sys.stderr)

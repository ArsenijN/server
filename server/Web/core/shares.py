import sqlite3, secrets, logging, time
from core.db import _db_connect
from datetime import datetime

def _create_share(user_id: int, path: str, is_dir: bool, require_account: bool,
                  track_stats: bool, allow_anon_upload: bool, allow_auth_upload: bool,
                  expires_at=None, allow_preview: bool = False, allow_cdn_embed: bool = False) -> str:
    """Mint a new public share token and store it. Returns the raw token.
    expires_at: ISO datetime string or None for no expiry.
    """
    raw = secrets.token_urlsafe(24)
    with _db_connect() as conn:
        conn.execute(
            """INSERT INTO shared_links
               (token, owner_id, path, is_dir, require_account, track_stats,
                allow_anon_upload, allow_auth_upload, allow_preview, allow_cdn_embed,
                created_at, expires_at, access_count)
               VALUES (?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,?,0)""",
            (raw, user_id, path, 1 if is_dir else 0,
             1 if require_account else 0, 1 if track_stats else 0,
             1 if allow_anon_upload else 0, 1 if allow_auth_upload else 0,
             1 if allow_preview else 0, 1 if allow_cdn_embed else 0,
             expires_at)
        )
        conn.commit()
    return raw


def _get_shares_for_user(user_id: int) -> list:
    with _db_connect() as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """SELECT token, path, is_dir, require_account, track_stats,
                      allow_anon_upload, allow_auth_upload, allow_preview, allow_cdn_embed,
                      created_at, expires_at, access_count
               FROM shared_links WHERE owner_id = ? ORDER BY created_at DESC""",
            (user_id,)
        )
        return [dict(r) for r in cur.fetchall()]


def _get_share_raw(token: str) -> dict | None:
    """Return share row regardless of expiry, or None if token never existed."""
    with _db_connect() as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM shared_links WHERE token = ?", (token,))
        r = cur.fetchone()
        return dict(r) if r else None


def _parse_expiry(value: str):
    """Parse expiry string in any format the UI might send (ISO or DD.MM.YYYY)."""
    if not value:
        return None
    for fmt in ('%Y-%m-%dT%H:%M', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d.%m.%Y'):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.strip())
    except Exception:
        return None


def _is_share_expired(share: dict) -> bool:
    """Return True if the share has a past expiry date."""
    val = share.get('expires_at')
    if not val:
        return False
    exp = _parse_expiry(val)
    if exp is None:
        return False
    now = datetime.now(exp.tzinfo) if exp.tzinfo else datetime.now()
    return now > exp


def _get_share(token: str) -> dict | None:
    """Return share metadata if token exists and has not expired; else None."""
    share = _get_share_raw(token)
    if not share:
        return None
    if _is_share_expired(share):
        return None
    return share


def _update_share(token: str, owner_id: int, fields: dict):
    allowed = {'require_account', 'track_stats', 'allow_anon_upload', 'allow_auth_upload',
               'allow_preview', 'allow_cdn_embed', 'expires_at'}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return False
    parts = []
    vals = []
    for k, v in updates.items():
        parts.append(f"{k} = ?")
        if k == 'expires_at':
            vals.append(v if v else None)   # store None to remove expiry
        else:
            vals.append(1 if v else 0)
    vals += [token, owner_id]
    with _db_connect() as conn:
        cur = conn.execute(
            f"UPDATE shared_links SET {', '.join(parts)} WHERE token = ? AND owner_id = ?", vals
        )
        conn.commit()
        return cur.rowcount > 0


def _delete_share(token: str, owner_id: int) -> bool:
    with _db_connect() as conn:
        cur = conn.execute(
            "DELETE FROM shared_links WHERE token = ? AND owner_id = ?", (token, owner_id)
        )
        conn.commit()
        return cur.rowcount > 0


def _log_share_access(token: str, user_id, action: str = 'view'):
    try:
        with _db_connect() as conn:
            conn.execute(
                "INSERT INTO share_access_log (token, user_id, action, accessed_at) VALUES (?,?,?,CURRENT_TIMESTAMP)",
                (token, user_id, action)
            )
            conn.execute(
                "UPDATE shared_links SET access_count = access_count + 1 WHERE token = ?", (token,)
            )
            conn.commit()
    except Exception:
        logging.exception("Failed to log share access")


def _get_share_stats(token: str, owner_id: int) -> list | None:
    """Return access log for a share the requesting user owns."""
    with _db_connect() as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # Verify ownership
        cur.execute("SELECT id FROM shared_links WHERE token = ? AND owner_id = ?", (token, owner_id))
        if not cur.fetchone():
            return None
        cur.execute(
            """SELECT l.accessed_at, u.username, l.action
               FROM share_access_log l
               LEFT JOIN users u ON l.user_id = u.id
               WHERE l.token = ?
               ORDER BY l.accessed_at DESC LIMIT 200""",
            (token,)
        )
        return [dict(r) for r in cur.fetchall()]


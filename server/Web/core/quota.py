import os, time, threading, logging, shutil
from core.db import _db_connect
from core.trash import _trash_size_used, _user_trash_root
from config import SERVE_ROOT
from config import QUOTA_MAX_BYTES, DEFAULT_QUOTA_BYTES, QUOTA_MIN_BYTES

_GB = 1024 ** 3

# Space uploads may never use, so the disk can't fill up completely (the DB,
# logs, trash moves and temp files all need room too). The larger of a fixed
# amount and a share of the whole disk.
QUOTA_RESERVE_MIN_BYTES = int(float(os.getenv('QUOTA_RESERVE_GB', '20')) * _GB)
QUOTA_RESERVE_PCT       = float(os.getenv('QUOTA_RESERVE_PCT', '2')) / 100


def _get_server_free_bytes() -> int:
    return shutil.disk_usage(SERVE_ROOT).free


def _reserve_bytes() -> int:
    total = shutil.disk_usage(SERVE_ROOT).total
    return max(QUOTA_RESERVE_MIN_BYTES, int(total * QUOTA_RESERVE_PCT))


def _cached_user_usage(user_id: int) -> int:
    """User's stored bytes (minus trash) from the directory cache.

    Never walks the disk — a user whose folder hasn't been scanned yet counts
    as 0, which only makes the fair share below *smaller* (the safe side)
    until the background scan catches up.
    """
    from core.status import _dir_cache_get_ex   # lazy: core.status is heavy
    _c, total, warm = _dir_cache_get_ex(os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))
    if not warm:
        return 0
    _tc, trash, _tw = _dir_cache_get_ex(os.path.normpath(_user_trash_root(user_id)))
    return max(0, total - trash)


_quota_cache = {'value': None, 'at': 0.0}
_QUOTA_CACHE_TTL = 60   # it's called per upload and per admin-list row


def _compute_dynamic_quota() -> int:
    """Fair share of the space that's actually available, per non-pinned user.

        pool  = free space − reserve
                + what non-pinned users already store   (their share is theirs)
                − headroom still promised to pinned users
        quota = pool / number of non-pinned users, clamped to [MIN, MAX]

    Adding back what non-pinned users store means one user uploading doesn't
    shrink everyone else's quota (the old free-space tiers did exactly that);
    the quota only moves when users join or leave, pinned users grow, or the
    disk itself changes. And because it's a share of real space, the quotas
    together can't promise more than the disk has — except where the MIN
    floor kicks in, which the disk-full guard below still covers.
    """
    now = time.monotonic()
    if _quota_cache['value'] is not None and now - _quota_cache['at'] < _QUOTA_CACHE_TTL:
        return _quota_cache['value']
    try:
        with _db_connect() as conn:
            rows = conn.execute('SELECT id, quota_bytes, quota_override FROM users').fetchall()
        dynamic_ids   = [uid for uid, _q, ovr in rows if not ovr]
        pinned        = [(uid, q) for uid, q, ovr in rows if ovr and q]
        dynamic_usage = sum(_cached_user_usage(uid) for uid in dynamic_ids)
        pinned_headroom = sum(max(0, q - _cached_user_usage(uid)) for uid, q in pinned)
        pool  = _get_server_free_bytes() - _reserve_bytes() + dynamic_usage - pinned_headroom
        share = pool // max(1, len(dynamic_ids))
        quota = max(QUOTA_MIN_BYTES, min(QUOTA_MAX_BYTES, share))
        quota = (quota // _GB) * _GB   # whole GB — stable, readable numbers
    except Exception:
        logging.exception('Dynamic quota computation failed; using default')
        quota = DEFAULT_QUOTA_BYTES
    _quota_cache.update(value=quota, at=now)
    return quota


def _pending_buffer_bytes() -> int:
    """Bytes of unfinished 'buffer' uploads — they'll land on the data disk
    at completion but aren't there yet ('direct' uploads pre-allocate their
    space, so the disk's free space already accounts for them)."""
    with _db_connect() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(total_size), 0) FROM upload_sessions "
            "WHERE strategy = 'buffer' AND completed = 0 AND total_size > 0").fetchone()
    return int(row[0] or 0)


def _check_server_space(needed_bytes: int) -> None:
    """Raise ValueError when the server itself is out of room.

    Independent of the user's quota: quotas are per-user promises, this is the
    physical disk. Keeps the reserve free and fails the upload *before* any
    data is sent, with a message the user can understand, instead of a
    "No space left on device" error halfway through.
    """
    try:
        available = _get_server_free_bytes() - _reserve_bytes() - _pending_buffer_bytes()
    except Exception:
        logging.exception('Server space check failed; allowing upload')
        return
    if needed_bytes > available:
        raise ValueError(
            'The server is out of storage space right now, so new uploads are paused. '
            'Your existing files are safe. Please try again later.')


def _quota_updater_thread(interval_seconds=3600):
    """Hourly: recalculate and store dynamic quota for all non-override users."""
    while True:
        time.sleep(interval_seconds)
        try:
            _quota_cache['value'] = None          # force a fresh computation
            new_quota = _compute_dynamic_quota()
            with _db_connect() as conn:
                conn.execute(
                    'UPDATE users SET quota_bytes = ? WHERE quota_override = 0 OR quota_bytes IS NULL',
                    (new_quota,)
                )
                conn.commit()
            logging.info(f'Quota updated: {new_quota // _GB} GB per user')
        except Exception:
            logging.exception('Quota updater failed')

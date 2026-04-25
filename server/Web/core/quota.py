import os, time, threading, logging
from core.db import _db_connect
from core.trash import _trash_size_used
from config import SERVE_ROOT

# Never saw it actually changed - need to be tested
# Seems like related to the "small size of CDN drive" in my current server config
DEFAULT_QUOTA_BYTES = 50 * 1024 ** 3  # 50 GB
QUOTA_MIN_BYTES     = 10 * 1024 ** 3  # floor: never drop below 10 GB
QUOTA_MAX_BYTES     = 100 * 1024 ** 3 # ceiling: never exceed 100 GB

def _get_server_free_bytes() -> int:
    import shutil
    stat = shutil.disk_usage(SERVE_ROOT)
    return stat.free

def _compute_dynamic_quota() -> int:
    """
    Scale the default quota based on free disk space.
    Free > 500 GB  → 100 GB quota
    Free 200–500   → 50 GB  (default)
    Free 100–200   → 35 GB
    Free < 100     → 10 GB  (floor)
    """
    free = _get_server_free_bytes()
    gb = free / (1024 ** 3)
    if gb >= 500:   return QUOTA_MAX_BYTES
    if gb >= 200:   return DEFAULT_QUOTA_BYTES
    if gb >= 100:   return 35 * 1024 ** 3
    return QUOTA_MIN_BYTES

def _quota_updater_thread(interval_seconds=3600):
    """Hourly: recalculate and store dynamic quota for all non-override users."""
    while True:
        time.sleep(interval_seconds)
        try:
            new_quota = _compute_dynamic_quota()
            with _db_connect() as conn:
                conn.execute(
                    'UPDATE users SET quota_bytes = ? WHERE quota_override = 0 OR quota_bytes IS NULL',
                    (new_quota,)
                )
                conn.commit()
            logging.info(f'Quota updated: {new_quota // (1024**3)} GB per user')
        except Exception:
            logging.exception('Quota updater failed')

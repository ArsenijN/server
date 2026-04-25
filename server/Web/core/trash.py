import os, shutil, secrets, time, logging
from core.db import _db_connect
# needs SERVE_ROOT — import from server_cdn would be circular; instead:
from config import SERVE_ROOT   # or pass it in as a parameter

def _user_trash_root(user_id: int) -> str:
    return os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id), '.trash')

_TRASH_PRESSURE_THRESHOLD = 0.80

def _trash_retention_days() -> int:
    try:
        st = os.statvfs(SERVE_ROOT)
        used_frac = 1 - (st.f_bavail / st.f_blocks) if st.f_blocks else 0
        return 7 if used_frac >= _TRASH_PRESSURE_THRESHOLD else 30
    except Exception:
        return 30

def _trash_size_for(path: str) -> int:
    if os.path.isfile(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0
    total = 0
    try:
        for dp, _, fnames in os.walk(path):
            for fn in fnames:
                try:
                    total += os.path.getsize(os.path.join(dp, fn))
                except OSError:
                    pass
    except OSError:
        pass
    return total

def _move_to_trash(user_id: int, fs_path: str, original_path: str) -> dict:
    trash_root = _user_trash_root(user_id)
    os.makedirs(trash_root, exist_ok=True)
    size_bytes = _trash_size_for(fs_path)
    is_dir     = 1 if os.path.isdir(fs_path) else 0
    name       = os.path.basename(fs_path)
    uid_suffix = secrets.token_hex(4)
    trash_name = f"{name}__{uid_suffix}"
    trash_path = os.path.join(trash_root, trash_name)
    os.rename(fs_path, trash_path)
    retention  = _trash_retention_days()
    now        = time.time()
    return {
        'user_id':       user_id,
        'original_path': original_path,
        'trash_path':    trash_path,
        'deleted_at':    now,
        'size_bytes':    size_bytes,
        'is_dir':        is_dir,
        'retention_days': retention,
    }

def _trash_list(user_id: int) -> list:
    with _db_connect() as conn:
        rows = conn.execute(
            "SELECT id, original_path, trash_path, deleted_at, size_bytes, is_dir, retention_days"
            " FROM trash_items WHERE user_id = ? ORDER BY deleted_at DESC",
            (user_id,)
        ).fetchall()
    items = []
    for row in rows:
        tid, orig, tpath, deleted_at, size, is_dir, ret = row
        expires_at = deleted_at + ret * 86400
        items.append({
            'id':            tid,
            'original_path': orig,
            'name':          os.path.basename(orig),
            'deleted_at':    deleted_at,
            'expires_at':    expires_at,
            'size_bytes':    size,
            'is_dir':        bool(is_dir),
            'retention_days': ret,
            'trash_path':    tpath,
        })
    return items

def _trash_restore(user_id: int, item_id: int) -> str:
    with _db_connect() as conn:
        row = conn.execute(
            "SELECT original_path, trash_path, is_dir FROM trash_items WHERE id = ? AND user_id = ?",
            (item_id, user_id)
        ).fetchone()
        if not row:
            raise RuntimeError('Trash item not found.')
        orig, tpath, is_dir = row
        user_root = os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id))
        dest = os.path.join(user_root, orig.lstrip('/'))
        if os.path.exists(dest):
            raise RuntimeError(f'Cannot restore: {orig!r} already exists. Rename the existing file first.')
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        os.rename(tpath, dest)
        conn.execute('DELETE FROM trash_items WHERE id = ?', (item_id,))
        conn.commit()
    return orig

def _trash_delete_permanent(user_id: int, item_id: int) -> None:
    with _db_connect() as conn:
        row = conn.execute(
            "SELECT trash_path FROM trash_items WHERE id = ? AND user_id = ?",
            (item_id, user_id)
        ).fetchone()
        if not row:
            raise RuntimeError('Trash item not found.')
        tpath = row[0]
        if os.path.isdir(tpath):
            shutil.rmtree(tpath, ignore_errors=True)
        elif os.path.exists(tpath):
            os.remove(tpath)
        conn.execute('DELETE FROM trash_items WHERE id = ?', (item_id,))
        conn.commit()

def _trash_purge_expired() -> int:
    now = time.time()
    purged = 0
    try:
        with _db_connect() as conn:
            rows = conn.execute(
                "SELECT id, trash_path, is_dir FROM trash_items"
                " WHERE (deleted_at + retention_days * 86400) <= ?",
                (now,)
            ).fetchall()
            for tid, tpath, is_d in rows:
                try:
                    if is_d:
                        shutil.rmtree(tpath, ignore_errors=True)
                    elif os.path.exists(tpath):
                        os.remove(tpath)
                except Exception:
                    pass
                conn.execute('DELETE FROM trash_items WHERE id = ?', (tid,))
                purged += 1
            if purged:
                conn.commit()
    except Exception:
        logging.exception('trash_purge_expired failed')
    return purged

def _trash_size_used(user_id: int) -> int:
    try:
        with _db_connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(size_bytes),0) FROM trash_items WHERE user_id = ?",
                (user_id,)
            ).fetchone()
            return row[0] if row else 0
    except Exception:
        return 0

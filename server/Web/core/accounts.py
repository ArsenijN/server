"""Account deletion — what the Privacy Policy (§7) and TOS (§10) promise.

delete_account() removes the account's database rows immediately and moves
its FluxDrop folder into FluxDrop/.deleted_accounts/<id>-<unix time>/.
purge_deleted_accounts() (run by the periodic worker) removes those folders
for good once DELETED_ACCOUNT_PURGE_DAYS have passed. The grace period exists
so an accidental or disputed deletion can still be undone by hand.
"""
import logging
import os
import shutil
import time

from config import SERVE_ROOT, DELETED_ACCOUNT_PURGE_DAYS
from core.db import _db_connect

DELETED_ROOT = os.path.join(SERVE_ROOT, 'FluxDrop', '.deleted_accounts')


def delete_account(user_id: int) -> dict:
    """Delete an account now; its files follow after the grace period.

    Tables declared with ON DELETE CASCADE (trash_items, notifications,
    policy acceptances, checksums, jobs …) go with the users row. The older
    tables below reference users(id) *without* a cascade, so they must be
    cleared first — with foreign_keys=ON the users DELETE fails otherwise.
    """
    uid = int(user_id)
    with _db_connect() as conn:
        if not conn.execute('SELECT 1 FROM users WHERE id = ?', (uid,)).fetchone():
            raise LookupError('not_found')
        tokens = [r[0] for r in conn.execute(
            'SELECT token FROM shared_links WHERE owner_id = ?', (uid,)).fetchall()]
        for tok in tokens:
            conn.execute('DELETE FROM share_access_log WHERE token = ?', (tok,))
        conn.execute('DELETE FROM shared_links WHERE owner_id = ?', (uid,))
        # Their visits to other people's links: drop the username link, keep the count.
        conn.execute('UPDATE share_access_log SET user_id = NULL WHERE user_id = ?', (uid,))
        conn.execute('DELETE FROM sessions WHERE user_id = ?', (uid,))
        conn.execute('DELETE FROM download_tokens WHERE user_id = ?', (uid,))
        conn.execute('DELETE FROM protected_files WHERE created_by = ?', (uid,))
        conn.execute('UPDATE cdn_uploads SET uploaded_by = NULL WHERE uploaded_by = ?', (uid,))
        dev_ids = [r[0] for r in conn.execute(
            'SELECT id FROM beacon_devices WHERE user_id = ?', (uid,)).fetchall()]
        for d in dev_ids:
            conn.execute('DELETE FROM beacon_read_tokens WHERE device_id = ?', (d,))
        conn.execute('DELETE FROM beacon_devices WHERE user_id = ?', (uid,))
        conn.execute("DELETE FROM upload_sessions WHERE owner_type IN ('user', 'catbox') AND owner_ref = ?",
                     (str(uid),))
        # Reports stay (they document takedowns) but lose the personal link.
        conn.execute('UPDATE content_reports SET reporter_user_id = NULL WHERE reporter_user_id = ?', (uid,))
        conn.execute('DELETE FROM users WHERE id = ?', (uid,))
        conn.commit()

    moved_to = None
    user_dir = os.path.join(SERVE_ROOT, 'FluxDrop', str(uid))
    if os.path.isdir(user_dir):
        os.makedirs(DELETED_ROOT, exist_ok=True)
        moved_to = os.path.join(DELETED_ROOT, f'{uid}-{int(time.time())}')
        os.rename(user_dir, moved_to)   # same filesystem → instant, no copy
    logging.info('Account %s deleted; files %s', uid,
                 f'moved to {moved_to} (purged after {DELETED_ACCOUNT_PURGE_DAYS} days)'
                 if moved_to else 'folder not found')
    return {'files_pending_purge': bool(moved_to), 'purge_days': DELETED_ACCOUNT_PURGE_DAYS}


def purge_deleted_accounts() -> int:
    """Remove deleted accounts' folders older than the grace period."""
    if not os.path.isdir(DELETED_ROOT):
        return 0
    cutoff = time.time() - DELETED_ACCOUNT_PURGE_DAYS * 86400
    purged = 0
    for entry in os.scandir(DELETED_ROOT):
        try:
            deleted_at = int(entry.name.rsplit('-', 1)[1])
        except (IndexError, ValueError):
            continue          # not ours — leave anything unexpected alone
        if deleted_at < cutoff and entry.is_dir(follow_symlinks=False):
            shutil.rmtree(entry.path, ignore_errors=True)
            purged += 1
            logging.info('Purged files of deleted account folder %s', entry.name)
    return purged

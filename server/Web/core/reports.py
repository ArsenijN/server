"""Content reports — the Report button on share pages and the /report form.

A report is only a pointer (URL + reason + message); nothing is taken down
automatically. The operator reviews reports in the admin panel and picks an
action. See TOS §6 and Privacy Policy §2.12 for the promises this backs.
"""
import logging
import os
import re
import threading
from urllib.parse import urlparse, unquote

from config import (SERVE_ROOT, CDN_UPLOAD_DIR, CATBOX_UPLOAD_DIR, PUBLIC_BASE_URL,
                    REPORT_NOTIFY_EMAIL, CONTACT_EMAIL)
from core.db import _db_connect
from core.mailer import send_plain
from core.rate_limit import _rate_limit

REPORT_REASONS = ('illegal', 'copyright', 'encrypted', 'abuse', 'other')
REPORT_STATUSES = ('open', 'action_taken', 'dismissed')
MAX_MESSAGE_LEN = 4000
MAX_URL_LEN = 2048

_EMAIL_RE = re.compile(r'^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$')
_SHARE_RE = re.compile(r'^/share/([A-Za-z0-9_\-]+)(?:/.*)?$')


def resolve_target(target_url: str) -> dict:
    """Work out what a reported URL points to.

    Returns {'share_token', 'cdn_path', 'owner_id'} — any of them may be None
    when the URL isn't one of ours (the report is still stored; the operator
    can look at it manually).
    """
    out = {'share_token': None, 'cdn_path': None, 'owner_id': None}
    try:
        path = unquote(urlparse(target_url.strip()).path or '')
    except ValueError:
        return out
    m = _SHARE_RE.match(path)
    if m:
        out['share_token'] = m.group(1)
        with _db_connect() as conn:
            row = conn.execute('SELECT owner_id FROM shared_links WHERE token = ?',
                               (m.group(1),)).fetchone()
        if row:
            out['owner_id'] = row[0]
        return out
    cb_prefix = '/' + CATBOX_UPLOAD_DIR.strip('/') + '/'
    if path.startswith(cb_prefix) or path.startswith('/cdn/'):
        out['cdn_path'] = path
        name = os.path.basename(path)
        with _db_connect() as conn:
            row = conn.execute('SELECT uploaded_by FROM cdn_uploads WHERE filename = ?',
                               (name,)).fetchone()
            if not row and path.startswith(cb_prefix):
                # CatBox uploads are recorded in catbox_uploads since V0.22.0.26
                row = conn.execute('SELECT user_id FROM catbox_uploads WHERE name = ?',
                                   (name,)).fetchone()
        if row:
            out['owner_id'] = row[0]
    return out


def cdn_path_to_fs(cdn_path: str) -> str | None:
    """Map a reported CDN / CatBox URL path to the file on disk (or None)."""
    cb_prefix = '/' + CATBOX_UPLOAD_DIR.strip('/') + '/'
    if cdn_path.startswith(cb_prefix):
        root = os.path.realpath(os.path.join(SERVE_ROOT, CATBOX_UPLOAD_DIR))
        rel = cdn_path[len(cb_prefix):]
    elif cdn_path.startswith('/cdn/'):
        root = os.path.realpath(CDN_UPLOAD_DIR)
        rel = cdn_path[len('/cdn/'):]
    else:
        return None
    fs = os.path.realpath(os.path.join(root, rel))
    if fs != root and os.path.commonpath([root, fs]) == root and os.path.isfile(fs):
        return fs
    return None


def create_report(target_url: str, reason: str, message: str,
                  reporter_user_id=None, reporter_email: str | None = None) -> int:
    """Validate and store a report; e-mail the operator. Raises ValueError."""
    target_url = (target_url or '').strip()
    if not target_url or len(target_url) > MAX_URL_LEN:
        raise ValueError('bad_url')
    if reason not in REPORT_REASONS:
        raise ValueError('bad_reason')
    message = (message or '').strip()[:MAX_MESSAGE_LEN]
    if reason == 'other' and not message:
        raise ValueError('message_required')
    reporter_email = (reporter_email or '').strip() or None
    if reporter_email and (len(reporter_email) > 254 or not _EMAIL_RE.match(reporter_email)):
        raise ValueError('bad_email')

    t = resolve_target(target_url)
    with _db_connect() as conn:
        cur = conn.execute(
            '''INSERT INTO content_reports
               (target_url, share_token, cdn_path, owner_id, reason, message,
                reporter_user_id, reporter_email)
               VALUES (?,?,?,?,?,?,?,?)''',
            (target_url, t['share_token'], t['cdn_path'], t['owner_id'], reason, message,
             reporter_user_id, reporter_email))
        conn.commit()
        report_id = cur.lastrowid
    _notify_operator(report_id, target_url, reason, message, t)
    return report_id


def _app_home_url() -> str:
    # fluxdrop.me serves the app at /, the other domains under /fluxdrop_pp/
    base = PUBLIC_BASE_URL.rstrip('/')
    return base + ('/' if 'fluxdrop.me' in base else '/fluxdrop_pp/')


def _notify_operator(report_id, target_url, reason, message, t):
    if not REPORT_NOTIFY_EMAIL:
        logging.info('Content report #%s received (REPORT_NOTIFY_EMAIL not set, no alert sent)', report_id)
        return
    # The per-IP limit on /api/v1/report doesn't stop a flood from many IPs;
    # cap the alert mails overall (the reports themselves are all stored and
    # show up in the admin panel).
    if not _rate_limit('all', 'report_mail', max_hits=10):
        logging.warning('Content report #%s: alert mail skipped (over 10/min)', report_id)
        return
    kind = ('share link' if t['share_token'] else
            'CDN file' if t['cdn_path'] else 'unrecognised URL')
    body = (
        f"New FluxDrop content report #{report_id}\n\n"
        f"Target:  {target_url}\n"
        f"Type:    {kind}" + (f" (owner user id {t['owner_id']})" if t['owner_id'] else '') + "\n"
        f"Reason:  {reason}\n\n"
        f"Message:\n{message or '(none)'}\n\n"
        f"Review it in the admin panel: {_app_home_url()} → Admin panel → Reports\n"
    )
    # Off the request thread — a slow SMTP server must not delay the reply.
    threading.Thread(
        target=send_plain,
        args=(REPORT_NOTIFY_EMAIL, f'[FluxDrop] Content report #{report_id}: {reason}', body),
        name='ReportNotify', daemon=True,
    ).start()


def list_reports(status: str | None = None, limit: int = 200) -> list[dict]:
    q = '''SELECT r.id, r.created_at, r.target_url, r.share_token, r.cdn_path,
                  r.owner_id, o.username AS owner_username, r.reason, r.message,
                  -- language the owner email goes out in (same lookup as _notify_owner)
                  COALESCE((SELECT u2.lang FROM shared_links s JOIN users u2 ON u2.id = s.owner_id
                             WHERE s.token = r.share_token), o.lang, 'en') AS owner_lang,
                  ru.username AS reporter_username, r.reporter_email,
                  r.status, r.resolution_note, r.closed_at,
                  (SELECT 1 FROM shared_links s WHERE s.token = r.share_token
                      AND s.disabled_at IS NULL) AS share_active,
                  (SELECT 1 FROM shared_links s WHERE s.token = r.share_token
                      AND s.disabled_at IS NOT NULL) AS share_disabled
           FROM content_reports r
           LEFT JOIN users o  ON o.id  = r.owner_id
           LEFT JOIN users ru ON ru.id = r.reporter_user_id'''
    args = []
    if status:
        q += ' WHERE r.status = ?'
        args.append(status)
    q += ' ORDER BY (r.status = \'open\') DESC, r.id DESC LIMIT ?'
    args.append(limit)
    with _db_connect() as conn:
        conn.row_factory = __import__('sqlite3').Row
        rows = [dict(r) for r in conn.execute(q, args).fetchall()]
    for r in rows:
        r['share_active'] = bool(r['share_active'])
        r['share_disabled'] = bool(r['share_disabled'])
        r['cdn_file_exists'] = bool(r['cdn_path'] and cdn_path_to_fs(r['cdn_path']))
    return rows


def count_open() -> int:
    with _db_connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM content_reports WHERE status = 'open'").fetchone()[0]


def apply_action(report_id: int, action: str, note: str = '', owner_note: str = '') -> dict:
    """Admin action on a report. Raises ValueError / LookupError.

    disable_link  — disable the reported share link (files stay with the owner;
                    visitors see "disabled after a report", the owner is
                    emailed with owner_note and sees it in the links manager)
    restore_link  — undo disable_link (report → dismissed, owner emailed)
    delete_file   — delete a reported CDN / CatBox file from disk
    resolve       — mark handled (action taken outside this panel)
    dismiss       — no violation found
    reopen        — back to open
    """
    note = (note or '').strip()[:1000]
    owner_note = (owner_note or '').strip()[:1000]
    notify = None   # ('disabled' | 'restored', share_token) — mailed after commit
    with _db_connect() as conn:
        row = conn.execute('SELECT share_token, cdn_path, reason FROM content_reports WHERE id = ?',
                           (report_id,)).fetchone()
        if not row:
            raise LookupError('not_found')
        share_token, cdn_path, reason = row
        if action == 'disable_link':
            if not share_token:
                raise ValueError('not_a_share')
            cur = conn.execute(
                '''UPDATE shared_links SET disabled_at = CURRENT_TIMESTAMP, disabled_reason = ?,
                          disabled_note = ?, disabled_report_id = ?
                   WHERE token = ? AND disabled_at IS NULL''',
                (reason, owner_note or None, report_id, share_token))
            if not cur.rowcount:
                raise ValueError('link_gone')
            notify = ('disabled', share_token)
            status, auto_note = 'action_taken', 'Share link disabled'
        elif action == 'restore_link':
            if not share_token:
                raise ValueError('not_a_share')
            cur = conn.execute(
                '''UPDATE shared_links SET disabled_at = NULL, disabled_reason = NULL,
                          disabled_note = NULL, disabled_report_id = NULL
                   WHERE token = ? AND disabled_at IS NOT NULL''', (share_token,))
            if not cur.rowcount:
                raise ValueError('not_disabled')
            notify = ('restored', share_token)
            status, auto_note = 'dismissed', 'Share link restored'
        elif action == 'delete_file':
            fs = cdn_path_to_fs(cdn_path) if cdn_path else None
            if not fs:
                raise ValueError('no_file')
            os.remove(fs)
            conn.execute('DELETE FROM cdn_uploads WHERE filename = ?', (os.path.basename(fs),))
            # Also drop the CatBox record, or the deleted file would keep
            # counting against its owner's quota (catbox_user_bytes).
            conn.execute('DELETE FROM catbox_uploads WHERE name = ?', (os.path.basename(fs),))
            status, auto_note = 'action_taken', 'File deleted'
        elif action == 'resolve':
            status, auto_note = 'action_taken', ''
        elif action == 'dismiss':
            status, auto_note = 'dismissed', ''
        elif action == 'reopen':
            status, auto_note = 'open', ''
        else:
            raise ValueError('bad_action')
        full_note = '; '.join(x for x in (auto_note, note) if x) or None
        if status == 'open':
            conn.execute("UPDATE content_reports SET status='open', closed_at=NULL WHERE id = ?",
                         (report_id,))
        else:
            conn.execute(
                '''UPDATE content_reports SET status = ?, closed_at = CURRENT_TIMESTAMP,
                       resolution_note = COALESCE(?, resolution_note) WHERE id = ?''',
                (status, full_note, report_id))
        # Other open reports about the same target were handled by the same
        # takedown — close them too so the queue doesn't show stale duplicates.
        if action in ('disable_link', 'delete_file'):
            col, val = ('share_token', share_token) if action == 'disable_link' else ('cdn_path', cdn_path)
            conn.execute(
                f'''UPDATE content_reports SET status='action_taken', closed_at=CURRENT_TIMESTAMP,
                        resolution_note = COALESCE(resolution_note, ?)
                    WHERE {col} = ? AND status = 'open' ''',
                (f'Closed with report #{report_id}', val))
        conn.commit()
    logging.info('Content report #%s: %s', report_id, action)
    if notify:
        _notify_owner(*notify)
    return {'status': status}


def _notify_owner(kind: str, share_token: str) -> None:
    """Email the link's owner that it was disabled after a report / restored.
    In the owner's language; never says who reported it."""
    from core.snippets import tr
    with _db_connect() as conn:
        row = conn.execute(
            '''SELECT s.path, s.is_dir, s.disabled_reason, s.disabled_note, u.email, u.lang
               FROM shared_links s JOIN users u ON u.id = s.owner_id WHERE s.token = ?''',
            (share_token,)).fetchone()
    if not row or not row[4]:
        return
    path, is_dir, reason, owner_note, email, lang = row
    lang = lang or 'en'
    name = path.rstrip('/').split('/')[-1] or path
    contact = CONTACT_EMAIL or 'https://github.com/ArsenijN'
    if kind == 'disabled':
        subject = tr(lang, 'email_share_disabled_subject', name=name)
        body = tr(lang, 'email_share_disabled_body', name=name, path=path,
                  reason=tr(lang, f'report_reason_{reason}') if reason else '—',
                  note=owner_note or '—', contact=contact, app=_app_home_url())
    else:
        subject = tr(lang, 'email_share_restored_subject', name=name)
        body = tr(lang, 'email_share_restored_body', name=name, path=path, app=_app_home_url())
    threading.Thread(target=send_plain, args=(email, subject, body),
                     name='ShareTakedownNotify', daemon=True).start()


def prune_closed_reports(days: int = 365) -> None:
    with _db_connect() as conn:
        conn.execute(
            "DELETE FROM content_reports WHERE status != 'open' AND closed_at < datetime('now', ?)",
            (f'-{days} days',))
        conn.commit()

import threading, time, json, logging
from core.db import _db_connect
# SMTP config — these globals must come with it:
import os
SMTP_SERVER          = os.getenv('SMTP_SERVER', '')
SMTP_PORT            = int(os.getenv('SMTP_PORT', '587'))
SMTP_SENDER_EMAIL    = os.getenv('SMTP_SENDER_EMAIL', '')
SMTP_SENDER_PASSWORD = os.getenv('SMTP_SENDER_PASSWORD', '')

def _get_upload_notifications(user_id: int) -> list:
    """Return all enabled notification subscriptions for a user."""
    try:
        with _db_connect() as conn:
            rows = conn.execute(
                "SELECT id, type, target, secret FROM upload_notifications "
                "WHERE user_id=? AND enabled=1",
                (user_id,)
            ).fetchall()
        return [{"id": r[0], "type": r[1], "target": r[2], "secret": r[3]}
                for r in rows]
    except Exception:
        logging.exception("_get_upload_notifications failed")
        return []


def _fire_upload_notification(user_id: int, path: str, message: str) -> None:
    """Fire all enabled notifications for user_id in a background thread.

    Supports two delivery types:
      - webhook: HTTP POST with JSON payload + optional HMAC-SHA256 signature header
      - email:   SMTP (using the existing send_verification_email infrastructure)
    """
    subs = _get_upload_notifications(user_id)
    if not subs:
        return

    payload = {
        "event":   "upload_complete",
        "user_id": user_id,
        "path":    path,
        "message": message,
        "ts":      time.time(),
    }

    def _do_fire():
        import urllib.request as _ur, urllib.error as _ue, hmac as _hmac, hashlib as _hl

        for sub in subs:
            try:
                if sub["type"] == "webhook":
                    body = json.dumps(payload).encode()
                    req  = _ur.Request(
                        sub["target"],
                        data=body,
                        headers={"Content-Type": "application/json",
                                 "User-Agent":    "FluxDrop-Notify/1.0"},
                        method="POST",
                    )
                    if sub["secret"]:
                        sig = _hmac.new(
                            sub["secret"].encode(), body, _hl.sha256
                        ).hexdigest()
                        req.add_header("X-FluxDrop-Signature", f"sha256={sig}")
                    try:
                        with _ur.urlopen(req, timeout=10) as resp:
                            logging.info(
                                f"Notification sent to webhook {sub['target']!r} "
                                f"(HTTP {resp.status})"
                            )
                    except _ue.HTTPError as e:
                        logging.warning(
                            f"Notification webhook {sub['target']!r} returned {e.code}"
                        )
                    except Exception as exc:
                        logging.warning(
                            f"Notification webhook {sub['target']!r} failed: {exc}"
                        )

                elif sub["type"] == "email":
                    # Reuse existing SMTP infrastructure
                    if not SMTP_SENDER_EMAIL or not SMTP_SENDER_PASSWORD:
                        logging.warning("SMTP not configured; skipping email notification")
                        continue
                    import smtplib as _smtp
                    from email.mime.text import MIMEText as _MT
                    msg = _MT(
                        f"FluxDrop upload notification\\n\\n"
                        f"Path:    {path}\\n"
                        f"Message: {message}\\n"
                        f"Time:    {time.strftime('%Y-%m-%d %H:%M:%S')}\\n",
                        "plain"
                    )
                    msg["Subject"] = "FluxDrop: upload complete"
                    msg["From"]    = SMTP_SENDER_EMAIL
                    msg["To"]      = sub["target"]
                    try:
                        with _smtp.SMTP(SMTP_SERVER, SMTP_PORT) as srv:
                            srv.ehlo()
                            if SMTP_PORT == 587:
                                srv.starttls(); srv.ehlo()
                            srv.login(SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD)
                            srv.sendmail(SMTP_SENDER_EMAIL, [sub["target"]], msg.as_string())
                        logging.info(f"Notification email sent to {sub['target']!r}")
                    except Exception as exc:
                        logging.warning(f"Notification email to {sub['target']!r} failed: {exc}")
            except Exception:
                logging.exception(f"_fire_upload_notification: unexpected error for sub {sub}")

    threading.Thread(target=_do_fire, name="UploadNotify", daemon=True).start()

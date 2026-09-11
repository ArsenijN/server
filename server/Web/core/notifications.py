import threading, time, json, logging, re, socket, ipaddress
import urllib.request as _ur, urllib.error as _ue, urllib.parse as _up
from core.db import _db_connect
# SMTP config — these globals must come with it:
import os
from config import SMTP_PORT, SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD, SMTP_SERVER

# ── B13: SSRF-safe webhook delivery ─────────────────────────────────────────
# Webhook targets are supplied by an authenticated user (POST /api/v1/notifications)
# and this server makes the request on every upload — a naive urlopen() against
# an attacker-chosen URL is a textbook SSRF: it can reach loopback (the CDN's
# own internal port), the LAN, cloud metadata endpoints, and — via the default
# global opener's FileHandler — even local files. This builds a private opener
# restricted to http/https, and validates every hostname (including redirect
# targets) resolves to a public IP before connecting.

_EMAIL_RE = re.compile(r'^[^\s@<>\r\n]+@[^\s@<>\r\n]+\.[^\s@<>\r\n]+$')


def _resolve_ips(hostname: str) -> set:
    try:
        return {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except Exception:
        return set()


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _is_safe_webhook_url(url: str) -> bool:
    """True iff *url* is http(s), has a hostname, and every IP that hostname
    resolves to is a public (non-private/loopback/link-local/reserved) address.
    Call this again on every redirect hop — DNS can point anywhere, and a
    302 is how a naive host/scheme check at subscribe-time gets bypassed."""
    try:
        parsed = _up.urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        return False
    ips = _resolve_ips(parsed.hostname)
    return bool(ips) and all(_is_public_ip(ip) for ip in ips)


class _SafeRedirectHandler(_ur.HTTPRedirectHandler):
    """Re-validates the destination of every redirect hop before following it
    — otherwise an attacker-controlled https://looks-fine.example/ that 302s
    to http://127.0.0.1:64799/ would sail through the initial check."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_safe_webhook_url(newurl):
            raise _ue.HTTPError(newurl, code, 'Redirect to a disallowed host was blocked', headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# No FileHandler/FTPHandler/etc — only http(s), and only through the handler
# above, which re-checks every redirect.
_safe_opener = _ur.build_opener(_ur.HTTPHandler, _ur.HTTPSHandler, _SafeRedirectHandler)


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
        import hmac as _hmac, hashlib as _hl

        for sub in subs:
            try:
                if sub["type"] == "webhook":
                    # B13: re-validate at send time, not just at subscribe time —
                    # DNS for the target host can point anywhere by the time an
                    # upload actually fires the notification.
                    if not _is_safe_webhook_url(sub["target"]):
                        logging.warning(
                            f"Notification webhook {sub['target']!r} blocked: "
                            f"target does not resolve to a public address"
                        )
                        continue
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
                        with _safe_opener.open(req, timeout=10) as resp:
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
                    # B13/B17: validate the address shape and reject control
                    # characters — target is user-supplied and lands directly in
                    # an SMTP header (msg['To']) and the envelope recipient list.
                    target = sub["target"]
                    if '\r' in target or '\n' in target or not _EMAIL_RE.match(target):
                        logging.warning(f"Notification email target {target!r} rejected: not a valid address")
                        continue
                    import smtplib as _smtp
                    from email.mime.text import MIMEText as _MT
                    msg = _MT(
                        f"FluxDrop upload notification\n\n"
                        f"Path:    {path}\n"
                        f"Message: {message}\n"
                        f"Time:    {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
                        "plain"
                    )
                    msg["Subject"] = "FluxDrop: upload complete"
                    msg["From"]    = SMTP_SENDER_EMAIL
                    msg["To"]      = target
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

"""Outgoing email — one place that knows how to talk to the SMTP server.

Used by account verification (core/auth.py), upload notifications
(core/notifications.py) and content-report alerts. Supports:
  • port 465 — implicit TLS (SMTP_SSL)
  • port 587 — STARTTLS
  • anything else — plain SMTP, upgraded with STARTTLS when offered
"""
import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.utils import formataddr, make_msgid

from config import (SMTP_SERVER, SMTP_PORT, SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD,
                    SMTP_USERNAME, SMTP_SENDER_NAME, SMTP_REPLY_TO)


def smtp_configured() -> bool:
    return bool(SMTP_SERVER and SMTP_SENDER_EMAIL and SMTP_SENDER_PASSWORD)


def send_message(msg, to_addrs: list[str]) -> bool:
    """Fill in the standard headers and send. Returns True on success.

    Callers build the body; From / Reply-To / Message-ID are set here so every
    mail FluxDrop sends looks the same (and passes DMARC alignment as long as
    SMTP_SENDER_EMAIL is on the domain the provider signs for).
    """
    if not smtp_configured():
        logging.warning('SMTP not configured; not sending %r', msg.get('Subject'))
        return False
    if 'From' in msg:
        del msg['From']
    msg['From'] = formataddr((SMTP_SENDER_NAME, SMTP_SENDER_EMAIL)) if SMTP_SENDER_NAME else SMTP_SENDER_EMAIL
    if SMTP_REPLY_TO and 'Reply-To' not in msg:
        msg['Reply-To'] = SMTP_REPLY_TO
    if 'Message-ID' not in msg:
        msg['Message-ID'] = make_msgid(domain=SMTP_SENDER_EMAIL.rpartition('@')[2] or None)
    ctx = ssl.create_default_context()
    try:
        if SMTP_PORT == 465:
            srv = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=ctx, timeout=30)
        else:
            srv = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30)
        with srv:
            srv.ehlo()
            if SMTP_PORT != 465 and (SMTP_PORT == 587 or srv.has_extn('starttls')):
                srv.starttls(context=ctx)
                srv.ehlo()
            srv.login(SMTP_USERNAME, SMTP_SENDER_PASSWORD)
            srv.sendmail(SMTP_SENDER_EMAIL, to_addrs, msg.as_string())
        return True
    except Exception:
        logging.exception('Failed to send email %r to %s', msg.get('Subject'), to_addrs)
        return False


def send_plain(to: str, subject: str, body: str) -> bool:
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = subject
    msg['To'] = to
    return send_message(msg, [to])

import bcrypt, secrets, hashlib, time, logging, smtplib, os
import base64 as _base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from core.db import _db_connect
from core.rate_limit import _rate_limit
from core.notifications import SMTP_SERVER, SMTP_PORT, SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD
from core.snippets import _render_snippet
from config import PUBLIC_DOMAIN, HTTPS_PORT, SERVE_DIRECTORY
from email.mime.image import MIMEImage
from datetime import datetime, timedelta

# ── P1: Session token hashing ────────────────────────────────────────────
def _hash_session_token(raw: str) -> str:
    """SHA-256 hash a raw session token for safe DB storage.
    The raw token is returned to the client; only the hash is persisted."""
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

# ── P6: bcrypt safe wrapper ───────────────────────────────────────────────
def _prepare_password(password: str) -> bytes:
    """SHA-256 + base64-encode so bcrypt always receives exactly 44 bytes.
    bcrypt truncates at 72 bytes; pre-hashing avoids silent collision for
    passwords whose first 72 bytes are identical."""
    digest = hashlib.sha256(password.encode('utf-8')).digest()
    return _base64.b64encode(digest)   # always 44 bytes, well under the 72-byte limit

def _sha256_hash(password: str, salt: str) -> tuple[str, str]:
    """Legacy SHA-256 hash — used only during the bcrypt migration path."""
    salted = (salt + password).encode('utf-8')
    return hashlib.sha256(salted).hexdigest(), salt

def hash_password(password: str, salt=None) -> tuple[str, str]:
    """Hash a password with bcrypt.

    The ``salt`` parameter is accepted for call-site compatibility with the
    old SHA-256 path but is ignored — bcrypt embeds its own random salt.
    Returns ``(hashed, '')`` so callers that unpack two values still work;
    the empty string signals "no external salt".
    """
    hashed = bcrypt.hashpw(_prepare_password(password), bcrypt.gensalt(rounds=12))   # ← P6
    return hashed.decode('utf-8'), ''

def send_verification_email(email, token, username):
    """Sends a verification email to the user.

    The function can operate in three modes:
    1. **Simulation** – when SMTP settings are missing or explicitly
       left as placeholders.  In this case we log the verification link and
       return ``True`` so the caller treats the address as "sent".
    2. **Real send** – when all SMTP parameters are present.  A failure
       during the SMTP transaction is logged but does **not** cause the
       registration to fail; we fall back to simulation in that scenario.
    3. **Error** – only if an unexpected exception occurs *outside* the
       SMTP block (such as formatting the message) will we return ``False``.
    """
    verification_link = f"https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/auth/verify?token={token}"

    # If essential SMTP configuration is missing, simulate and log.
    if not SMTP_SERVER or not SMTP_SENDER_EMAIL or not SMTP_SENDER_PASSWORD:
        logging.error("SMTP configuration incomplete; simulating verification email.")
        logging.info(f"EMAIL SIMULATION: Verification link for {email}: {verification_link}")
        return True

    # Compose the message once, regardless of send outcome.
    subject = "Verify your FluxDrop Account"

    # Try to load icon.svg and convert it to a transparent PNG for embedding.
    # Gmail blocks SVG entirely; only raster formats work.
    # We use wand to rasterise at high resolution then crop to content so the
    # transparent background is preserved (no white box on mobile).
    icon_path = os.path.join(SERVE_DIRECTORY, 'fluxdrop_pp', 'icon.svg')
    icon_cid = 'fluxdrop_icon'
    icon_data = None  # will hold transparent PNG bytes if conversion succeeds
    try:
        from wand.image import Image as WandImage
        from wand.color import Color
        with WandImage(filename=icon_path, resolution=192) as img:
            img.background_color = Color('transparent')
            img.alpha_channel = 'set'
            img.format = 'png'
            img.trim()           # remove any whitespace border
            img.resize(64, 64)   # small — same height as the title text
            icon_data = img.make_blob()
    except Exception as _e:
        logging.warning(f"Could not rasterise icon.svg to PNG for email: {_e}")

    if icon_data:
        # Inline next to title, same height — mirrors the site header
        icon_img = f'<img src="cid:{icon_cid}" alt="" width="32" height="32" style="vertical-align:middle;margin-right:6px;display:inline-block">'
    else:
        icon_img = ''

    html_body = _render_snippet('email_verification.html',
        icon_img=icon_img,
        username=username,
        verification_link=verification_link,
    )

    # Build a multipart/related message so the icon CID attachment is recognised
    msg = MIMEMultipart('related')
    msg['Subject'] = subject
    msg['From'] = SMTP_SENDER_EMAIL
    msg['To'] = email

    # Wrap HTML in multipart/alternative (text fallback + HTML)
    alt = MIMEMultipart('alternative')
    alt.attach(MIMEText(
        f"Hello {username},\n\nVerify your FluxDrop account: {verification_link}\n\nThis link expires in 1 hour.",
        'plain'
    ))
    alt.attach(MIMEText(html_body, 'html'))
    msg.attach(alt)

    # Attach the icon inline — Content-Disposition must be inline (not attachment)
    # and X-Attachment-Id must match the CID so Gmail does not show it as a file.
    if icon_data:
        img_part = MIMEImage(icon_data, _subtype='png')
        img_part.add_header('Content-ID', f'<{icon_cid}>')
        img_part.add_header('Content-Disposition', 'inline', filename='icon.png')
        img_part.add_header('X-Attachment-Id', icon_cid)
        msg.attach(img_part)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            # ensure connection established
            server.ehlo()
            if SMTP_PORT == 587:
                server.starttls()
                server.ehlo()
            server.login(SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD)
            server.sendmail(SMTP_SENDER_EMAIL, [email], msg.as_string())
        logging.info(f"Verification email sent to {email}")
        return True
    except Exception:
        # don't let SMTP errors interrupt registration flow; log and simulate
        logging.exception(f"Failed to send verification email to {email}, falling back to simulation")
        logging.info(f"EMAIL SIMULATION: Verification link for {email}: {verification_link}")
        return True
    
# ==============================================================================
# --- DOWNLOAD TOKEN HELPERS ---
# Download tokens are short-lived (default 60 s), file-scoped, and single-use.
# A valid session token alone is NOT sufficient to download a file via HTTP GET;
# the client must call POST /api/v1/download_token with a valid session and the
# target file path to mint a fresh download token, then pass it as ?dl_token=
# within the TTL window.  This ensures session tokens never appear in server
# logs or browser history.
# ==============================================================================
# Tokens are valid for 1 hour so interrupted downloads can resume within that window.
DOWNLOAD_TOKEN_TTL_SECONDS = int(os.getenv("DOWNLOAD_TOKEN_TTL", "3600"))


def _mint_download_token(relative_path: str, user_id: int) -> str:
    """Create and store a resumable download token for *relative_path*.

    The token is valid for DOWNLOAD_TOKEN_TTL_SECONDS (default 1 h).  The same
    token may be reused with HTTP Range requests to resume an interrupted
    download — there is no single-use restriction.  Tokens expire after the TTL
    and are purged by the background worker.
    Returns the raw (unhashed) token string the client should use.
    """
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    expires_at = datetime.now() + timedelta(seconds=DOWNLOAD_TOKEN_TTL_SECONDS)
    with _db_connect() as conn:
        conn.execute(
            "INSERT INTO download_tokens (token_hash, relative_path, user_id, expires_at, bytes_confirmed) VALUES (?, ?, ?, ?, 0)",
            (token_hash, relative_path, user_id, expires_at)
        )
        conn.commit()
    return raw


def _validate_download_token(relative_path: str, raw_token: str) -> dict | None:
    """Validate a download token without consuming it.

    Returns a dict with token metadata (including bytes_confirmed) if valid,
    or None if the token is invalid, expired, or does not match the path.
    This allows the same token to be reused for Range-based resume requests.
    """
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    with _db_connect() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, bytes_confirmed, user_id FROM download_tokens
               WHERE token_hash = ? AND relative_path = ? AND expires_at > CURRENT_TIMESTAMP""",
            (token_hash, relative_path)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {"id": row[0], "bytes_confirmed": row[1], "user_id": row[2]}


def _update_token_progress(token_id: int, bytes_confirmed: int):
    """Update the bytes_confirmed counter for a download token.

    Called after each successful chunk so that if the connection drops the
    client (and server) both know the safe resume offset.
    """
    try:
        with _db_connect() as conn:
            conn.execute(
                "UPDATE download_tokens SET bytes_confirmed = ? WHERE id = ?",
                (bytes_confirmed, token_id)
            )
            conn.commit()
    except Exception:
        logging.exception("Failed to update download token progress")


def _purge_expired_download_tokens():
    """Remove expired download tokens. Call periodically to keep the table small.

    Returns True on success, False on failure (so the caller can back off).
    """
    try:
        with _db_connect() as conn:
            conn.execute(
                "DELETE FROM download_tokens WHERE expires_at <= CURRENT_TIMESTAMP"
            )
            conn.commit()
        return True
    except Exception:
        logging.exception("Failed to purge expired download tokens")
        return False

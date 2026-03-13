# FluxDrop — Security Audit v2
*Covers: `server_cdn.py`, `server_http.py`, `server_https.py`, `shared.py`, `config.py`*
*Updated after full code review — supersedes audit v1*

---

## Summary of changes since v1

Most of the original critical issues have been fixed. The table below tracks every
item from v1 and lists new findings discovered in this review.

| # | Issue | v1 | Current |
|---|-------|----|---------|
| 1 | Rate limiting on `/auth/login` + `/auth/register` | 🔴 Missing | ✅ Fixed |
| 2 | Upload size cap | 🔴 Missing | ✅ Fixed |
| 3 | JSON body size cap | 🔴 Missing | ✅ Fixed |
| 4 | IP blacklist not enforced in `server_cdn.py` | 🟡 Missing | ✅ Fixed |
| 5 | Session table cleanup | 🟡 Missing | ✅ Fixed |
| 6 | Passwords use SHA-256, not bcrypt | 🟡 Open | 🟡 Still open |
| 7 | `localhost` in `ALLOWED_ORIGINS` | 🟢 Low | 🟢 Still present |
| 8 | Missing `X-Content-Type-Options` / `X-Frame-Options` | 🟢 Low | ✅ Fixed |
| N1 | Blacklist never refreshed in `server_cdn.py` | — | 🔴 **New** |
| N2 | `do_PATCH` / `do_DELETE` / `do_OPTIONS` skip blacklist | — | 🟡 **New** |
| N3 | Failed token logged in full | — | 🟡 **New** |
| N4 | Password comparison not timing-safe | — | 🟡 **New** |
| N5 | `pending_verifications` never bulk-purged | — | 🟡 **New** |
| N6 | `net_outages` / `incident_log` grow unbounded | — | 🟡 **New** |
| N7 | `server_https.py` crash bug: `http.server.quote_plus` | — | 🔴 **New (bug)** |
| N8 | `server_https.py` upload form is a `...existing code...` stub | — | 🔴 **New (bug)** |
| N9 | `os.chdir()` in per-request handler `__init__` (race) | — | 🟡 **New** |
| N10 | Health-check HTTPS ping uses private `_create_unverified_context` | — | 🟢 **New** |
| N11 | `captcha_challenges` dict grows unbounded | — | 🟢 **New** |
| N12 | No input length validation on registration fields | — | 🟡 **New** |

---

## Part 1 — Items from v1

### ✅ 1–5, 8 — Fixed

- **Rate limiting**: `_rate_limit()` enforces `_RL_MAX_AUTH = 10/min` on login and register,
  and `_RL_MAX_API = 30/min` on all sensitive admin endpoints.
- **Upload size cap**: chunked uploads enforce `content_length > UPLOAD_CHUNK_SIZE * 2` per
  chunk; the legacy `handle_fluxdrop_api_post` has a streaming byte counter against
  `MAX_UPLOAD_BYTES` (default 10 GB, env-overridable).
- **JSON body cap**: `MAX_JSON_BODY = 1 MB` is checked before every `rfile.read()` on POST
  handlers.
- **Blacklist in `server_cdn.py`**: `do_GET` and `do_POST` both check `current_blacklist` at
  entry. (Note N2: `do_PATCH`, `do_DELETE`, `do_OPTIONS` still missing the check.)
- **Session cleanup**: `DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP` runs on
  every successful login.
- **Security headers**: `X-Content-Type-Options: nosniff` and `X-Frame-Options: SAMEORIGIN`
  sent from `_send_response`.

---

### 🟡 6 — bcrypt migration (still open)

SHA-256 + random salt is not a key-derivation function. It is fast by design — a GPU can
test billions of SHA-256 hashes per second. `bcrypt>=4.1.0` is already commented out in
`requirements.txt`; the migration just hasn't been done yet.

**Fix — `server_cdn.py`:**

```python
import bcrypt

def hash_password(password: str, salt=None):
    # salt param kept for API compatibility; bcrypt embeds its own salt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    return hashed.decode(), ''

def verify_password(password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash.encode())
```

**Transparent migration** — detect old hashes by checking whether the stored hash starts
with `$2b$`. If not, verify with SHA-256, then immediately re-hash with bcrypt and update
the DB row. All active users migrate on their next login with no manual intervention:

```python
# In handle_auth_login, replace the comparison block:
if stored_hash.startswith('$2b$'):
    if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
        return self._send_response(401, ...)
else:
    # Legacy SHA-256 path
    legacy_hash, _ = _sha256_hash(password, salt)
    if not secrets.compare_digest(legacy_hash, stored_hash):
        return self._send_response(401, ...)
    # Upgrade in place
    new_hash, _ = hash_password(password)
    conn.execute('UPDATE users SET password_hash=?, salt=? WHERE id=?',
                 (new_hash, '', user_id))
    conn.commit()
```

---

### 🟢 7 — `localhost` in `ALLOWED_ORIGINS` (still present)

Any page served from `localhost` on a visitor's own machine can make credentialed
cross-origin requests to your server. Low risk for a home server; remove before any
public deployment.

---

## Part 2 — New findings

### 🔴 N1 — `server_cdn.py` blacklist is never refreshed

`server_http.py` and `server_https.py` both start a background `update_blacklist` thread
that re-reads the blacklist file from disk every 60 seconds. `server_cdn.py` imports
`current_blacklist` at startup and checks it correctly in `do_GET` and `do_POST`, but the
set is never updated. Adding an IP to the blacklist file while the CDN is running has
**no effect on CDN traffic** until the process is restarted.

**Fix — add to the `if __name__ == '__main__'` block in `server_cdn.py`:**

```python
from shared import load_blacklist_safely, update_blacklist, stop_update_event
from config import BLACKLIST_FILE

# after init_db():
load_blacklist_safely(BLACKLIST_FILE)
_bl_thread = threading.Thread(
    target=update_blacklist,
    args=(BLACKLIST_FILE, 60, stop_update_event),
    name='BlacklistRefresh',
    daemon=True
)
_bl_thread.start()
```

---

### 🟡 N2 — `do_PATCH`, `do_DELETE`, `do_OPTIONS` skip the blacklist check

`do_GET` and `do_POST` both open with a blacklist guard. The other three HTTP methods do
not. A blocked IP can still reach:

- `PATCH /api/v1/shares/<token>` — update share settings
- `DELETE /api/v1/shares/<token>`, `DELETE /api/v1/board/<id>` — deletions
- `OPTIONS *` — CORS preflight

**Fix — add to the top of each method in `server_cdn.py`:**

```python
def do_PATCH(self):
    with blacklist_lock:
        if self.client_address[0] in current_blacklist:
            return self._send_response(403, json.dumps({'error': 'Forbidden'}))
    # ... rest of method

def do_DELETE(self):
    with blacklist_lock:
        if self.client_address[0] in current_blacklist:
            return self._send_response(403, json.dumps({'error': 'Forbidden'}))
    # ...

def do_OPTIONS(self):
    with blacklist_lock:
        if self.client_address[0] in current_blacklist:
            return self._send_response(403, json.dumps({'error': 'Forbidden'}))
    # ...
```

---

### 🟡 N3 — Failed session token logged in full

```python
# server_cdn.py _check_token_auth():
logging.warning(f"Token auth failed for token '{token}'")
```

A full 43-character `secrets.token_urlsafe(32)` token written to a log file is a
credential in the clear. If the log is ever readable by another process or shipped to an
aggregator, a stolen token could be extracted and replayed. The rest of the codebase
already truncates tokens to 12 characters in log lines (upload session tokens do this
correctly). This one does not.

**Fix:**

```python
logging.warning(f"Token auth failed for token '{token[:8]}…'")
```

---

### 🟡 N4 — Password comparison uses `!=` (timing side-channel)

```python
# server_cdn.py handle_auth_login():
if password_hash != stored_hash:
```

Python's `!=` on strings short-circuits on the first differing byte, leaking timing
information. With many probes this can help an attacker narrow down hash prefixes.
`secrets.compare_digest` exists exactly for this.

**Fix:**

```python
if not secrets.compare_digest(password_hash, stored_hash):
```

Note: once bcrypt migration (item 6) is done, this comparison disappears entirely since
`bcrypt.checkpw` is already timing-safe. Fix it now to be safe during the transition.

---

### 🟡 N5 — `pending_verifications` table grows without a global purge

Expired pending verification rows are only cleaned up when someone tries to re-register
with the exact same username/email/nickname. A bot POSTing to `/auth/register` with random
throwaway addresses fills the table indefinitely. At scale this slows down the uniqueness
`SELECT` checks that run on every registration attempt.

**Fix — add to the `_token_purge_worker` loop:**

```python
with _db_connect() as conn:
    conn.execute(
        "DELETE FROM pending_verifications WHERE expires_at <= CURRENT_TIMESTAMP"
    )
    conn.commit()
```

---

### 🟡 N6 — `net_outages` and `incident_log` grow unbounded

`status_snapshots` is correctly pruned to 90 days. `net_outages` and `incident_log` are
never pruned — every outage and incident ever recorded stays in the DB. For a server
running for years this means the queries in `_get_net_outages()` and the incident section
of `_handle_status_json` get progressively slower.

**Fix — add to the periodic purge worker:**

```python
with _db_connect() as conn:
    conn.execute(
        "DELETE FROM net_outages WHERE started_at < unixepoch('now', '-180 days')"
    )
    conn.execute(
        "DELETE FROM incident_log WHERE started_at < datetime('now', '-180 days')"
    )
    conn.commit()
```

Adjust the 180-day window to taste. The message board doesn't need pruning since posts
are deleted manually via the admin panel.

---

### 🔴 N7 — `server_https.py` crash: `http.server.quote_plus` does not exist

```python
# server_https.py _redirect_with_message():
encoded_message = http.server.quote_plus(message)
```

`http.server` has no `quote_plus` attribute. This raises `AttributeError` on every
upload completion or failure, crashing the HTTPS handler thread for that request. The
correct location is `urllib.parse`.

**Fix:**

```python
# Add to imports at the top of server_https.py:
from urllib.parse import quote_plus

# Replace the call:
encoded_message = quote_plus(message)
```

---

### 🔴 N8 — `server_https.py` upload form is a literal placeholder stub

```python
# server_https.py do_GET():
upload_form_html = f"""
<!DOCTYPE html>
<html lang="en">
...existing code...
</html>
"""
self.wfile.write(upload_form_html.encode('utf-8'))
```

`GET /upload` on the HTTPS server returns a page containing the literal text
`...existing code...`. This is an editing artifact where the HTML body was never
restored. Any visitor navigating to `/upload` gets a broken page.

Either restore the real HTML form, or — since the FluxDrop CDN now handles all uploads —
remove the `/upload` route from `server_https.py` and return 404.

---

### 🟡 N9 — `os.chdir()` in per-request handler `__init__` causes a thread race

```python
# server_http.py and server_https.py RequestHandler.__init__:
os.chdir(SERVE_DIRECTORY)
```

`os.chdir()` changes the **process-wide** working directory. Both servers use
`ThreadingHTTPServer`, handling concurrent requests in separate threads — but all threads
share one working directory. Two simultaneous requests calling `os.chdir()` can race,
causing one to serve files from an unexpected path or fail to locate a file entirely.

`server_cdn.py`'s `AuthHandler` already does this correctly by passing
`directory=SERVE_ROOT` to `super().__init__()`. Apply the same pattern:

**Fix for both `server_http.py` and `server_https.py`:**

```python
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Pass directory to parent constructor — thread-safe, never use os.chdir()
        super().__init__(*args, directory=SERVE_DIRECTORY, **kwargs)
```

Remove the `os.chdir()` call entirely.

---

### 🟢 N10 — Health-check uses `ssl._create_unverified_context()` (private API)

```python
# shared.py health_check_self_ping_https():
ctx = ssl._create_unverified_context()
```

Skipping TLS verification for a self-ping on a server with a self-signed cert is
reasonable. However, the leading underscore indicates a private, unsupported API that
could be removed or changed in a future Python release. The public equivalent is:

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```

---

### 🟢 N11 — `captcha_challenges` dict in `server_https.py` grows without eviction

```python
captcha_challenges = {}   # inserted on GET /upload, popped on POST verify
```

If a user loads the upload form but never submits (e.g. abandons the tab), the UUID +
answer pair stays in memory forever. Each entry is tiny but on a server that runs for
months without a restart it accumulates.

**Fix — add TTL-based eviction:**

```python
import time as _time
CAPTCHA_TTL = 600  # 10 minutes

def generate_captcha():
    # ... existing logic to compute question / answer ...
    captcha_id = str(uuid.uuid4())
    now = _time.monotonic()
    with captcha_lock:
        # Evict stale entries while holding the lock
        stale = [k for k, (_, ts) in captcha_challenges.items()
                 if now - ts > CAPTCHA_TTL]
        for k in stale:
            del captcha_challenges[k]
        captcha_challenges[captcha_id] = (answer, now)
    return captcha_id, question

def verify_captcha(captcha_id, user_answer):
    with captcha_lock:
        entry = captcha_challenges.pop(captcha_id, None)
    if entry is None:
        return False
    answer, ts = entry
    if _time.monotonic() - ts > CAPTCHA_TTL:
        return False   # expired after TTL
    return user_answer.strip() == answer
```

---

### 🟡 N12 — No input length validation on registration fields

`handle_auth_register` accepts any length for `username`, `nickname`, `email`, and
`password`. The 1 MB JSON body cap guards the whole request, but a single field can
still be hundreds of kilobytes, wasting CPU on SHA-256 (or eventually bcrypt, which
silently truncates input beyond 72 bytes).

**Fix — add after extracting fields in `handle_auth_register`:**

```python
MAX_USERNAME_LEN = 64
MAX_NICKNAME_LEN = 64
MAX_EMAIL_LEN    = 254   # RFC 5321 maximum
MAX_PASSWORD_LEN = 1024  # bcrypt only uses first 72 bytes; cap well above that

if (len(username or '') > MAX_USERNAME_LEN or
    len(nickname or '') > MAX_NICKNAME_LEN or
    len(email    or '') > MAX_EMAIL_LEN    or
    len(password or '') > MAX_PASSWORD_LEN):
    return self._send_response(
        400, json.dumps({'error': 'One or more fields exceed the maximum allowed length.'})
    )

# Optional: restrict username to safe characters
import re as _re
if not _re.match(r'^[A-Za-z0-9_\-\.]{3,64}$', username):
    return self._send_response(
        400, json.dumps({'error': 'Username must be 3–64 characters: letters, digits, _ - .'})
    )
```

---

## Part 3 — Things still done well

Carried forward from v1 — these remain correct:

- **No RCE vectors** — no `eval`, `exec`, `os.system`, `subprocess` on user input, or `pickle`.
- **Parameterised SQL throughout** — all queries use `?` placeholders; no SQL injection risk.
- **Path traversal defended consistently** — every file operation checks `os.path.realpath(path).startswith(allowed_root)`.
- **`/FluxDrop/` hard-blocked** — direct URL access to user storage returns 403.
- **Session tokens use `secrets.token_urlsafe(32)`** — 256 bits of entropy.
- **Cross-user access checked** — API verifies `target_user == authenticated_user_id` before allowing access.
- **CORS origins whitelisted** — only your own domains get `Allow-Credentials: true`.
- **Timing-safe device token comparison** — `secrets.compare_digest` used for anonymous upload device tokens.
- **Admin privilege check** — `is_admin` DB column, verified server-side on every admin endpoint via `_check_admin_auth()`.
- **Chunked upload integrity** — per-chunk and whole-file SHA-256 verification with abort + cleanup on mismatch.
- **Download tokens** — short-lived per-file tokens separate from session tokens; session token never exposed in download URLs.
- **Share access log** — all share views recorded to `share_access_log`.
- **WAL journal mode** — `PRAGMA journal_mode=WAL` with 15 s lock timeout on every DB connection.
- **Opportunistic download-token purge** — `_purge_expired_download_tokens()` called on every download and in a background worker every 5 minutes.

---

## Priority order for remaining work

| Priority | Item | Effort |
|----------|------|--------|
| 🔴 1 | **N7** — Fix `http.server.quote_plus` crash in `server_https.py` | 2 lines |
| 🔴 2 | **N8** — Fix/remove `...existing code...` stub in upload form | Minutes |
| 🔴 3 | **N1** — Start blacklist refresh thread in `server_cdn.py` | ~10 lines |
| 🟡 4 | **N2** — Add blacklist check to `do_PATCH` / `do_DELETE` / `do_OPTIONS` | ~12 lines |
| 🟡 5 | **N4** — Use `secrets.compare_digest` for password comparison | 1 line |
| 🟡 6 | **N3** — Truncate token in failed-auth log line | 1 line |
| 🟡 7 | **N9** — Fix `os.chdir()` race in `server_http.py` / `server_https.py` | ~4 lines |
| 🟡 8 | **N12** — Add input length validation on registration | ~10 lines |
| 🟡 9 | **N5** — Add `pending_verifications` periodic purge | 3 lines |
| 🟡 10 | **N6** — Add `net_outages` / `incident_log` periodic pruning | 4 lines |
| 🟡 11 | **6** — Migrate passwords from SHA-256 to bcrypt | Medium |
| 🟢 12 | **N11** — Add TTL eviction to `captcha_challenges` | ~15 lines |
| 🟢 13 | **N10** — Replace `ssl._create_unverified_context()` with public API | 2 lines |
| 🟢 14 | **7** — Remove `localhost` from `ALLOWED_ORIGINS` | 1 line |

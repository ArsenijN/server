# FluxDrop — Security & Code Audit v4
*Covers: `server_cdn.py` (post-v3 patch), `script.js`, `config.py`, `shared.py`*
*Supersedes audit v3. All v3 items are resolved unless explicitly carried forward.*

---

## Summary table

| # | Issue | Severity | File(s) |
|---|-------|----------|---------|
| **B1** | Plain-text password transmitted over HTTP (answered in full below) | 🔴 Critical* | `script.js`, `server_cdn.py` |
| **B2** | Session tokens stored plain-text in the `sessions` DB table | 🟠 High | `server_cdn.py` |
| **B3** | `bcrypt` silently truncates passwords longer than 72 bytes | 🟡 Medium | `server_cdn.py` |
| **B4** | No rate limit on `PATCH /api/v1/me/password` | 🟡 Medium | `server_cdn.py` |
| **B5** | Missing size cap on `PATCH /api/v1/me/password` JSON body | 🟡 Medium | `server_cdn.py` |
| **B6** | No username/password length cap at login (bcrypt DoS) | 🟡 Medium | `server_cdn.py` |
| **B7** | HTTP server accepts auth requests — no redirect to HTTPS | 🟡 Medium | `server_cdn.py` |
| **B8** | Missing `Strict-Transport-Security` (HSTS) header | 🟡 Medium | `server_cdn.py` |
| **B9** | Missing `Content-Security-Policy` header | 🟡 Medium | `server_cdn.py` |
| **B10** | `X-Frame-Options` only on API responses, not on HTML pages | 🟢 Low | `server_cdn.py` |
| **B11** | `UPLOAD_TMP_DIR` default path is inside `SERVE_ROOT` — chunks exposed if `.upload_sessions` somehow gets served | 🟢 Low | `server_cdn.py` |
| **B12** | `A7` carry-forward — fragile DownDetector HTML scrape still present | 🟢 Low | `server_cdn.py` |

*\* Whether B1 is a real risk depends on your deployment — see the detailed section below.*

---

## Part 1 — Resolved items from v3

All 8 v3 items applied in the previous patch are confirmed in the current code:

- **A1** `_rl_attempts` empty-bucket eviction ✅
- **A2** `share_access_log` 90-day pruning ✅
- **A4** `handle_upload_session_init` JSON body size cap ✅
- **A5** `handle_public_share_upload` 500 MB per-file limit ✅
- **A6** Token-auth success log demoted to DEBUG ✅
- **A8** SHA-256 recomputed from assembled file — already fixed before v3 ✅
- **A9** `repr()` replaced with `json.dumps()` in inline JS ✅
- **A10** `message_board` 100-row pruning ✅

---

## Part 2 — Plain-text passwords (TODO item `!!!`)

This is the item marked `(!!!)` in your TODO. Here is the complete picture.

### What actually happens today

1. The browser sends `POST /auth/login` (or `/auth/register`) with a JSON body:
   ```json
   { "username": "alice", "password": "hunter2" }
   ```
2. The server receives the plain-text password and immediately hashes it with bcrypt (rounds=12). The plain-text value is never written to disk.

**The password is not encrypted or hashed before leaving the browser.** It travels as plain text inside the HTTP/HTTPS body.

### Is this a problem right now?

It depends entirely on the transport layer:

| Scenario | Risk |
|----------|------|
| Request goes over **HTTPS** (port 64800) | ✅ Safe — TLS encrypts the body end-to-end |
| Request goes over **HTTP** (port 63512) | ⚠️ Password visible to anyone on the network path |
| User opens the app over HTTP | The page loads over HTTP, so `API_BASE_URL` is set to the HTTP port, and credentials are sent unencrypted |

The `script.js` already guards correctly: it only falls back to HTTP when the *page itself* was loaded over HTTP. But because both HTTP and HTTPS ports serve the full app (including `/auth/login`), a user who arrives via the HTTP URL sends their password in the clear.

### The real fix: redirect HTTP → HTTPS at the server

The standard solution is **not** to hash passwords in the browser (that has its own problems — the hash becomes the password). The standard solution is to ensure credentials are never sent over HTTP in the first place:

```python
# In do_GET / do_POST on the HTTP server, redirect auth endpoints to HTTPS:
AUTH_PATHS = {'/auth/login', '/auth/register', '/auth/logout'}
if parsed_url.path in AUTH_PATHS:
    https_url = f"https://{self.headers.get('Host', PUBLIC_DOMAIN).split(':')[0]}:{HTTPS_PORT}{self.path}"
    self.send_response(308)  # 308 = Permanent Redirect, preserves POST method
    self.send_header('Location', https_url)
    self.end_headers()
    return
```

This is addressed as **B7** below with a broader solution.

### Why client-side hashing is not the answer

Hashing before sending would make the hash itself the credential. An attacker who steals the DB can log in by replaying the hash without knowing the original password — the same threat you're trying to prevent. It also breaks "show password strength" UX and complicates the bcrypt migration path. **TLS is the correct layer for this.**

---

## Part 3 — New findings

---

### 🟠 B2 — Session tokens stored plain-text in the database

```python
# server_cdn.py ~line 3907
cursor.execute(
    "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
    (user_id, session_token, expires_at)
)
```

And looked up verbatim:
```python
cursor.execute(
    "SELECT user_id FROM sessions WHERE session_token = ? AND ...",
    (token,)
)
```

If the SQLite DB file is ever read by an attacker (backup leak, misconfigured path, local access), every active session for every user is immediately usable. Download tokens already use SHA-256 storage (`token_hash`). Sessions should too.

**Fix — store and look up sessions by hash:**

```python
import hashlib

def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

# On login — store hash only:
session_token = secrets.token_urlsafe(32)
token_hash    = _hash_token(session_token)
cursor.execute(
    "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
    (user_id, token_hash, expires_at)
)
# Return raw token to client as before.

# In _check_token_auth — hash before lookup:
token_hash = _hash_token(token)
cursor.execute(
    "SELECT user_id FROM sessions WHERE session_token = ? AND expires_at > CURRENT_TIMESTAMP",
    (token_hash,)
)
```

The column is already `UNIQUE`, so no schema change is needed — only the two call sites above, and the logout handler.

---

### 🟡 B3 — bcrypt silently truncates passwords longer than 72 bytes

```python
# server_cdn.py line 1723
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
```

bcrypt only uses the first 72 bytes of its input. A password whose first 72 bytes are identical to another password will produce the same hash. Since `_MAX_PASSWORD = 1024`, users can set passwords longer than 72 bytes and believe them to be unique when they are not.

For most users this is theoretical, but it is a correctness bug, and the comment on line 3773 ("bcrypt only uses first 72 bytes; cap well above that") shows awareness without providing an actual fix.

**Fix — pre-hash with SHA-256 before passing to bcrypt, which is the standard pattern for long-password support:**

```python
import base64

def _prepare_password(password: str) -> bytes:
    """SHA-256 + base64 pre-hash so bcrypt sees exactly 44 bytes, safely under the 72-byte limit."""
    digest = hashlib.sha256(password.encode('utf-8')).digest()
    return base64.b64encode(digest)  # 44 bytes, never truncated

def hash_password(password: str, salt=None) -> tuple[str, str]:
    hashed = bcrypt.hashpw(_prepare_password(password), bcrypt.gensalt(rounds=12))
    return hashed.decode('utf-8'), ''

# All three bcrypt.checkpw call sites:
ok = bcrypt.checkpw(_prepare_password(password), stored_hash.encode('utf-8'))
```

This also lets you drop `_MAX_PASSWORD = 1024` entirely — the pre-hash makes any length safe.

---

### 🟡 B4 — No rate limit on `PATCH /api/v1/me/password`

The login endpoint is rate-limited. The password-change endpoint is not. An attacker who steals a session token (e.g. from `localStorage` via XSS) can brute-force `current_password` at full CPU speed — the only limit is bcrypt's own cost.

**Fix — add a rate limit at the top of the handler, using the `"auth"` bucket:**

```python
if parsed_url.path == '/api/v1/me/password':
    client_ip = self.client_address[0]
    if not _rate_limit(client_ip, "auth"):
        return self._send_response(429, json.dumps({'error': 'Too many attempts. Please wait.'}))
    user_id = self._check_token_auth()
    ...
```

---

### 🟡 B5 — Missing JSON body size cap on `PATCH /api/v1/me/password`

```python
length = int(self.headers.get('Content-Length', 0))
data = json.loads(self.rfile.read(length))
```

Same pattern fixed in A4 (`handle_upload_session_init`), but missed here.

**Fix — add the standard guard:**

```python
length = int(self.headers.get('Content-Length', 0))
if length <= 0 or length > MAX_JSON_BODY:
    return self._send_response(400, json.dumps({'error': 'Invalid or missing request body.'}))
data = json.loads(self.rfile.read(length))
```

---

### 🟡 B6 — No username/password length cap at login (bcrypt DoS vector)

Registration enforces `_MAX_PASSWORD = 1024` and `_MAX_USERNAME = 64`. Login does not:

```python
# handle_auth_login
username = data.get('username')
password = data.get('password')
if not all([username, password]):
    ...
# ← no length check before the DB query and bcrypt call
```

Sending a 10 MB `password` field causes the server to attempt `bcrypt.checkpw` on a 10 MB string. Even though bcrypt truncates at 72 bytes, the Python `encode('utf-8')` call allocates the full string. Under the default `_RL_MAX_AUTH = 10` rate limit, an attacker gets 10 × 10 MB allocations per IP per minute — trivially bypassed with multiple IPs.

**Fix — mirror the registration caps at the top of `handle_auth_login`:**

```python
_MAX_USERNAME_LOGIN = 64
_MAX_PASSWORD_LOGIN = 1024
if len(username) > _MAX_USERNAME_LOGIN or len(password) > _MAX_PASSWORD_LOGIN:
    return self._send_response(401, json.dumps({'error': 'Invalid credentials.'}))
    # Return 401 (not 400) to avoid leaking that the length was the problem
```

---

### 🟡 B7 — HTTP server accepts auth requests with no redirect to HTTPS

Both HTTP (port 63512) and HTTPS (port 64800) run the same `AuthHandler`, which accepts `/auth/login`, `/auth/register`, and all API endpoints. If a user opens the app over HTTP, credentials are sent in the clear.

The `fetchWithFallback` in `script.js` correctly avoids the HTTP fallback when the *page* is on HTTPS, but it does nothing to prevent a user who arrives via HTTP.

**Fix — redirect auth and sensitive API paths from HTTP to HTTPS. Add this near the top of `do_POST` (and `do_PATCH`, `do_DELETE`) before any other processing:**

```python
HTTPS_ONLY_PREFIXES = ('/auth/', '/api/')

def _redirect_to_https_if_needed(self) -> bool:
    """If serving over plain HTTP and the path is sensitive, 308-redirect to HTTPS.
    Returns True if a redirect was sent (caller should return immediately)."""
    if not isinstance(self.server.socket, ssl.SSLSocket):
        parsed = urlparse(self.path)
        if any(parsed.path.startswith(p) for p in HTTPS_ONLY_PREFIXES):
            host = self.headers.get('Host', PUBLIC_DOMAIN).split(':')[0]
            location = f"https://{host}:{HTTPS_PORT}{self.path}"
            self.send_response(308)
            self.send_header('Location', location)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return True
    return False

# Call at the top of do_POST, do_PATCH, do_DELETE:
if self._redirect_to_https_if_needed():
    return
```

`308 Permanent Redirect` is used because it preserves the HTTP method (POST stays POST), which `301` does not.

---

### 🟡 B8 — Missing `Strict-Transport-Security` (HSTS) header

The HTTPS server never sends `Strict-Transport-Security`. Without it, browsers will not automatically upgrade future HTTP requests to HTTPS, and MITM downgrades remain possible.

**Fix — add to `_send_response` when the socket is TLS:**

```python
# In _send_response, after X-Frame-Options:
if isinstance(self.server.socket, ssl.SSLSocket):
    self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
```

Start with `max-age=300` (5 minutes) during testing so you can roll back if something breaks, then increase to `31536000` (1 year) once stable.

---

### 🟡 B9 — Missing `Content-Security-Policy` header

No `Content-Security-Policy` header is ever sent for HTML pages. This leaves the app open to XSS escalation — if an attacker can inject a script (e.g. via a crafted filename rendered in the file table), there is no browser-side barrier to exfiltrating `localStorage` tokens.

**Suggested starter policy** (tighten over time):

```python
# In _send_response, for HTML content types only:
if content_type.startswith('text/html'):
    self.send_header(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
```

Note: `'unsafe-inline'` is needed because the app currently uses inline `<script>` and `<style>` blocks in the share HTML pages. Eliminating those (moving to external files) would eventually let you remove `'unsafe-inline'` for a much stronger policy.

---

### 🟢 B10 — `X-Frame-Options` only on API (`_send_response`), not on static HTML

`X-Frame-Options: SAMEORIGIN` is correctly set in `_send_response`, but static HTML files (index.html, share pages, offline.html) are served via `SimpleHTTPRequestHandler.send_head()` which does **not** call `_send_response`. Those HTML pages can currently be iframed by third-party sites.

**Fix — override `send_head` to inject the header before delegating:**

```python
def send_head(self):
    result = self._guarded_send_head()
    if result is not None:
        # send_head has already written headers via SimpleHTTPRequestHandler internals;
        # inject security headers after end_headers would be too late.
        # Instead, override end_headers (see below).
    return result
```

The cleaner approach is to override `end_headers`:

```python
def end_headers(self):
    self.send_header('X-Frame-Options', 'SAMEORIGIN')
    self.send_header('X-Content-Type-Options', 'nosniff')
    if isinstance(self.server.socket, ssl.SSLSocket):
        self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    super().end_headers()
```

This fires for *every* response (both API and static), so you can remove the duplicate headers from `_send_response`.

---

### 🟢 B11 — `UPLOAD_TMP_DIR` default is inside `SERVE_ROOT`

```python
UPLOAD_TMP_DIR = os.getenv('UPLOAD_TMP_DIR', os.path.join(
    '/media/arsen/...', '.upload_sessions'
))
```

The default path is `/media/arsen/.../.upload_sessions` — a hidden directory directly inside the disk that is also `SERVE_ROOT`. The `/fluxdrop` block in `do_GET` does not cover `.upload_sessions`. If the dot-prefix were ever stripped or if the path were requested directly, raw chunk files would be served.

In the current code this is likely unexploitable because:
1. `SimpleHTTPRequestHandler` does serve dotfiles, but the directory name starts with `.`, which most OS path resolutions would keep hidden.
2. Chunk filenames are `000001.chunk` etc. — not guessable without knowing the upload token.

However, the safest fix is to move `UPLOAD_TMP_DIR` outside `SERVE_ROOT` entirely:

```python
UPLOAD_TMP_DIR = os.getenv('UPLOAD_TMP_DIR', '/tmp/fluxdrop_upload_sessions')
```

Or add an explicit 403 block:

```python
if norm_path.lower().startswith('/.upload_sessions'):
    self.send_response(403); ...; return None
```

---

## Priority order

| Priority | Item | Effort |
|----------|------|--------|
| 🟠 1 | **B2** — Hash session tokens before DB storage | ~10 lines, 3 call sites |
| 🟡 2 | **B7** — Redirect HTTP auth/API to HTTPS | ~15 lines |
| 🟡 3 | **B8** — Add HSTS header on HTTPS responses | 2 lines (or 1 via `end_headers` override) |
| 🟡 4 | **B4** — Rate limit `PATCH /api/v1/me/password` | 3 lines |
| 🟡 5 | **B5** — Size cap on password-change JSON body | 3 lines |
| 🟡 6 | **B6** — Length cap on login username/password | 4 lines |
| 🟡 7 | **B3** — Pre-hash passwords before bcrypt (72-byte fix) | ~10 lines across hash + checkpw sites |
| 🟡 8 | **B9** — Add Content-Security-Policy header | 5 lines |
| 🟢 9 | **B10** — Override `end_headers` for universal security headers | ~8 lines, removes duplicates |
| 🟢 10 | **B11** — Move `UPLOAD_TMP_DIR` outside `SERVE_ROOT` | 1 line in config |
| 🟢 11 | **B12** — Remove DownDetector HTML scrape (carry-forward from A7) | Design decision |

---

## Things still done well

All positives from v3 remain valid. Additionally:

- `fetchWithFallback` correctly refuses the HTTP fallback when the page is loaded over HTTPS — mixed-content would be blocked by the browser anyway, but the explicit guard is good practice.
- Download tokens are SHA-256 hashed in the DB — session tokens should follow the same pattern (B2).
- `_check_token_for_file` uses `==` on SHA-256 strings — not timing-sensitive here since file-token hashes are not secret credentials, but consistent with the rest of the codebase.
- bcrypt rounds=12 is a solid cost factor for 2025 hardware.
- The `is_admin` flag is checked server-side on every admin endpoint — client-side `isAdmin` in `localStorage` is cosmetic only.
- No `eval`, no `exec`, no `subprocess` on user input anywhere in the codebase.

---

## On the TODO items

A few TODO entries have direct security relevance:

- **"Audit: question about expose of the temp chunks at CDN"** → This is B11 above.
- **"Add file info modal — background hashsums"** → When implemented, ensure the `nice`-based background process cannot be triggered to hash arbitrary paths outside the user's root (path traversal in the job queue).
- **"Add PDF / Markdown preview"** → When rendering user-uploaded content inline, the CSP from B9 becomes critical — these are common XSS vectors.
- **"i18n support"** → If locale strings are fetched from a server endpoint, ensure they are not injectable into HTML templates without escaping.
- **"Re-push chunk on server unresponsive"** → Safe to implement; the server already validates per-chunk SHA-256.

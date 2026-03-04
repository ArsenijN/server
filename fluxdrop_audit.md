# FluxDrop — Pre-release Security Audit & Modularisation Plan

---

## Part 1 — Security Audit

### ✅ Things that are already done well

- **No RCE vectors** — no `eval`, `exec`, `os.system`, `subprocess`, or `pickle` anywhere. Good.
- **Parameterised SQL throughout** — all DB queries use `?` placeholders, no string-interpolated SQL. No SQL injection risk.
- **Path traversal is consistently defended** — every file operation checks `os.path.realpath(path).startswith(allowed_root)` before proceeding. This is the correct pattern and it's applied on upload, download, delete, rename, and mkdir.
- **`/FluxDrop/` is hard-blocked** — direct URL access to user storage returns 403; files must go through the API. Good.
- **Session tokens use `secrets.token_urlsafe(32)`** — cryptographically strong, 256 bits of entropy.
- **Passwords use salted SHA-256** — not ideal (bcrypt/argon2 would be better), but far better than unsalted or plaintext.
- **Cross-user access is checked** — the API verifies `target_user == authenticated_user_id` before allowing access to another user's FluxDrop path.
- **CORS origins are whitelisted** — only your own domains echo back `Allow-Credentials: true`.

---

### 🔴 Critical issues (fix before going public)

#### 1. No rate limiting on auth endpoints
`/auth/login` and `/auth/register` have **zero** rate limiting. An attacker can make unlimited login attempts at full network speed. On an i3 370M your SHA-256 check is fast enough that a targeted brute-force against a known username is practical.

**Fix — add a simple in-memory tracker at the top of `server_cdn.py`:**

```python
import collections, time

_login_attempts: dict[str, list[float]] = collections.defaultdict(list)
_LOGIN_WINDOW   = 60    # seconds
_LOGIN_MAX      = 10    # attempts per window per IP

def _check_rate_limit(ip: str) -> bool:
    """Return True if the IP is allowed, False if it should be blocked."""
    now = time.monotonic()
    attempts = _login_attempts[ip]
    # Purge old entries
    _login_attempts[ip] = [t for t in attempts if now - t < _LOGIN_WINDOW]
    if len(_login_attempts[ip]) >= _LOGIN_MAX:
        return False
    _login_attempts[ip].append(now)
    return True
```

Then at the top of `handle_auth_login` and `handle_auth_register`:

```python
client_ip = self.client_address[0]
if not _check_rate_limit(client_ip):
    return self._send_response(429, json.dumps({"error": "Too many attempts. Try again later."}))
```

#### 2. No upload size limit
`handle_fluxdrop_api_post` streams the uploaded file to disk without any size check. A single client can fill your entire disk by uploading a huge file. The `/share` upload handler has the same issue.

**Fix — add a check right after parsing the Content-Length header:**

```python
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB, adjust to taste

content_length = int(self.headers.get('Content-Length', 0))
if content_length > MAX_UPLOAD_BYTES:
    return self._send_response(413, json.dumps({"error": "File too large."}))
```

Also add a running total inside the streaming write loop and abort if it exceeds the limit (guards against a lying Content-Length header):

```python
written = 0
with open(save_path, 'wb') as f:
    while True:
        chunk = file_item.stream.read(2 * 1024 * 1024)
        if not chunk:
            break
        written += len(chunk)
        if written > MAX_UPLOAD_BYTES:
            os.unlink(save_path)
            return self._send_response(413, json.dumps({"error": "File too large."}))
        f.write(chunk)
```

#### 3. JSON body size is unbounded
`self.rfile.read(content_len)` on lines 879, 1089, 1138, etc. trusts the client-supplied `Content-Length` unconditionally. A malicious client could send `Content-Length: 999999999` to exhaust RAM.

**Fix — cap it before reading:**

```python
MAX_JSON_BODY = 1 * 1024 * 1024  # 1 MB is generous for any JSON API call
content_len = int(self.headers.get('Content-Length', 0))
if content_len > MAX_JSON_BODY:
    return self._send_response(413, json.dumps({"error": "Request too large."}))
post_body = self.rfile.read(content_len)
```

---

### 🟡 Medium issues (should fix soon)

#### 4. Blacklist is not enforced in `server_cdn.py`
`server_http.py` and `server_https.py` both check `current_blacklist` at the start of every request handler. `server_cdn.py` imports nothing from `shared.py` and **never checks the blacklist at all**. Blocked IPs can still hit all FluxDrop/auth/CDN endpoints freely.

**Fix — import and check at the top of `do_GET` / `do_POST` in `AuthHandler`:**

```python
from shared import current_blacklist, blacklist_lock

# At start of do_GET and do_POST:
client_ip = self.client_address[0]
with blacklist_lock:
    if client_ip in current_blacklist:
        return self._send_response(403, json.dumps({"error": "Forbidden"}))
```

#### 5. Sessions are never cleaned up
Every login inserts a new row into `sessions`. Rows are checked for expiry on read but never deleted. After months of public use this table will have thousands of dead rows, and a user who logs in daily will accumulate 365+ rows per year. Add a periodic purge.

**Fix — one line in `handle_auth_login` after inserting the new session:**

```python
conn.execute("DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP")
```

#### 6. Passwords use SHA-256, not a proper KDF
SHA-256 is fast — that's bad for password storage. A modern GPU can compute billions of SHA-256 hashes per second. If your DB is ever leaked, passwords are crackable quickly.

**Fix — migrate to `bcrypt`:**

```python
import bcrypt

def hash_password(password: str):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    return hashed.decode(), ''   # bcrypt embeds the salt, second field unused

def verify_password(password: str, stored_hash: str, _salt: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash.encode())
```

Install: `sudo /opt/venvs/site_web/bin/pip install bcrypt`

Note: existing passwords will need to be re-hashed on next login (detect by length — bcrypt hashes start with `$2b$`).

#### 7. Verification page is a bare HTML string with no CSP
The `/auth/verify` success/failure responses return raw HTML with no `Content-Security-Policy` header. Not critical since they contain no user input, but worth adding for defence in depth.

---

### 🟢 Low / informational

#### 8. `localhost` is in ALLOWED_ORIGINS
This means any page served from `localhost` on a visitor's own machine can make credentialed cross-origin requests to your server. Low risk in practice, but worth removing from the production set.

#### 9. Session token is returned in the JSON login response (not a Set-Cookie)
This is fine for an API, but it means the token lives in `localStorage` in the browser, which is accessible to any JavaScript on the page (XSS risk). Since you control the frontend this is acceptable, but worth being aware of.

#### 10. No `X-Content-Type-Options` / `X-Frame-Options` headers
Worth adding to `_send_response` for HTML responses:
```python
self.send_header('X-Content-Type-Options', 'nosniff')
self.send_header('X-Frame-Options', 'SAMEORIGIN')
```

---

## Part 2 — HTML Modularisation

### Current state
`server_cdn.py` contains ~300 lines of inline HTML across 6 locations:

| Method | Description |
|---|---|
| `send_verification_email` | Email body HTML |
| `handle_auth_verify` | Verify success/fail pages |
| `_render_share_page` | Full public share browser page |
| `_render_share_expired_page` | Share expired error page |
| `_render_share_not_found_page` | Share not found error page |
| `handle_public_share_mkdir` / upload | Inline HTML fragments inside those handlers |

### Recommended structure

```
Web/
├── server_cdn.py
├── snippets/
│   ├── __init__.py          ← makes it a package
│   ├── share_page.html      ← _render_share_page template
│   ├── share_expired.html   ← _render_share_expired_page
│   ├── share_notfound.html  ← _render_share_not_found_page
│   ├── verify_ok.html       ← handle_auth_verify success
│   ├── verify_fail.html     ← handle_auth_verify failure
│   └── email_verify.html    ← send_verification_email body
└── snippets.py              ← loader module
```

### `snippets.py`

```python
import os, functools

_DIR = os.path.join(os.path.dirname(__file__), 'snippets')

@functools.lru_cache(maxsize=None)
def _load(name: str) -> str:
    with open(os.path.join(_DIR, name), encoding='utf-8') as f:
        return f.read()

def render(name: str, **kwargs) -> str:
    """Load a snippet by filename and substitute {key} placeholders."""
    return _load(name).format_map(kwargs)
```

`lru_cache` means each template is read from disk once and cached in memory for the life of the process — no overhead per-request.

### Usage in server_cdn.py

Replace, for example:
```python
# before
return self._send_response(200, self._render_share_page(...), "text/html")

# after
from snippets import render
html = render('share_page.html',
    title=share_title,
    rows=rows_html,
    upload_section=upload_section,
    ...
)
return self._send_response(200, html, "text/html")
```

### Caution with `str.format_map`
If any placeholder value itself contains `{` or `}` (e.g. user-supplied filenames, JavaScript code), it will break. Escape those values before passing them in:

```python
def _fmt_safe(s: str) -> str:
    return str(s).replace('{', '{{').replace('}', '}}')
```

Or switch to a minimal template engine like `string.Template` (uses `$var` syntax, immune to this issue) — it's in the stdlib, no install needed.

---

## Priority order for fixes

1. 🔴 Rate limiting on `/auth/login` and `/auth/register`
2. 🔴 Upload size limits (both FluxDrop API and public share)
3. 🔴 JSON body size cap
4. 🟡 Blacklist enforcement in `server_cdn.py`
5. 🟡 Session table cleanup on login
6. 🟡 bcrypt for passwords (can be done gradually — detect old hash format on login)
7. 🟢 Remove `localhost` from ALLOWED_ORIGINS in production config
8. 🟢 Add `X-Content-Type-Options` / `X-Frame-Options` headers
9. ♻️ HTML modularisation (not a security issue, do after the above)

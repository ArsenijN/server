# FluxDrop — Security & Code Audit v6
*Covers: `server_cdn.py`, `script.js`, `config.py`, `shared.py`, `net_monitor.py`*
*Supersedes audit v5. All v5 items are resolved or carried forward explicitly below.*

---

## Summary table

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| **B1** | Plain-text password over HTTP | 🔴 Critical* | ✅ Resolved — B7 redirect covers this |
| **B2** | Session tokens stored plain-text in DB | 🟠 High | ✅ Resolved — `_hash_session_token()` applied at all call sites |
| **B3** | bcrypt 72-byte truncation | 🟡 Medium | ✅ Resolved — `_prepare_password()` pre-hash applied |
| **B4** | No rate limit on `PATCH /api/v1/me/password` | 🟡 Medium | ✅ Resolved — shares `"auth"` bucket |
| **B5** | Missing size cap on password-change body | 🟡 Medium | ✅ Resolved — `MAX_JSON_BODY` cap applied |
| **B6** | No username/password length cap at login | 🟡 Medium | ✅ Resolved — `_MAX_USERNAME_LOGIN`, `_MAX_PASSWORD_LOGIN` |
| **B7** | HTTP server accepts auth requests | 🟡 Medium | ✅ Resolved — `_redirect_to_https_if_needed()` in all do_* methods |
| **B8** | HSTS `max-age` still at test value (300 s) | 🟡 Medium | ⚠️ Open — bump to `31536000` once HTTPS redirect confirmed end-to-end |
| **B9** | Missing CSP header | 🟡 Medium | ✅ Resolved — in `end_headers()` override; `unsafe-inline` kept intentionally |
| **B10** | `X-Frame-Options` only on API, not HTML | 🟢 Low | ✅ Resolved — `end_headers()` override fires for every response |
| **B11** | `UPLOAD_TMP_DIR` default inside `SERVE_ROOT` | 🟢 Low | ✅ Resolved |
| **B12** | Fragile DownDetector HTML scrape | 🟢 Low | ✅ **Fixed in v6** — replaced with direct Quad9 TCP probe |
| **C1** | Duplicate `_redirect_to_https_if_needed()` calls | 🟡 Medium | ✅ Resolved in v5 |
| **C2** | `do_HEAD` bypasses security headers override | 🟡 Medium | ✅ Resolved in v5 |
| **C3** | `do_GET` static-file fallback bypasses security headers override | 🟡 Medium | ✅ **Fixed in v6** — see below |
| **J1** | Unescaped `err.message` in `innerHTML` (`script.js`) | 🟡 Medium | ✅ **Fixed in v6** — see below |

---

## Part 1 — New findings fixed in v6

---

### 🟡 C3 — `do_GET` static-file fallback bypassed the `end_headers()` security-header override

This is the exact same class of bug as C2 (fixed in v5 for `do_HEAD`), but it
was missed in the `do_GET` handler.

The `do_GET` method patches `self.end_headers` before delegating to
`super().do_GET()` (i.e. `SimpleHTTPRequestHandler`) to inject `Accept-Ranges`
and CORS headers.  The inner closure called:

```python
super(AuthHandler, self).end_headers()
```

This goes directly to `SimpleHTTPRequestHandler.end_headers()`, bypassing
`AuthHandler.end_headers()`.  As a result, every response to a plain static-file
`GET` request (anything not matched by an API route) was missing:

- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security`
- `Content-Security-Policy`

**Fix applied in `server_cdn.py`:**

```python
# Before (v5):
def patched_end_headers():
    self.send_header('Accept-Ranges', 'bytes')
    self._send_cors_headers()
    super(AuthHandler, self).end_headers()   # ← skips our override

# After (v6):
def patched_end_headers():
    self.send_header('Accept-Ranges', 'bytes')
    self._send_cors_headers()
    AuthHandler.end_headers(self)   # ← goes through our override
```

The pattern is now identical to the already-fixed `do_HEAD`.

---

### 🟡 J1 — Unescaped `err.message` inserted into `innerHTML` (`script.js`, line 1013)

In `renderDirectory()`, an error caught from a failed directory-listing fetch
was interpolated directly into `innerHTML` without HTML-escaping:

```javascript
// Before (v5):
fileList.innerHTML = `<p ...>Failed to load directory: ${err.message}</p>`;
```

`err.message` can contain content from a server-controlled error response (e.g.
a JSON parse error whose message includes the raw response body).  A crafted
server response could therefore inject arbitrary HTML — including a `<script>`
tag — into the page.  Combined with the still-present CSP `unsafe-inline` (B9),
this is a practical stored-XSS vector if the server or a CDN is ever
compromised.

Every other comparable error path in the file already uses `escapeHtml()` (lines
1731, 2005, 2232, 4077).  This one was simply missed.

**Fix applied in `script.js`:**

```javascript
// After (v6):
fileList.innerHTML = `<p ...>Failed to load directory: ${escapeHtml(err.message)}</p>`;
```

---

### 🟢 B12 — DownDetector HTML scrape replaced with direct Quad9 TCP probe (`net_monitor.py`)

The old `_dd_check_google()` scraped `https://downdetector.com/status/google/`
and pattern-matched against specific strings in the HTML.  This would silently
break on any page layout change and added an unnecessary external dependency on a
third-party website.

**Fix applied in `net_monitor.py`:** The function now opens a TCP connection to
Quad9 (`9.9.9.9:53`) — a well-known DNS resolver independent of both Google and
Cloudflare (the existing primary probes).  If Quad9 is also unreachable the
outage is flagged as likely external; if it responds, the outage is local.  No
HTML parsing, no external imports, ~10 lines.

```python
_THIRD_HOST = ('9.9.9.9', 53)   # Quad9 DNS — independent of Google & Cloudflare
try:
    with socket.create_connection(_THIRD_HOST, timeout=_NET_PROBE_TIMEOUT):
        return False   # third host is up → outage is not external
except OSError:
        return True    # third host also down → likely external
```

The `socket` module is already imported at the top of `net_monitor.py` so no new
dependency is introduced.

---

## Part 2 — Still open

---

### ⚠️ B8 — HSTS `max-age` still at test value (carry-forward)

Both `end_headers()` implementations (main `AuthHandler` around line 722, and the
CDN handler around line 726) still have:

```python
self.send_header('Strict-Transport-Security', 'max-age=300; includeSubDomains')
```

Once the HTTP→HTTPS redirect is confirmed working end-to-end, change both to:

```python
self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
```

**Do not bump this value until the redirect is fully validated.** A 1-year HSTS
header on a broken HTTPS configuration will lock users out for a year with no
easy recovery.

---

### 🟢 B9 — `unsafe-inline` in CSP (carry-forward)

`unsafe-inline` is still present in `script-src` and `style-src` because the
share snippet pages use inline `<script>` and `<style>` blocks.  Until those are
externalised, J1 (now fixed) was one concrete exploitation path.  Removing
`unsafe-inline` is still the correct long-term goal, as it neutralises any future
unescaped-innerHTML bugs regardless of how they arise.

---

## Part 3 — Notes on open TODO items with security relevance (unchanged from v5)

- **PDF/Markdown/archive previews** — render user-uploaded content in an iframe or
  sandboxed element; tighten CSP `unsafe-inline` first.
- **File info modal / background hashsums** — validate paths against the user's
  root directory before queueing a background hash job.
- **i18n locale fetching** — locale strings from a server endpoint must not be
  injected into `innerHTML` without sanitisation.
- **Auto-reconnect / chunked download resume** — safe to implement; existing
  per-chunk SHA-256 validation already covers integrity.

---

## Things still done well (unchanged from v5)

- `fetchWithFallback` refuses HTTP fallback when page is loaded over HTTPS.
- Download tokens are SHA-256-hashed in DB.
- bcrypt rounds=12 with pre-hash.
- `is_admin` checked server-side on every admin endpoint.
- No `eval`, `exec`, or `subprocess` on user input anywhere.
- `secrets.compare_digest` used on the legacy SHA-256 path.
- Blacklist loaded and refreshed in the CDN server.
- The `_mdToHtml` Markdown renderer HTML-escapes input before any substitution,
  then passes through an explicit allowlist sanitiser — safe for server-controlled
  policy documents.

---

## Priority order for remaining work

| Priority | Item | Effort |
|----------|------|--------|
| 🟡 1 | **B8** — Bump HSTS to 1 year once HTTPS redirect confirmed end-to-end | 2 lines (both handlers) |
| 🟢 2 | **B9** — Remove `unsafe-inline` once share snippets use external JS/CSS files | Medium refactor |

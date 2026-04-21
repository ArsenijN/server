# FluxDrop — Security & Code Audit v5
*Covers: `server_cdn.py` (post-v4 patch), `script.js`, `config.py`, `shared.py`*
*Supersedes audit v4. All v4 items are resolved or carried forward explicitly below.*

---

## Summary table

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| **B1** | Plain-text password over HTTP | 🔴 Critical* | ✅ Resolved — B7 redirect covers this |
| **B2** | Session tokens stored plain-text in DB | 🟠 High | ✅ Resolved — `_hash_session_token()` applied at all 3 call sites |
| **B3** | bcrypt 72-byte truncation | 🟡 Medium | ✅ Resolved — `_prepare_password()` pre-hash applied |
| **B4** | No rate limit on `PATCH /api/v1/me/password` | 🟡 Medium | ✅ Resolved — shares `"auth"` bucket, P4a label |
| **B5** | Missing size cap on password-change body | 🟡 Medium | ✅ Resolved — `MAX_JSON_BODY` cap applied, P4b label |
| **B6** | No username/password length cap at login | 🟡 Medium | ✅ Resolved — `_MAX_USERNAME_LOGIN = 64`, `_MAX_PASSWORD_LOGIN = 1024` |
| **B7** | HTTP server accepts auth requests | 🟡 Medium | ✅ Resolved — `_redirect_to_https_if_needed()` in all do_* methods |
| **B8** | Missing HSTS header | 🟡 Medium | ⚠️ Partial — header present but `max-age=300` (test value); bump to `31536000` once HTTPS redirect is stable end-to-end |
| **B9** | Missing CSP header | 🟡 Medium | ✅ Resolved — in `end_headers()` override; `unsafe-inline` intentionally kept until share snippet pages are externalised |
| **B10** | `X-Frame-Options` only on API, not HTML | 🟢 Low | ✅ Resolved — `end_headers()` override fires for every response |
| **B11** | `UPLOAD_TMP_DIR` default inside `SERVE_ROOT` | 🟢 Low | ✅ Resolved — `config.py` uses `/tmp/fluxdrop_upload_sessions` |
| **B12** | Fragile DownDetector HTML scrape | 🟢 Low | 🔲 Open — design decision pending |
| **C1** | Duplicate `_redirect_to_https_if_needed()` calls | 🟡 Medium | ✅ Fixed in v5 patch — see below |
| **C2** | `do_HEAD` bypasses security headers override | 🟡 Medium | ✅ Fixed in v5 patch — see below |

---

## Part 1 — Resolved items from v4

All B-series items are confirmed in the current code with the exceptions noted in the
summary table above.

---

## Part 2 — New findings fixed in v5

---

### 🟡 C1 — Duplicate `_redirect_to_https_if_needed()` in `do_POST`, `do_PATCH`, `do_DELETE`

Each of the three mutating verb handlers called `_redirect_to_https_if_needed()` twice:
once at the very top (correct, labelled `# ← P2`) and again immediately after the
blacklist check (copy-paste leftover with no label).

The second call was harmless in production — the first call already returns on HTTP
— but it added a redundant DB/socket check on every HTTPS request and was confusing
to read.

**Fix applied:** the second call and its `return` guard were removed from all three
handlers (`do_POST` line 4114, `do_PATCH` line 4238, `do_DELETE` line 4335).

---

### 🟡 C2 — `do_HEAD` bypassed the `end_headers()` security-header override

`do_HEAD` monkey-patches `self.end_headers` to inject `Accept-Ranges` and CORS
headers, then calls `super(AuthHandler, self).end_headers()` — which goes directly
to `SimpleHTTPRequestHandler.end_headers` (i.e. the base class), skipping
`AuthHandler.end_headers`. This meant HEAD responses were missing:

- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security`
- `Content-Security-Policy`

**Fix applied:** the inner call was changed from
`super(AuthHandler, self).end_headers()` to `AuthHandler.end_headers(self)`.
This goes through our override (which itself calls `super().end_headers()` at the
end), so all security headers are present and there is no double-invocation.

---

## Part 3 — Still open

---

### ⚠️ B8 — HSTS `max-age` still at test value

```python
# end_headers(), line 2880–2881
self.send_header('Strict-Transport-Security',
                'max-age=300; includeSubDomains')
```

`max-age=300` means browsers only remember to use HTTPS for 5 minutes. Once the
HTTP→HTTPS redirect is confirmed working end-to-end (including the frontend
port-switching logic in `script.js`), change this to:

```python
self.send_header('Strict-Transport-Security',
                'max-age=31536000; includeSubDomains')
```

**Do not bump this value until the redirect is fully working.** A 1-year HSTS
header on a broken HTTPS setup will lock users out of the site in their browser
for a year with no easy recovery path.

---

### 🟢 B12 — Fragile DownDetector HTML scrape (carry-forward from A7/B12)

The `_dd_check_google` function scrapes an HTML page to detect outages. This will
silently break whenever the page layout changes. Replace with a direct probe
(e.g. DNS or TCP to `8.8.8.8:53`) when convenient.

---

## Part 4 — Notes on open TODO items with security relevance

These are not new findings but flags to keep in mind when implementing TODO features:

- **PDF/Markdown/archive previews** — render user-uploaded content in an iframe or
  sandboxed element. The CSP `unsafe-inline` must be tightened before shipping
  these, otherwise a crafted filename or file content is a direct XSS vector.
- **File info modal / background hashsums** — ensure the path fed to the background
  hasher is validated against the user's root directory. A job-queue path traversal
  is the most likely vulnerability here.
- **i18n locale fetching** — if locale strings come from a server endpoint, they
  must not be injected into `innerHTML` without sanitisation.
- **Auto-reconnect / chunked download resume** — safe to implement; existing
  per-chunk SHA-256 validation already covers integrity.

---

## Things still done well (unchanged from v4)

- `fetchWithFallback` refuses HTTP fallback when page is loaded over HTTPS.
- Download tokens are SHA-256-hashed in DB — sessions now match.
- bcrypt rounds=12 remains a solid cost factor.
- `is_admin` checked server-side on every admin endpoint.
- No `eval`, `exec`, or `subprocess` on user input anywhere.
- `secrets.compare_digest` used on the legacy SHA-256 path.
- Blacklist is now loaded and refreshed in the CDN server (N1 fix confirmed).

---

## Priority order for remaining work

| Priority | Item | Effort |
|----------|------|--------|
| 🟡 1 | **B8** — Bump HSTS to 1 year once redirect confirmed working | 1 line |
| 🟢 2 | **B9** — Remove `unsafe-inline` once share snippets use external files | Medium refactor |
| 🟢 3 | **B12** — Replace DownDetector HTML scrape with direct TCP/DNS probe | ~10 lines |
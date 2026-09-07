# FluxDrop — Security & Code Audit v7

*Covers backend only: `server_cdn.py`, `server_http.py`, `server_https.py`, `config.py`, `shared.py`, `core/*.py`.*
*Supersedes audit v6 (April, `d301733`). ~196 commits / ~6.4k changed backend lines since.*
*Method: static reading of the current tree at `HEAD` (`b0e8664`, V0.20.0.21). Findings are traced through the code, **not** dynamically exploited — verify before and after fixing.*

---

## Summary table

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| **B16** | Cross-user path traversal — `realpath().startswith(root)` with no trailing separator lets user *N* reach any user whose id **starts with** `str(N)` (`1`→`10‑19`, `2`→`20‑29`, …). Read **and** write. | 🔴 Critical | ✅ Fixed — `_is_within()` helper applied to all 33 guard sites in `server_cdn.py` + `core/trash.py:_trash_restore` |
| **C3** *(reopened)* | `do_GET` static-file, `/policies/*.md`, and avatar closures call `super(AuthHandler,self).end_headers()` — bypassing the security-header override. Same bug v6 marked fixed; regressed for `do_GET`. | 🟠 High | ✅ Fixed — all 3 closures now call `AuthHandler.end_headers(self)` |
| **B13** | Authenticated SSRF via upload-notification webhooks (no host/IP allow-list, redirects followed, `file://` reachable) + arbitrary outbound email (`target` unvalidated). | 🟠 High | ⛔ New |
| **B15** | Per-IP rate-limit & IP blacklist ineffective behind the reverse proxy — CDN reads `self.client_address` (always `127.0.0.1`) instead of the `X-Forwarded-For` the proxies set. | 🟠 High | ⛔ New |
| **B14** | Naive `datetime.now()` written to `expires_at`, compared against SQLite `CURRENT_TIMESTAMP` (UTC). Grants extra lifetime at UTC+; **breaks registration/login entirely west of UTC**. | 🟡 Medium | ⛔ New |
| **B17** | Registration validates `username` strictly but accepts any `nickname` / `email` (length-only). Email → SMTP header-injection surface; nickname → stored-XSS surface wherever rendered unescaped. | 🟡 Medium | ⛔ New |
| **B18** | `share_access_log` grows unbounded; anonymous share hits are un-throttled and each bumps `access_count` + inserts a row → disk-fill vector on any public share. | 🟡 Medium | ⛔ New |
| **B19** | Every `ON DELETE CASCADE` is dead — `PRAGMA foreign_keys` is never enabled. Admin user-delete orphans sessions, shares, trash, checksums, notifications, policy rows. Compounds the GDPR gap. | 🟡 Medium | ⛔ New |
| **B8** | HSTS `max-age` still `300` (`config.HSTS_MAX_AGE`). | ⚠️ Open | Carry-forward from v6 |
| **B9** | CSP still carries `unsafe-inline` (`script-src`, `style-src`) for the snippet pages. | ⚠️ Open | Carry-forward from v6 |
| **B1–B7, B10–B12, C1–C2, J1** | — | ✅ | Resolved in v5/v6, still resolved |

Minor / low: notification email body has literal `\n` (`core/notifications.py:84‑88`); PIL avatar decode relies on the default `MAX_IMAGE_PIXELS` guard only; failed-token prefix is logged (`server_cdn.py:1377`); `datetime.fromtimestamp` (naive) in status rendering.

---

## 🔴 B16 — Cross-user path traversal via prefix `startswith` check

**Where:** the buggy `realpath().startswith(realpath(root))` idiom appears **33 times** across `server_cdn.py` — upload save, batch-tar, mkdir, rename, move, copy, delete, download, folder-size, create-share, share-page browse, CRC scan, avatar/checksum paths — plus `core/trash.py:_trash_restore` (which had **no** containment check at all). Representative sites:

| File:line (pre-fix) | Endpoint |
|---|---|
| `server_cdn.py:938` | `POST /api/v1/batch_tar_upload` — `dest_fs` |
| `server_cdn.py:1890/1923` | chunked upload `init` (`owner_type` = user / share) — `dest_path` |
| `server_cdn.py:3703` | `POST /api/v1/share` (create share) — `fs_path` |
| `server_cdn.py:3802` | `_render_share_page` — `target_fs` |
| `server_cdn.py:5417/5496/6005/6067/6131/6215/6365` | mkdir / upload-save / rename / move / copy handlers — `base_fs`-relative |
| `server_cdn.py:4486` | CRC/checksum scan root |
| `core/trash.py:93` | `_trash_restore` — `dest` (no realpath check at all) |

Every site does:

```python
user_root = os.path.realpath(os.path.join(SERVE_ROOT, "FluxDrop", str(user_id)))   # e.g. /srv/FluxDrop/2
fs_path   = os.path.normpath(os.path.join(user_root, path.lstrip("/")))
if not os.path.realpath(fs_path).startswith(user_root):        # ← no os.sep on user_root
    return 403
```

`path.lstrip("/")` strips leading slashes but **not** `..`. With `user_id = 2` and `path = "../20/private.txt"`:

```
fs_path            = /srv/FluxDrop/20/private.txt
realpath(fs_path)  = /srv/FluxDrop/20/private.txt
.startswith("/srv/FluxDrop/2")  →  True    ← guard passes
```

So an authenticated user can **read and write files in any other user's tree whose numeric id is a decimal-string prefix of their own** — `1` reaches `10`–`19`, `2` reaches `20`–`29`, `12` reaches `120`–`129`, etc. Sequential low ids make this very reachable, and early-adopter / admin accounts hold the lowest ids. Reachable operations include: upload into, extract a tar into, create a **public share** of, browse, and (via `_trash_restore`, which has *no* containment check) `os.rename` a trash entry to an arbitrary `original_path`.

**Fix** — one shared helper, used at every site:

```python
def _is_within(root: str, candidate: str) -> bool:
    root = os.path.realpath(root)
    cand = os.path.realpath(candidate)
    return cand == root or cand.startswith(root + os.sep)
```

For `_trash_restore`, also reject `original_path` containing `..` before the join, and containment-check `dest` against `user_root` the same way.

---

## 🟠 C3 (reopened) — security headers bypassed on `do_GET`

`AuthHandler.end_headers()` (`server_cdn.py:1266`) is the single place that emits `X-Frame-Options`, `X-Content-Type-Options: nosniff`, HSTS, and CSP. Three closures re-patch `self.end_headers` and then call the **base class** instead of the override:

- `server_cdn.py:2880` — the catch-all static-file handler (`patched_end_headers` → `super(AuthHandler,self).end_headers()`). This serves the SPA JS/CSS, images, **CatBox uploads, and user files fetched by path** — all with no CSP, no `nosniff`, no `X-Frame-Options`.
- `server_cdn.py:2868` — `/policies/*.md` + `versions.json` (`patched_end_headers_nocache`).
- `server_cdn.py:2741` — `GET /api/v1/avatar/<id>` (`super(AuthHandler,self).end_headers()` inline).

`do_HEAD` (`:2353`) and the `do_GET` API closure (`:2350`) were fixed to call `AuthHandler.end_headers(self)` — these three were not (or regressed since v6).

**Impact:** missing `nosniff` on same-origin user-controlled content (a CatBox “image” that is actually HTML → MIME-sniffed → stored XSS), no CSP on the app origin so any DOM-XSS is unmitigated, no `X-Frame-Options` → clickjacking. Avatar bytes are re-encoded by Pillow so that route is lower-risk, but should still be consistent.

**Fix:** in all three closures, replace `super(AuthHandler, self).end_headers()` with `AuthHandler.end_headers(self)` (exactly the v6 fix).

---

## 🟠 B13 — SSRF & arbitrary email via upload-notification subscriptions

`_handle_notifications_subscribe` (`server_cdn.py:1123`) accepts `{type, target, secret}`. Validation is only: `type in ("webhook","email")`, `target` non-empty, `len(target) <= 512`, and for webhooks `target.startswith(("http://","https://"))`. On every completed upload, `_fire_upload_notification` (`core/notifications.py:23`) runs:

- **webhook:** `urllib.request.urlopen(Request(target, data=..., method="POST"), timeout=10)` using the **default global opener** — so `target` can be `http://127.0.0.1:64799/…` (the internal CDN port), `http://192.168.x.x/…` (LAN devices/router), `http://169.254.169.254/…`, and redirects are followed (an `https://` target can 302 to any of those). The default opener also has a `FileHandler`, so `file:///etc/passwd` is reachable. Blind (body not returned) but status + timing are observable, and a POST to an internal mutating endpoint needs no response.
- **email:** `target` gets **no validation at all** — no `@`, no format, no CR/LF check. `msg["To"] = target` then `sendmail(..., [target], ...)` → an authenticated user turns the server into an arbitrary-recipient mailer using your SMTP identity/reputation, with CR/LF in `target` as a header-injection surface.

**Fix:**
- Build a private opener with only `HTTPHandler`/`HTTPSHandler` (no `FileHandler`, no `FTPHandler`) and a redirect handler that re-validates each hop.
- Resolve the target host; reject loopback / private / link-local / ULA / `0.0.0.0/8` / multicast. Re-resolve+recheck on redirect (or forbid redirects).
- Email target: validate against a real address regex, reject control chars; ideally restrict email notifications to the subscriber's own verified account address.
- Optional: challenge-response at subscribe time (endpoint must echo a nonce) to prove intent.

---

## 🟠 B15 — IP rate-limit / blacklist don't see the real client behind the proxy

`server_http.py:91`, `server_https.py:292` & `:586` proxy to the CDN and set `X-Forwarded-For: handler.client_address[0]`. But the CDN uses `self.client_address[0]` — which for every proxied request is `127.0.0.1` — for:

- `_rate_limit(self.client_address[0], "auth"/"api")` — register (`:3469`), login (`:3569`), and API buckets (`:1610`, `:1638`, `:1677`, `:1707`).
- blacklist checks (`self.client_address[0] in current_blacklist` — `:2322`, `:2342`, `:2586`, `:2910`, `:3192`, `:3292`).

Only `:2408` reads `X-Forwarded-For`. Net effect through the public entrypoint: the "10 auth attempts / IP / minute" limiter is a **single global bucket** (anyone can lock out all logins with 10 requests/min, and brute-force protection per attacker IP is gone), and **IP bans do nothing**.

Also the proxies **overwrite** `X-Forwarded-For` with the immediate peer, so if Cloudflare/another proxy is upstream the real visitor IP is lost even at `:2408`.

**Fix:** one `_client_ip()` helper on the CDN handler — trust `X-Forwarded-For[0]` **only when `self.client_address[0]` is loopback**, else use the socket peer — and route every rate-limit / blacklist / access-log call through it. Have the proxies append to (not replace) `X-Forwarded-For`, and honour `CF-Connecting-IP` if Cloudflare fronts the deployment.

---

## 🟡 B14 — naive local time vs SQLite UTC for expiry

- `server_cdn.py:3515` — `expires_at = (datetime.now() + timedelta(hours=1)).isoformat()` (pending verification)
- `server_cdn.py:3630` — `expires_at = datetime.now() + timedelta(days=7)` (session)
- `core/auth.py:177` — `datetime.now() + timedelta(seconds=DOWNLOAD_TOKEN_TTL_SECONDS)` (download token)

All are compared against `CURRENT_TIMESTAMP` (`sessions`, `pending_verifications`, `download_tokens` lookups), which SQLite evaluates in **UTC**. `datetime.now()` is naive local.

- UTC+3 (this server): every lifetime is silently +3h (session ≈ 7d 3h, verification link ≈ 4h). Harmless but wrong.
- Any host **west of UTC+1**: `expires_at` for a 1-hour token is written *already in the past* relative to `CURRENT_TIMESTAMP` → verification links are dead on arrival and sessions expire immediately. Registration/login break outright.

**Fix:** use `datetime.now(timezone.utc)` (or `datetime.utcnow()`) at those three sites, or store epoch seconds and compare against `strftime('%s','now')` — matching what `core/db.py`, `core/trash.py`, `core/net_monitor.py` already do with `time.time()`.

---

## 🟡 B17 — `nickname` / `email` not validated at registration

`handle_register` (`server_cdn.py:3473`+) enforces `^[A-Za-z0-9_\-\.]{3,64}$` on `username` (good) but `nickname` and `email` get only a length cap (`:3486`).

- `email`: no format check, no CR/LF rejection before it reaches `msg['To']` / `sendmail` in `send_verification_email`. Garbage emails also create dead `pending_verifications` rows (send fails → silent simulation fallback).
- `nickname`: `<script>…` is accepted and stored. Safe only as long as **every** surface that renders a nickname escapes it (admin user list, profile displays, any future share/listing UI). One missed `innerHTML` = stored XSS. Same class as v6's J1.

**Fix:** constrain `nickname` (printable, no `<>&"'`, length), validate `email` with a real regex + reject control chars. Keep escaping on the frontend regardless.

---

## 🟡 B18 — unbounded public share access log

`_log_share_access` (`core/shares.py:122`) inserts a `share_access_log` row and increments `shared_links.access_count` on **every** hit of a `track_stats` share, with no rate limit and no row cap. `_get_share_stats` only limits the *display* to 200. Anyone with a public share URL can inflate the table and the DB file indefinitely by looping the URL.

**Fix:** throttle logging per (token, client-ip) to e.g. 1/min, and cap retained rows per token (ring-buffer / periodic prune), or aggregate to a daily counter.

---

## 🟡 B19 — `ON DELETE CASCADE` never enforced

`core/db.py` declares `REFERENCES users(id) ON DELETE CASCADE` on `trash_items`, `upload_notifications`, `policy_acceptances`, `file_checksums`, `checksum_jobs`, `copy_jobs`, `beacon_read_tokens`. SQLite enforces foreign keys only when `PRAGMA foreign_keys = ON` is set **per connection** — `_db_connect` (`core/db.py:7`) never sets it. So deleting a user (`DELETE FROM users …`, `server_cdn.py:3313`) leaves every child row behind, plus the on-disk `FluxDrop/<id>/` tree (the handler comments that this is intentional/manual). This is the mechanical half of the GDPR-deletion gap discussed separately.

**Fix:** add `conn.execute("PRAGMA foreign_keys = ON")` in `_db_connect` (alongside the existing `PRAGMA journal_mode=WAL`), and have the admin-delete path also remove `shared_links`, `share_access_log`, `download_tokens`, `cdn_uploads`, `protected_files`, and the user's storage + `.trash` directories.

---

## Carry-forward (unchanged from v6)

### ⚠️ B8 — HSTS still at test value
`config.py:83` — `HSTS_MAX_AGE = 300`. Bump to `31536000` via env once the HTTP→HTTPS redirect is confirmed end-to-end. Do **not** raise it while HTTPS is uncertain.

### ⚠️ B9 — `unsafe-inline` in CSP
`server_cdn.py:1277‑1278`. Needed while snippet pages (`share_*`, `status_page`) use inline `<script>`/`<style>`. Externalise those, then drop `unsafe-inline` — with B16/C3 fixed and `unsafe-inline` gone, the residual XSS surface is small.

---

## Still done well

- Path guards, though prefix-buggy (B16), are present and consistent — one helper fixes all sites.
- Session & download tokens: SHA-256-hashed at rest; download tokens are separate from session tokens, file-scoped, TTL'd.
- bcrypt rounds=12 with SHA-256+base64 pre-hash (no 72-byte truncation).
- `_check_admin_auth` is header-only, re-checks `is_admin` on every admin call, sends its own 401/403.
- No `os.system` / `subprocess` / `eval` / `exec` / `pickle` anywhere in the backend.
- Every SQL statement is parameterised; the only f-string SQL (`db.py` migrations) interpolates hardcoded literals.
- Body-size caps: `MAX_JSON_BODY`, `MAX_UPLOAD_BYTES`, `MAX_SHARE_UPLOAD_BYTES`, `CATBOX_MAX_UPLOAD_BYTES`, avatar `MAX_JSON_BODY` + `AVATAR_MAX_BYTES`.
- `UPLOAD_TMP_DIR` moved out of `SERVE_ROOT` (v6 B11 stays fixed).
- Avatar uploads are re-encoded through Pillow — stored bytes are never attacker bytes.
- `_db_connect` is a context manager (no connection leaks) with WAL + 15 s lock timeout.
- DownDetector scrape gone; connectivity probes are pure TCP against independent resolvers.
- Per-upload-session chunk locks prevent lost-update races on `chunks_received`.
- Webhook notifications support HMAC-SHA256 signing and a per-user subscription cap.

---

## Priority order

| Priority | Item | Effort |
|---|---|---|
| ~~🔴 1~~ | ~~**B16**~~ — ✅ done: `_is_within()` in `server_cdn.py`, applied to 33 sites; `_trash_restore` now containment-checks `dest` | — |
| ~~🟠 2~~ | ~~**C3**~~ — ✅ done: 3 closures call `AuthHandler.end_headers(self)` | — |
| 🟠 3 | **B13** — private opener (no `file://`), private-IP block, redirect re-check; validate/restrict email target | Medium |
| 🟠 4 | **B15** — `_client_ip()` helper trusting XFF only from loopback; route all rate-limit/blacklist through it | Small–medium |
| 🟡 5 | **B14** — UTC at the 3 expiry-write sites | 3 lines |
| 🟡 6 | **B17** — validate `nickname` / `email` in `handle_register` | Small |
| 🟡 7 | **B19** — `PRAGMA foreign_keys = ON` + widen admin-delete cleanup | Small (pairs with the GDPR work) |
| 🟡 8 | **B18** — throttle + cap `share_access_log` | Small |
| ⚠️ 9 | **B8** HSTS 1-year, **B9** drop `unsafe-inline` (after snippet externalisation) | 2 lines / medium |

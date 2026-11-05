# Code map

Where things live, for finding your way around. Line numbers drift, so this
points at file names, section banners and function names you can search for.
Function lists per backend module are in the **MODULE INDEX** comment at the
top of `server/Web/server_cdn.py`.

## Layout

```
README.md, TODO.md, TESTING.md   release notes, plan, what still needs testing
DEVNOTES.md, notes.md            working notes
CODEMAP.md                       this file
build.sh, package.json           frontend build (Tailwind, minify, locale bundle)
sync_to_server.sh / .bat         deploy: mirrors server/ to the host, restarts
policies/                        Privacy Policy / Terms drafts (en, uk)
server/
  Web/                           the Python servers (run from here)
    server_cdn.py                FluxDrop: API, uploads, shares, CatBox, status
    server_https.py              public HTTPS front: static sites, proxies
    server_http.py               public HTTP front: redirects, static, CDN paths
    shared.py                    helpers shared by the three servers
    config.py                    every setting (env + secrets/*.env)
    core/                        FluxDrop logic split out of server_cdn.py
    snippets/                    server-rendered HTML (share pages, emails, status)
    secrets_samples/             templates for secrets/ (git-ignored)
    ip_beacon.py                 client daemon: reports a device's public IP
    .helper-*.py                 admin CLI helpers (users, passwords, tokens)
  build/
    src/fluxdrop_pp/             frontend SOURCE — edit here
    build_locale_bundle.py, check_locales.py
  TestWeb/                       build OUTPUT served as the site (don't edit)
  services/                      systemd units (+ webserver-https drop-in)
```

## Request flow

```
browser ──HTTPS──▶ server_https.py (FRONT_HTTPS_PORT, 8443)
                     1. _get_host_proxy      whole subdomain → local service
                                             (gallery.* → Immich, tbot.*)
                     2. _try_path_proxy      per-host path prefixes
                     3. fluxdrop_legacy_redirect   arseniusgen.* → fluxdrop.me
                     4. _CDN_PROXY_PREFIXES  /api/ /auth/ /share/ /status …
                                             → server_cdn.py on loopback 64799
                     5. otherwise            static files from TestWeb/
                                             (fluxdrop.me serves fluxdrop_pp/ at /)
browser ──HTTP───▶ server_http.py (FRONT_HTTP_PORT, 8080)
                     redirects to HTTPS (_https_redirect_host), CDN paths proxied
```

`server_cdn.py` also listens itself on 63512 (HTTP) / 64800 (HTTPS).

## Backend: server_cdn.py

Search for these banners / names:

| Search for | What's there |
|---|---|
| `MODULE INDEX` | which function lives in which `core/` module |
| `# --- CONFIGURATION ---` | settings read at import (most come from `config.py`) |
| `_bg_crc32_scanner` | nightly/idle checksum scan + integrity scrub (`_SCRUB_DAYS`) |
| `_zip_build_job`, `_handle_zip_*` | folder ZIP: background job, status polling, streaming, `/report` |
| `# --- MAIN REQUEST HANDLER ---` | `class AuthHandler` — everything per request |
| `_pattern = re.compile` | URL patterns of the API routes |
| `def do_GET` / `do_POST` / `do_PUT` / `do_PATCH` / `do_DELETE` | routing: each matches the patterns above, in order |
| `handle_upload_session_*` | chunked upload API (init / chunk / status / complete / cancel) |
| `_free_upload_dest`, `replace_temp_path` | name clashes: keep both / replace |
| `_render_share_page`, `handle_public_share*` | public share pages, share uploads |
| `handle_catbox_*` | CatBox-compatible API |
| `_cdn_admin_denied`, `_publish_denied` | admin-only legacy CDN folder, `can_publish` flag |
| `_send_inline_isolation_headers` | `CSP: sandbox` for user files shown inline |
| `_token_purge_worker` | 5-minute housekeeping (tokens, abandoned uploads, CatBox expiry) |
| `# --- SERVER EXECUTION ---` | startup: threads, ports, TLS |

### core/

| Module | Responsibility |
|---|---|
| `db.py` | SQLite connection, schema + migrations (`init_db`), checksums, CatBox owners, integrity issues |
| `upload.py` | upload sessions: strategies (direct / buffer), chunks, assembly, replace swap, purge |
| `auth.py` | passwords, sessions, download tokens, verification email |
| `shares.py` | share links and their access log |
| `trash.py` | trash bin |
| `quota.py` | dynamic quota, server free-space guard |
| `archive_tree.py` | archive listing for previews (cache, background tar worker, zip-bomb limits) |
| `snippets.py` | snippet rendering + server-side translations |
| `mailer.py` | SMTP |
| `notifications.py` | upload webhooks / emails |
| `reports.py` | content reports |
| `accounts.py` | account deletion + delayed purge |
| `status.py`, `net_monitor.py` | status page, uptime snapshots, network outages |
| `rate_limit.py`, `meta.py` | throttling; version + start time |

### Database tables

`users`, `sessions`, `pending_verifications`, `policy_acceptances` ·
`upload_sessions` · `shared_links`, `share_access_log` · `trash_items` ·
`download_tokens`, `protected_files` · `file_checksums`, `checksum_jobs`,
`file_integrity_issues` · `copy_jobs` · `catbox_uploads`, `cdn_uploads` ·
`upload_notifications` · `content_reports` · `status_snapshots`,
`incident_log`, `net_outages`, `message_board` · `beacon_devices`,
`beacon_read_tokens`. Schema: `init_db()` in `core/db.py`.

### Background threads (server_cdn.py)

Checksum scanner + scrub, ZIP sessions cleanup, ZIP build jobs, copy jobs,
archive-tree worker, quota updater, network monitor, token/upload purge,
upload notifications, integrity alerts.

## Frontend: server/build/src/fluxdrop_pp/

| File | What |
|---|---|
| `index.html` | app shell, boot loader, static modals |
| `script.js` | the app (sections below) |
| `fd_addons.js` | i18n (`window.t`, `FDi18n`, `fd_lang` cookie), overlay animations, extras |
| `fd_dark.css`, `input.css` | dark theme overrides; Tailwind input |
| `locale/en.json`, `uk.json` | all UI + email + share-page strings (the server reads them too) |
| `fd_locale_bundle.js` | generated from `locale/` by the build |
| `sw.js`, `offline.html` | service worker, offline page |

`script.js` sections (search the banner text):

`--- CONFIGURATION ---` · `--- GLOBAL STATE & DOM ELEMENTS ---` ·
`--- UTILITY FUNCTIONS ---` · `--- UI RENDERING & ROUTING ---` ·
`--- DOWNLOAD MANAGER` · `--- MEDIA PREVIEW ---` (`previewFile`, archive tree) ·
`--- TRASH BIN VIEW ---` · `--- MOVE / RENAME / COPY DIALOG ---` ·
`--- CHUNKED UPLOAD ENGINE ---` (`uploadChunked`, `_askUploadConflict`,
`_Sha256`) · `--- UPLOAD MANAGER` (tray) · `--- EVENT HANDLERS & LOGIC ---` ·
`--- PROFILE MENU ---` · `--- PROFILE PANEL ---` (settings) · `--- ADMIN PANEL ---`.
Share dialog / manager: `openShareDialog`, `openShareManager`.

## Build and deploy

`./build.sh` → `server/TestWeb/` (minified, locale bundle, cache version);
`./sync_to_server.sh` → mirrors `server/` to the host (never `Web/secrets/`)
and restarts the services. Details: wiki → Installation / Deployment.

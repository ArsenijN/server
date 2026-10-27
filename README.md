# FluxDrop & server `v0.21.1.21`
Self-hosted file hosting (FluxDrop) plus the rest of my home server, in one
repo. Anyone can use it.

## What's new
> **In short:** content reports and an admin Reports tab, a safer account
> verification flow, fairer storage quotas with a disk-full guard, much faster
> first load (compressed and minified assets, lighter fonts and icons), more
> of the UI translated, and reverse-proxy fixes for Immich. Two breaking
> changes: account verification is now a `POST`, and IP Beacon registration
> needs a FluxDrop login.

### FluxDrop (UI)
**Added**
- Content reports: a 🚩 Report link on shared folder pages, and a report form
  at `/report` for single-file links and CDN / CatBox files (English and
  Ukrainian). Reports can be sent anonymously; an email for a reply is optional
- Admin panel: a **Reports** tab with an open-report counter, filters, and
  actions — disable the share link, delete the CDN file, mark resolved,
  dismiss, reopen
- Account verification page: the email link now opens a "You're almost set!"
  page with a **Verify my account** button, the address / username / nickname
  it was sent for, when the link expires (in the visitor's time zone), and a
  **Report** button that cancels a registration you didn't make (English and
  Ukrainian)
- Version picker in the Terms of Service / Privacy Policy viewer: read any
  earlier published version, with a note when it's no longer in effect
- Full-screen "Creating your account…" spinner while registering
- Loading screen shows what it's doing ("Loading the app… / translations… /
  extras… / Starting…") with a progress bar, and after 8 s explains that the
  connection seems slow and that later visits load from the device

**Changed**
- The offline page loads the Inter font from FluxDrop itself instead of Google
  Fonts, so visitors' IPs are no longer sent to Google
- Verification email: explains what happens after confirming, why it was
  sent, and where to get help (`support@fluxdrop.me`). The extra text also
  cleared a spam-filter penalty for image-heavy mail — mail-tester now scores
  it 10/10. Username and address are HTML-escaped in the email
- The report page has an EN / УКР switch (shared with the app's language
  setting), and "FluxDrop" links on share / report / status pages go to `/` on
  fluxdrop.me instead of the legacy `/fluxdrop_pp/index.html`
- Better contrast for the blue and green buttons and the grey footer text
  (they were below the WCAG 4.5 : 1 minimum)
- Faster first load: the Latin Inter font is preloaded instead of waiting for
  `Inter.css`, the landing logo is a 3 KB WebP instead of an 11 KB PNG, and the
  loading bar animates with `transform` (no layout work per frame)
- The HTTPS server accepts bursts of new connections better: the listen
  backlog is 1024 instead of the default 5, and the worker pool is 400 threads
  instead of 100 (`HTTPS_MAX_WORKERS` to change it; threads are only created
  when needed). Every keep-alive connection occupies one worker for up to 45 s,
  and Immich's timeline opens about 60 parallel connections while scrolling, so
  a busy moment could leave new connections waiting until a worker was free

**Fixed**
- I18n in the profile panel: title, avatar statuses, password messages,
  button states and Space Analyzer tooltips now follow the selected language
- I18n in pop-up messages: "Upload successful" and every other message dialog
  that still had hardcoded English text (upload/download errors, session
  expired, login failed, share updates, account verification), plus the
  desktop notification shown when an upload finishes in the background
- Ukrainian UI now tells uploads and downloads apart: upload is
  «вивантажити / вивантаження», download is «завантажити / завантаження».
  Previously both buttons read «Завантажити»
- Admin panel dark mode: hovered user rows turned white, row dividers, usage
  bars, the active tab and report cards kept their light colours
- Admin panel user list could fail with "proxy error: timed out" after a
  restart: it measured every account's folder size inside the request when the
  size cache was cold. Sizes not cached yet now show "calculating…" and fill
  in automatically (the list refreshes every few seconds until they're in)
- Page could hang on "Loading FluxDrop…" right after a deploy, with a huge
  logo, stray "OK" buttons and a false "FluxDrop failed to load ()" banner: the
  new service worker downloaded ~5 MB of assets all at once while the page was
  loading, so the page's own CSS/JS sat pending behind them. The service
  worker now precaches only the app shell, 3 files at a time; on-demand
  libraries (heic2any, jszip, marked, untar, StreamSaver) are cached on first
  use; registration waits for the page's `load` event; and `index.html` keeps
  `.hidden` elements hidden and the logo at 32 px even before the stylesheets
  arrive
- Slow first paint on slow connections (tested on simulated GPRS): removed the
  unused Font Awesome stylesheet (84 KB, render-blocking, its fonts weren't even
  deployed); `Inter.css` now declares one face per character subset with a
  weight range (the font is variable) instead of 35 faces, which made Firefox
  request the same font file up to 5 times; the 176 KB `icon.svg` (a PNG wrapped
  in SVG) is replaced in the app and page favicons by `icon-64.png` (4.5 KB) and
  `icon-128.png` (11 KB)
- "Loading FluxDrop…" and the "failed to load" banner in `index.html` were
  always English; they now follow the saved language
- "Loading…" in the Terms / Privacy Policy viewer, trash, move dialog and
  Markdown preview was hardcoded English; it's now translated, with a spinner.
  The policy "could not load" / "Retry" messages are translated too
- The Terms of Service and Privacy Policy pop-ups open and close with the same
  animation as the other dialogs (the viewer also closes with `Esc`)
- Immich timeline thumbnails sometimes didn't load while scrolling (a blurred
  thumb until you opened the photo and went back): the reverse proxy answered
  `204 No Content` responses (Immich's sync acknowledgements and asset
  `PUT` / `DELETE`) as `Transfer-Encoding: chunked` followed by a `0` chunk
  terminator. A 204 has no body, so strict HTTP clients read those stray bytes
  as the start of the next response on the same keep-alive connection, and the
  next request on it, often a thumbnail, failed. The proxy now sends 204, 205,
  304, 1xx and `HEAD` responses with headers only
- The reverse proxy followed `3xx` redirects itself instead of passing them to
  the client, which turned `POST` into `GET` on 301 / 302 / 303, dropped the
  request body, and could send the server out to the public address to fetch
  the `Location`. Redirects now reach the client unchanged

### Server (backend)
**Added**
- `content_reports` table and `POST /api/v1/report` (3 reports per minute per
  IP), `GET /api/v1/admin/reports`, `POST /api/v1/admin/reports/<id>`. New
  reports are emailed to `REPORT_NOTIFY_EMAIL` (defaults to `CONTACT_EMAIL`);
  closed reports are pruned after 1 year
- Server logs rotate daily and are kept for `LOG_RETENTION_DAYS` (90);
  `maintenance.log` is split per day with the same limit
- Deleting an account moves its files to `FluxDrop/.deleted_accounts/` and
  purges them after `DELETED_ACCOUNT_PURGE_DAYS` (30); its share links,
  tokens and IP Beacon devices are removed right away
- One mail module (`core/mailer.py`) for all outgoing email, with port 465
  support and new `SMTP_USERNAME`, `SMTP_SENDER_NAME`, `SMTP_REPLY_TO`
  settings — needed for transactional providers when sending from
  `@fluxdrop.me`

**Changed**
- Dynamic quotas are now a fair share of the real available space
  (`free − reserve + what non-pinned users store − headroom promised to pinned
  users`, split between non-pinned users, 10–100 GB) instead of free-space
  tiers. One user uploading no longer shrinks everyone else's quota, and the
  quotas together can't promise more space than the disk has
- Disk-full guard: uploads, copies and tar streams are refused up front with a
  readable "server is out of storage space" message once only the reserve
  (`QUOTA_RESERVE_GB`, default 20, or `QUOTA_RESERVE_PCT` of the disk, default
  2 %) is left — instead of failing with "No space left on device" mid-transfer
- Static text files (JS, CSS, HTML, SVG, JSON, Markdown) are now sent
  compressed: the web servers serve the pre-built `.br` / `.gz` copy when the
  browser accepts it, and gzip on the fly (cached in memory) otherwise. Before,
  only `.md` was compressed — `script.js` went out as 456 KB, now ~63 KB
- The app page itself is compressed too (13.8 KB → 4.9 KB): the `fluxdrop.me/`
  rewrite and folder URLs like `/fluxdrop_pp/` sent it uncompressed
- The landing page at `fluxdrop.me/` can be indexed by search engines
  (`index, follow` plus a canonical link). Every other URL that serves the app
  (`/files/…`, `/fluxdrop_pp/`, other domains) stays `noindex`
- `build.sh` minifies the TestWeb copies of the JS/CSS with esbuild (source
  maps included, `build/src` stays readable; `--no-minify` to skip) and
  pre-compresses text assets. esbuild is a new dev dependency — run
  `npm install` once
- `GET /api/v1/policy/history`: published versions of each policy per
  language (never anything newer than `versions.json`, so drafts stay hidden)

**Changed (breaking)**
- `/auth/verify` no longer activates the account on GET; activation is
  `POST /auth/verify {token}` (the page's button), and
  `POST /auth/verify_cancel {token}` cancels the registration and files a
  content report
- `POST /beacon/register` now requires a FluxDrop login and records the
  owning account. `ip_beacon.py --register` needs `--fluxdrop-token` (or
  `FLUXDROP_TOKEN`); devices registered on the web page can be handed over
  with `--primary-token`. Older daemons keep pinging, only new registrations
  change

**Fixed**
- Deleting a user from the admin panel failed with a database constraint
  error when the user had share links, download tokens or protected files
- `/beacon/register` accepted registrations without any login, despite the
  code comments calling it session-gated
- Accounts were verified by anything that opened the email link — mail
  scanners (Outlook Safe Links, antivirus gateways, mail-tester's link check)
  verified accounts nobody had confirmed

### Known issues
- Pausing an upload can sometimes lose a chunk the server had already
  received, so less data shows as uploaded after resuming
- "Cancelling…" on an upload sometimes stays forever without cancelling
- Files inside a folder in the trash can't be previewed yet (the folder's
  contents can be browsed)
- After a ZIP download is cancelled, the server keeps hashing its files in the
  background
- The Privacy Policy and Terms of Service v0.1.0 are drafted but not published
  yet

### Housekeeping
- Moved the finished "Background hashsums" entry to the Done part of `TODO.md`
- Reorganised `TODO.md` into phases (priority fixes → backend → API V2 →
  frontend V2), with the project rules in their own section
- Updated the `README.md` layout; installation instructions moved to the
  [Wiki](https://github.com/ArsenijN/server/wiki), which was updated to match
  the current code
- Drafted Privacy Policy and Terms of Service v0.1.0 (English and Ukrainian)
  in `policies/`; not active until `versions.json` is bumped

<details>
<summary>Older releases</summary>

Each commit is one version (`V0.21.1.1`, `V0.21.1.2`, …), and the README at
that commit holds its notes, so `git log -p README.md` shows the history.
[CHANGELOG.md](./CHANGELOG.md) has older, more detailed notes, but isn't kept
up to date.

</details>

---

## About

### What's in this repo

Mostly **FluxDrop**; a few other things share the same server for now:

| Part | What it is | Code |
|---|---|---|
| FluxDrop | File hosting: resumable chunked uploads, sharing, trash, previews, storage quotas | `server_cdn.py`, `core/`, `build/src/fluxdrop_pp/` |
| CatBox API | CatBox-compatible upload API (`/user/api.php`) on the same CDN | `server_cdn.py` |
| Status page | Uptime, incidents, message board and FluxDrop notices | `core/status.py`, `snippets/status_page.html` |
| Main site | Static sites and reverse proxy for my domains | `server_http.py`, `server_https.py` |
| IP beacon | Small client daemon that reports a device's public IP to FluxDrop | `ip_beacon.py` |

FluxDrop and the rest of the server may become separate repos later. For
now they share one codebase and one version number.

### Status

As of September 11, 2026, FluxDrop is ready for public use (see the
[audit](./fluxdrop_audit.md) and [TODO](./TODO.md)).

Updates go in this order: logic and safety issues first, then TODO entries,
then feedback and [GitHub Issues](https://github.com/ArsenijN/server/issues).
Please report problems there.

### Links

- FluxDrop: https://fluxdrop.me
- Main site: https://arseniusgen.dev, https://arseniusgen.uk.to
- Wiki: https://github.com/ArsenijN/server/wiki

For how FluxDrop handles **your** data, see the Privacy Policy and Terms of
Service linked at the bottom right of [fluxdrop.me](https://fluxdrop.me/).

### About Immich

I don't provide the Immich server (`gallery.arseniusgen.dev`) to anyone except
a few selected users. Resources are limited, it makes no profit, and Immich
stores data unencrypted on disk, so I could technically see it. Please use
FluxDrop instead.

### History

The repo started in 2023 as the backend for my personal site on free FreeDNS
subdomains. FluxDrop began as my own file host inside it and grew into the main
project; most changes since then are for FluxDrop. I want its design to feel
"very human" and be open to anyone. The repo also served
[driveguard](https://github.com/ArsenijN/driveguard) (OTA updates; currently
stalled) and briefly hosted a friend's site, which now runs on its own server.

Everything now runs on proper HTTPS with **Let's Encrypt** certificates:
arseniusgen.dev, fluxdrop.me, arseniusgen.uk.to and arsenius-gen.uk.to.
(arsenius_gen.uk.to also works, but can't get a certificate because of the
underscore.)

Many thanks to Afraid FreeDNS for providing free subdomains for over two years.
They are what got me into running my own internet projects in 2023.

> **Q: Why didn't you use Let's Encrypt before?**
>
> A: I only owned a subdomain from [FreeDNS](https://freedns.afraid.org/subdomain/),
> not a domain, and many other people used uk.to subdomains too. In 2023
> `certbot` refused with "too many certificates already issued for this
> domain", so self-signed certificates were the only option. By 2026 the
> domain's usage had dropped (uk.to may now be a stealth domain that only
> existing users can use), and the certificates were issued without problems.

---

## Installation

Full instructions are in the **[Wiki](https://github.com/ArsenijN/server/wiki)**:
[Prerequisites](https://github.com/ArsenijN/server/wiki/Prerequisites) ·
[Installation](https://github.com/ArsenijN/server/wiki/Installation) ·
[Configuration](https://github.com/ArsenijN/server/wiki/Configuration) (every
setting) ·
[Deployment](https://github.com/ArsenijN/server/wiki/Deployment) ·
[Admin & Helpers](https://github.com/ArsenijN/server/wiki/Admin-and-Helpers) ·
[Troubleshooting](https://github.com/ArsenijN/server/wiki/Troubleshooting)

Short version:

- **Needs:** Python 3.14+ (developed on 3.14.3) on the server; Node.js + npm,
  `rsync` and `ssh` on your build machine.
- **Build** on your machine: `npm install` once, then `./build.sh`. Edit the
  frontend in `server/build/src`; `server/TestWeb` is regenerated on every
  build.
- **Deploy** with `./sync_to_server.sh` (set up `deploy.env` from
  `deploy.env.sample` first). It mirrors `server/` to the host, never touches
  `Web/secrets/`, and restarts the three services.
- **Configure** on the server: copy the samples from `Web/secrets_samples/`
  into `Web/secrets/` (git-ignored) and fill in `vars.env` and `smtp.env`.
  Don't set `HTTP_PORT` / `HTTPS_PORT` there — the CDN and the front servers
  read the same names (see the Configuration page).
- **Services:** edit `User=`, `WorkingDirectory=` and `ExecStart=` in
  `server/services/webserver-*.service`, copy them to `/etc/systemd/system/`
  and enable them.
- Check `https://<your-domain>/status` — it also shows the deployed version.

---

## Dev notes

### Upload temp directory

`UPLOAD_TMP_DIR` decides how uploads are written (see `core/upload.py`):

- **Different drive than the destination** (recommended): chunks are written
  straight into the pre-allocated destination file — no temp copies, no
  assembly step.
- **Same drive**: chunks are buffered in `UPLOAD_TMP_DIR` and copied into the
  destination when the upload finishes. On an HDD this means heavy head seeking
  and much slower processing.

The default is `/tmp/fluxdrop_upload_sessions`.

### Posting a notice

Notices live in the `message_board` table, so any post on the status page's
message board can become one. The intended flow is the status page admin panel
(bottom-right *Admin* pill → **Message Board**): post the announcement as usual,
then press 📢 on it, choose level/duration, optionally fill in the Ukrainian
text, and save. Press 📢 again on a live notice to edit it, or **Stop showing**
to pull it while keeping the board post.

Levels are `info`, `ok`, `warning`, `critical`. Only `critical` re-shows after a
user dismisses it; the rest are remembered per notice id in the visitor's
`localStorage`.

The same thing over the API, if you prefer scripting it:

```bash
TOKEN=<admin session token>

# Post, and show it as a notice for the next 6 hours
curl -X POST https://fluxdrop.me/api/v1/board \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"level":"warning","title":"Planned maintenance 02:00-04:00",
       "body":"Uploads are paused while the CDN restarts.",
       "show_modal":true,"expires_in_hours":6,
       "i18n":{"uk":{"title":"Планові роботи 02:00-04:00",
                     "body":"Завантаження призупинено на час перезапуску CDN."}}}'

# Promote an existing board post (id 42) without changing its text
curl -X PATCH https://fluxdrop.me/api/v1/board/42 \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"show_modal":true,"expires_in_hours":24}'

# What visitors currently get (no auth)
curl -s https://fluxdrop.me/api/v1/notice

# Stop showing it (the board post stays)
curl -X PATCH https://fluxdrop.me/api/v1/board/42 \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"show_modal":false}'
```

Omit both `expires_in_hours` and `expires_at` and the notice stays up until you
stop it. `expires_at` is UTC `YYYY-MM-DD HH:MM[:SS]`, matching how SQLite stores
`CURRENT_TIMESTAMP`. Sending `"expires_at": null` or `"i18n": null` on a PATCH
clears that field.

### Helper scripts

Run from `Web/` with the venv active:

| Script | Purpose |
|---|---|
| `.helper-list_users.py [--db path]` | List accounts (incl. admin flag and quota) |
| `.helper-check_user_password.py <user> <pass>` | Check a password; reports which hash scheme matched |
| `.helper-set_user_password.py <user> <pass>` | Reset a password; logs out all sessions |
| `.helper-generate_token.py <user> <pass> <path>` | Mint a download token and print its URL |

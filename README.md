# FluxDrop & server `v0.21.1.6`
Self-hosted file hosting (FluxDrop) plus the rest of my home server, in one
repo. Anyone can use it.

## What's new
> **In short:** ...

### FluxDrop (UI)
**Added**
- ...

**Changed**
- ...

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

### Server (backend)
**Added**
- ...

**Fixed**
- ...

### Known issues
- ...

### Housekeeping
- Moved the finished "Background hashsums" entry to the Done part of `TODO.md`
- Updated the `README.md` layout

<details>
<summary>Older releases</summary>

Short one-line summaries of previous versions, or a link to CHANGELOG.md /
git tags — optional.

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

### Prerequisites
- Python 3.14+ (developed and tested on 3.14.3)
- `pip`
- ImageMagick (`sudo apt install imagemagick libmagickwand-dev`) — for email
  icon embedding
- Node.js + npm — for rebuilding Tailwind CSS and the locale bundle if you
  change the frontend

### 1. Clone the repository (on your build machine)
```bash
git clone https://github.com/ArsenijN/server
cd server
```

### 2. Build the frontend
```bash
./build.sh
```
Checks the locale files, regenerates the locale bundle, builds Tailwind CSS
and syncs `server/build/src` → `server/TestWeb`.

### 3. Create a virtual environment (on the server)
```bash
python3.14 -m venv /opt/venvs/site_web   # matches the path in the .service files
source /opt/venvs/site_web/bin/activate
pip install -r requirements.txt           # from the deployed Web/ directory
```
Any path works — just update `ExecStart=` in the `.service` files to match.

### 4. Configure secrets

Sensitive data (database, SMTP credentials, TLS keys, blacklist) lives in
`server/Web/secrets/`, which git **ignores** and deploys never overwrite.
Samples are in `server/Web/secrets_samples/`:
```bash
cp secrets_samples/credentials_local.env.sample secrets/credentials_local.env
cp secrets_samples/smtp.env.sample               secrets/smtp.env
cp secrets_samples/myCA.pem.sample               secrets/myCA.pem   # replace with real cert
cp secrets_samples/myCA.key.sample               secrets/myCA.key   # replace with real key
cp secrets_samples/blklst.txt.sample             secrets/blklst.txt
```
`config.py` loads `KEY=VALUE` pairs from these files automatically.

Key variables (in `secrets/vars.env`):

| Variable | Description | Example |
|---|---|---|
| `PUBLIC_DOMAIN` | Your public hostname | `example.com` |
| `SERVE_ROOT` | Root of the CDN/media volume | `/srv/fluxdrop/cdn` |
| `SERVE_DIRECTORY` | Root of the static web files | `/srv/fluxdrop/site/TestWeb` |
| `UPLOAD_TMP_DIR` | Temp dir for upload chunks — put it on a **different drive** than `SERVE_ROOT` (ideally an SSD), see below | `/mnt/ssd/fluxdrop_upload_sessions` |
| `HTTP_PORT` | HTTP listen port | `63512` |
| `HTTPS_PORT` | HTTPS listen port | `64800` |

The background hash scanner has its own settings (`BG_SCAN_*`); see the
comments above `_bg_crc32_scanner` in `server_cdn.py`.

### 5. Install the systemd services

The `.service` files in `server/services/` use the author's user and paths
(`User=arsen`, `WorkingDirectory=/home/arsen/...`). Edit `User=`,
`WorkingDirectory=` and `ExecStart=` to match your setup first, then:
```bash
sudo cp ../services/webserver-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now webserver-http webserver-https webserver-cdn
```

### 6. Check the logs
```bash
journalctl -u webserver-cdn -f
journalctl -u webserver-https -f
```

---

## Keeping the server up to date

`sync_to_server.sh` mirrors your local `./server` tree to the host and
restarts all three services:
```bash
./sync_to_server.sh
```

- SSH `ControlMaster` multiplexing means your passphrase is asked only once.
- `secrets/` is **always excluded**, so live credentials and the SQLite
  database are never overwritten.
- To avoid a sudo prompt each time, either allow passwordless sudo for
  `systemctl restart` on the remote, or set `NO_SUDO_PROMPT=1` (uses `sudo`
  without `-S`, so you need an active sudo session there already).

Check the deployed version on the status page: `https://<your-domain>/status`.

Over time, old files from earlier versions can pile up in `Web/`. To clean up,
wipe the `Web/` folder **except `secrets/`** and deploy again. Be careful with
`rm -rf` here — deleting `secrets/` loses all credentials and the user
database.

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

# FluxDrop & server `v0.22.0.14`
Self-hosted file hosting (FluxDrop) plus the rest of my home server, in one
repo. Anyone can use it.

## What's new
> **In short:** fixes for pausing, resuming and cancelling uploads; previews
> for big `.tar.gz` archives and for files inside trashed folders; ZIP
> downloads stop hashing when cancelled; FluxDrop now lives only on
> fluxdrop.me (old domains redirect there); uploading a file with a name
> that already exists no longer destroys the old file — you choose: keep
> both, replace or skip, and can compare the two first.

### FluxDrop (UI)
**Added**
- Files inside a trashed folder can be previewed: click a file in the
  folder's "Browse" list
- Previewing a large `.tar`/`.tar.gz` shows progress while the server reads
  it, and a note when the list was cut short

**Changed**
- Files under 25 MB skip the upload speed test: they reuse the speed of a
  recent upload, or use small 1 MB chunks that are safe on slow connections
- Cancelling a ZIP download that is still being prepared tells the server to
  stop
- The trash "Browse" list shows files under their folders
- More of the UI is translated: the Uploads/Downloads trays, the Info
  panel, the Move/Rename/Copy dialog, the copy toast and archive preview
- A ZIP that the server is still preparing shows "Building archive…"
  instead of "Downloading via browser…"
- When an uploaded file's name already exists, a dialog asks: **Keep
  both**, **Replace** (the old file goes to the Trash once the new one is
  uploaded) or **Skip**, with both sizes and dates and a **Compare
  contents** button (SHA-256 of both). The default is in Settings →
  Transfer tray
- Resuming an upload shows "Checking with the server…" while it asks which
  chunks arrived
- The archive preview's header and Download button are translated
- See [TESTING.md](./TESTING.md) for what still needs checking

**Fixed**
- Pausing and resuming an upload could skip chunks, so it failed with
  "Missing chunks". Resume now asks the server which chunks it is missing and
  sends only those, and checks again before finishing
- Cancelling a paused upload stayed on "Cancelling…" forever
- Pausing while a chunk was being retried cancelled the whole upload
- The loading spinner could keep running hidden behind the app
- Resuming the same upload twice from "Interrupted" left a second tray row;
  its Cancel then failed with 409 and showed "Cancelled" for a finished
  upload
- Esc didn't close the Trash
- The archive preview spinner restarted on every progress update
- File names in the trash "Browse" list, the ZIP "skipped files" list and
  the audio preview weren't escaped

### Server (backend)
**Added**
- `CATBOX_API_ENABLED` — set to 0 to switch the CatBox API off; uploaded
  files stay downloadable
- `/api/v1/trash/<id>/file?path=<sub/path>` streams a file inside a trashed
  folder (checked to stay inside it)
- `DELETE /api/v1/zip_status/<job>` cancels a ZIP job
- Archive listings (`/api/v1/archive_tree`) are cached on disk. `.tar(.gz)`
  is read by a low-priority background worker (202 + progress until ready),
  also right after it's uploaded. Zip-bomb limits: max entries, time and
  compression ratio (`ARCHIVE_TREE_*` settings)
- `FRONT_HTTP_PORT` / `FRONT_HTTPS_PORT` for the front servers
- `on_conflict` for `upload_session/init`: `rename` (default), `ask` (200
  with `conflict: true` and the existing file's size and mtime; no
  session is created) or `replace` (uploads under a
  hidden temporary name; on completion the old file goes to the Trash).
  Share uploads always rename
- `FLUXDROP_LEGACY_HOSTS`: FluxDrop pages, shares and API on the old
  domains (arseniusgen.uk.to, arseniusgen.dev) redirect to `PUBLIC_BASE_URL`

**Changed**
- CatBox `urlupload` fetched any URL for anyone, without a login, and
  published the response — a way to reach internal addresses (the LAN, the
  CDN's loopback port) through the server. It's disabled; downloading
  external URLs will come back as a separate service
- The build no longer makes a new cache version when nothing changed: the
  locale bundle's "Generated" timestamp alone changed the hash, so every
  build made visitors re-download the app
- ZIP downloads: one job per folder (a second request or Resume joins it); a
  job stops when its page stops polling for `ZIP_JOB_IDLE_STOP` seconds (20),
  even in the middle of a file, keeps the hashes done so far and continues
  when polled again
- HTTP→HTTPS redirects go to the host and port of `PUBLIC_BASE_URL`; they
  used the CDN's port (64800) and sent `/api/` to the main domain
- `wand` and `requests` removed from `requirements.txt` (nothing uses them)
- The archive listing cache is keyed by the file's content (size, mtime,
  first/last 64 KB) instead of its path, so copies, moves and renames reuse
  it. Existing cache entries no longer match and are read again once

**Changed (breaking)**
- 

**Fixed**
- Uploading a file with the same name as an existing one wrote over it
  from the first byte, and cancelling deleted it, so both were lost. The
  new file is now saved as `name (1).ext` (also when another unfinished
  upload uses that name)
- Unfinished upload sessions were purged 2-3 hours early (local time
  compared with UTC)
- Previewing a 1.6 GB `.tar.gz` failed with HTTP 502 (the proxy gave up
  while the whole archive was decompressed)

### Known issues
- The upload, ZIP, archive and trash fixes above still need testing on the
  live server
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
  For the front servers' ports use `FRONT_HTTP_PORT` / `FRONT_HTTPS_PORT`;
  `HTTP_PORT` / `HTTPS_PORT` there would reach the CDN too (see the
  Configuration page).
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

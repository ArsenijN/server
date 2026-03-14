# TODO

This file collects planned enhancements for FluxDrop.  Many items arise from
user feedback or ideas for future development.

- [x] **Frontend input escaping**: ensure `'`, `"`, `?`, etc. are handled
  correctly in UI (paths encoded when building URLs, onclick handlers
  use `JSON.stringify`).
- [x] **Shareable links**
  - Generate public URLs that allow downloading a file (or browsing a
    folder) without requiring the recipient to log in.
  - Support one‑time links and expiring links.
  - Provide a management UI where a user can view/revoke their shared items.
  - Folder shares should open a FluxDrop-style directory browser for the
    recipient.
- [x] **CDN access restriction**
  - Do not expose directory listings when no auth token is present; return
    403 or empty result. - result: FluxDrop user's files are safe from direct
    access without proper auth
  - Provide a little script/CLI command to generate per-file access tokens.
- [x] **Safe download links**: use special tokens to download the files, not
  the user token
- [x] **Add the ETA for uploads**: similar to the download ETA — floating
  upload tray with progress bar, speed and ETA
- [x] **Fix for mail that have no icon**: FluxDrop emails now embed the icon
  as a transparent inline PNG (rasterised via wand/ImageMagick); works in Gmail
- [x] **Fix expired pending registrations blocking re-registration**
- [x] **Hosting links / streaming support**
  - Similar to share links but intended for embedding (useful for
    video/audio playback) with optional bandwidth throttling or expiry.
- [x] **Security hardening** (see `fluxdrop_audit.md` for full details —
  required before public/production release)
  - [x] Rate limiting on `/auth/login` and `/auth/register` (brute-force
    protection)
  - [x] Upload size cap (both FluxDrop API and public share upload)
  - [x] JSON body size cap on all POST endpoints
  - [x] Enforce IP blacklist in `server_cdn.py` (currently only in
    `server_http.py` and `server_https.py`)
  - [x] Periodic session table cleanup (expired rows accumulate forever) -- fixed?
  - [x] Migrate password hashing from SHA-256 to bcrypt or argon2
- [x] **HTML modularisation** — move inline HTML snippets out of
  `server_cdn.py` into a `snippets/` folder with a `snippets.py` loader
  (see `fluxdrop_audit.md` Part 2 for the full design)

- [x] **Server stability dashboard** — detailed window showing internet,
  services and features outages, planned works or unexpected issues
  (aka DownDetector)

---

- [ ] **Tree download** — allow downloading an entire folder as a `.zip`
  archive from the API.

- [ ] **Family/Group accounts**
  - Let two or more usernames share a common root directory with mutual
    read/write privileges.
  - Add settings to control whether group members may add/remove other
    users, set quotas, etc.



- [ ] **Tailwind CSS — production build** — replace the CDN `<script>` with
  a proper build step so unused classes are purged and there is no
  runtime compilation.

- [ ] **Legacy usage without JS** — at minimum, users should be able to
  download shared files without JavaScript enabled.

- [ ] **Misc future ideas**
  - Per-user quotas and storage statistics.
  - Server-side filename sanitisation for illegal characters.
  - Explicit **move** and **copy** endpoints (avoid awkward rename paths).
  - **Folder size** in directory listings (sum of contained file sizes)
    for quota display.
  - Replace Tailwind CDN with a build step for production CSS.

- [ ] Fix `status` page have inconsistent times
- [ ] Fix `status` page have inconsistent items
- [ ] Add placeholder items to avoid UI flash, like YouTube or other services have when client doesn't have enough speed to fetch the proper data
- [ ] Fix every FluxDrop snippet (UI) to work properly with mobile and non-16:9 screens
- [x] Fix the upload feature that are now broken
- [x] Test if `/status` will display the actual server outages (like when it doesn't work or got restarted and doesn't worked for few seconds)
- [x] Add message board to `/status` to add infos of something was broken and server outage was long
- [x] Add automatic details tab about the outages (like why server considered that it was outaged)
- [x] Add ability to see per-day details of outages (line graph or similar to the uptime history)
- [x] Add error catchers, embed to the server reliability history (like what was wrong and why happened)
- [ ] Add checkers for external HTTP and HTTPS hosters
- [ ] Add fallback page for `/share` without token
- [x] Fix the cancelation of upload
- [ ] Fix the possible performance issues with server, use multithread for downloads with legacy support
- [x] ~~Fix the possible performance issues with server, use multithread for uploads with legacy support?~~ -- can't be sure it's compliant with the legacy support, but at least it works beautifully
- [ ] Merge (or forward) HTTP and HTTPS hoster's regular ports with CDN's ports for more ideal links and simplicity
- [ ] Add quota for user
- [x] Make admin account or admin access via configs or account or commands
- [ ] Add more settings that can be managed via site with admin account
- [ ] Check for the safety measures for admin-related things
- [ ] Add manager for the non-finished uploads (window)
- [x] Fix the issue with FluxDrop preview link manager: in some edge case, FD downloads the HTML page instead of file content -- doesn't appear for now @20260308
- [x] Declare current server version as `v0.7.0`
- [x] ~~Avoid regression in server code files since I now can be confused with versioning system since code can be somewhere outdated; if not - just reapply new features to the code back~~ - avoided
- [ ] By some reason browser almost always displays the "hover link" `arseniusgen.uk.to/fluxdrop_pp/index.html#`, whenewer mouse was on the button or background - fixes by going out of the site, and same link regularly appears on the buttons
- [ ] Add the HEIC, AVIF support for previews
- [ ] Add PDF preview
- [ ] Add plain text preview (.ini already there)
- [ ] Add Markdown previews with proper formatting
- [ ] Add .zip, .tar.gz, and so on support for previews (at least file table)
- [ ] Add .docx, .pptx, .odt, .odf, .ods, and so on documents
- [ ] Make special player with "video preview support", aka "slow internet mode" (re-convert the uploaded videos to the FluxDrop with AV1 to reduce bandwidth and resolution)

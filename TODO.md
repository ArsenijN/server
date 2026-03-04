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

---

- [ ] **Security hardening** (see `fluxdrop_audit.md` for full details —
  required before public/production release)
  - [ ] Rate limiting on `/auth/login` and `/auth/register` (brute-force
    protection)
  - [ ] Upload size cap (both FluxDrop API and public share upload)
  - [ ] JSON body size cap on all POST endpoints
  - [ ] Enforce IP blacklist in `server_cdn.py` (currently only in
    `server_http.py` and `server_https.py`)
  - [ ] Periodic session table cleanup (expired rows accumulate forever)
  - [ ] Migrate password hashing from SHA-256 to bcrypt or argon2

- [ ] **HTML modularisation** — move inline HTML snippets out of
  `server_cdn.py` into a `snippets/` folder with a `snippets.py` loader
  (see `fluxdrop_audit.md` Part 2 for the full design)

- [ ] **Tree download** — allow downloading an entire folder as a `.zip`
  archive from the API.

- [ ] **Family/Group accounts**
  - Let two or more usernames share a common root directory with mutual
    read/write privileges.
  - Add settings to control whether group members may add/remove other
    users, set quotas, etc.

- [ ] **Server stability dashboard** — detailed window showing internet,
  services and features outages, planned works or unexpected issues
  (aka DownDetector)

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

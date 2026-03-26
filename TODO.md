# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

---

- [ ] **Tree download** — allow downloading an entire folder as a `.zip`
  archive from the API.

- [ ] **Family/Group accounts**
  - [ ] Let two or more usernames share a common root directory with mutual
    read/write privileges.
  - [ ] Add settings to control whether group members may add/remove other
    users, set quotas, etc.

- [ ] **Legacy usage without JS** — at minimum, users should be able to
  download shared files without JavaScript enabled.

- [ ] **Misc future ideas**
  - [ ] Per-user quotas and storage statistics.
  - [ ] Server-side filename sanitisation for illegal characters.
  - [ ] Explicit **move** and **copy** endpoints (avoid awkward rename paths).
  - [ ] **Folder size** in directory listings (sum of contained file sizes)
    for quota display.

- [ ] Add sorting in file manager (by name, size, date of modify; folders first, treat folders as files (sorting))
- [ ] Improve user iterations by adding auto-reconnect on dropped connection (e.g. switched networks)
- [ ] Add file info modal
  - [ ] Basics (file modify, size)
  - [ ] Hash sums (do it via `nice` so it will execute when server isn't fully utilized, or as background thing)
    - [ ] Use those hashes as filechecks for background activity
      - [ ] Add parchives to avoid file damages
      - [ ] Add some kind of messages if files got corrupted on server side and was unrecoverable 
- [ ] Auto-login on token expiry
- [ ] Sand off the UI and textes, fix small inconsistences in UI (like on rename function)
- [ ] i18n support (language changes)
- [ ] Add handler to show when internet connection drops (upload/download)
- [ ] Shares that will work after file move/folder rename/file rename
- [ ] (not necessary) Divide snippets to dedicated HTML, JS and CSS
- [ ] Fix every FluxDrop snippet and site (UIs) to work properly with mobile and non-16:9 screens
- [ ] Add checkers for external HTTP and HTTPS hosters
- [ ] Improve server download speeds by use of multithreaded function
- [ ] Merge (or forward) HTTP and HTTPS hoster's regular ports with CDN's ports for more ideal links and simplicity
- [ ] Add usable space quota for user
- [ ] Add "profile" to check current used quota, subscribtion info, change of the password, etc.
- [ ] Add quota info to mini-profile menu
- [ ] Add more settings that can be managed via site with admin account
- [ ] Add the HEIC, AVIF support for previews
- [ ] Add PDF preview
- [ ] Add plain text preview (.ini already there)
- [ ] Add Markdown previews with proper formatting
- [ ] Add .zip, .tar.gz, and so on support for previews (at least file table)
- [ ] Add .docx, .pptx, .odt, .odf, .ods, and so on documents
- [ ] Make special player with "video preview support", aka "slow internet mode" (re-convert the uploaded videos to the FluxDrop with AV1 to reduce bandwidth and resolution)

- [ ] Add landing page for FluxDrop
- [ ] Add ToS and PP docs
- [ ] Make proper header and footer for the main FluxDrop UI
- [ ] Make an mobile version of the FluxDrop as an app or as an installable app via Chrome
- [ ] Add autoupdate "agreement" (when newer ToS or PP appears - user must accept it within)
- [ ] Discover ways to build own page via modules (zero-code; not necessary since I can just remember CSS and HTML, and do that by hands)
- [ ] Add "proper" loading wheels (1 second as least amount of time for the "apply" and other important features, more pleasant loadings for the file manager)
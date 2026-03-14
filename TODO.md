# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.


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
- [ ] Fix upload speed measurements was inconsistent
- [ ] Add placeholder items to snippets and FluxDrop site to avoid UI flash, like YouTube or other services have when client doesn't have enough speed to fetch the proper data
- [ ] Divide FluxDrop site to dedicated HTML, JS and CSS
- [ ] Fix every FluxDrop snippet (UI) to work properly with mobile and non-16:9 screens
- [ ] Add checkers for external HTTP and HTTPS hosters
- [ ] Add fallback page for `/share` without token
- [ ] Improve server download speeds by use of multithreaded function
- [ ] Merge (or forward) HTTP and HTTPS hoster's regular ports with CDN's ports for more ideal links and simplicity
- [ ] Add usable space quota for user
- [ ] Add "profile" to check current used quota, subscribtion info, change of the password, etc.
- [ ] Add quota info to mini-profile menu
- [ ] Add more settings that can be managed via site with admin account
- [ ] Check for the safety measures for admin-related things
- [ ] Add manager for the non-finished uploads (window)
- [ ] By some reason browser almost always displays the "hover link" `arseniusgen.uk.to/fluxdrop_pp/index.html#`, whenewer mouse was on the button or background - fixes by going out of the site, and same link regularly appears on the buttons
- [ ] Add the HEIC, AVIF support for previews
- [ ] Add PDF preview
- [ ] Add plain text preview (.ini already there)
- [ ] Add Markdown previews with proper formatting
- [ ] Add .zip, .tar.gz, and so on support for previews (at least file table)
- [ ] Add .docx, .pptx, .odt, .odf, .ods, and so on documents
- [ ] Make special player with "video preview support", aka "slow internet mode" (re-convert the uploaded videos to the FluxDrop with AV1 to reduce bandwidth and resolution)

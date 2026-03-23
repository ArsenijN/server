# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.


- [x] **Tailwind CSS — production build** — replace the CDN `<script>` with
  a proper build step so unused classes are purged and there is no
  runtime compilation.

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
  - [x] Replace Tailwind CDN with a build step for production CSS.

- [x] Check the performance of the file check on the server (filehash checksums after uploads)
- [x] Check for the safety measures for admin-related things (I think for now it's ok)
- [ ] Links are auto-copied on creation in share menu
- [ ] Fix issue when browser almost always displays the "hover link" `arseniusgen.uk.to/fluxdrop_pp/index.html#`, whenewer mouse was on the button or background - fixes by going out of the site, and same link regularly appears on the buttons (after it stops the first issue)
- [ ] Sand off the UI and textes, fix small inconsistences in UI (like on rename function)
- [ ] i18n support (language changes)
- [ ] Add support from browser to switch between states (I mean... what I mean by that)
- [ ] Add support for internet interruption (auto-continue)
- [ ] Add handler to show when internet connection drops
- [ ] Shares that will work after file move/folder rename/file rename
- [x] Fix upload speed measurements was inconsistent
- [ ] Add placeholder items to snippets and FluxDrop site to avoid UI flash, like YouTube or other services have when client doesn't have enough speed to fetch the proper data
- [ ] (not necessary) Divide snippets to dedicated HTML, JS and CSS
- [ ] Fix every FluxDrop snippet and site (UIs) to work properly with mobile and non-16:9 screens
- [ ] Add checkers for external HTTP and HTTPS hosters
- [x] Add fallback page for `/share` without token
- [ ] Improve server download speeds by use of multithreaded function
- [ ] Merge (or forward) HTTP and HTTPS hoster's regular ports with CDN's ports for more ideal links and simplicity
- [ ] Add usable space quota for user
- [ ] Add "profile" to check current used quota, subscribtion info, change of the password, etc.
- [ ] Add quota info to mini-profile menu
- [ ] Add more settings that can be managed via site with admin account
- [ ] Add manager for the unfinished uploads (window)
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
- [ ] Improve user iterations by adding auto-reconnect on dropped connection (e.g. switched networks)
- [ ] Add the detailed (with ETA) info about the file check on the server side (no long waits without any feedback of what does server do)
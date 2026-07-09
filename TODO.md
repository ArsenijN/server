# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

---

## Items that are pending for implementations:

### Important without category (critical before release)

### UI - add new features
- [ ] Markdown parser does not understand:
  - [ ] `***` following with the new lines inside the text and then `***` again 
  -- still does not understand, aka there:
  ```
  ***This is an example Markdown text
  that is broken with current text
  parser, and will not end with proper formatting.***
  ```
  ```
  ***This is an example of the text that
  is not broken with current text parser.***
  ```
  ```
  ***This is also example of not broken text***
  ```
  Following text does not have a problems:
  ```
  ***Also, in the time of the server optimizations, we are managed to bump the 
  download speeds to the mindblowing 2x times! Right now, our hardware can handle 
  up to 40 MB/s download speeds, that's 2x times faster than the older code!***

  ***Important note: if you want, you can try to use HTTP endpoints of our 
  services to reach the theoretical 100 MB/s speeds. The problem is that our 
  hardware is old enough to struggle at encryptions, e.g. `AES` for HTTPS. For 
  even faster speeds, we have made attempts to add the 
  `TLS_CHACHA20_POLY1305_SHA256` as secondary main hashing algorithm for HTTPS, 
  but it may fallback to `AES` and cause slower speeds***

  ***For developers and testers:***
  ```
- [ ] Add MIDI and modules player (tracker music). Inspired by modarchive.org
- [ ] Make proper header and footer for the main FluxDrop UI
- [ ] Add "landing page" for CatBox API to use it from the browser, and also
- [ ] Add "CatBox API usage" page for CatBox API

### UX - fixes for existing features or new overall experience enhancements
- [ ] Make file info modal able to work as "turn on and stay until closed": 
toggle in settings to change this behavior; works as file info modal that 
doesn't close when user clicks outside of it
- [ ] Add multiple files streaming (archive and stream to the server; one 
stream - a lot of files) feature to site UI from `batch_tar_upload.py`
- [ ] Make file upload multithreaded (2+ files processing simultaneously on 
upload)
- [ ] Make an mobile version of the FluxDrop as an installable app 
via Chrome or as "native" Android Material Design one
- [ ] Make AJAX-like updates for the file manager (no visual reloads of the 
content) -- file manager, ...
- [ ] Add ability to preload the JPEG/any current format for previews like AVIF 
and for other files (contribute to the background media scan via FFmpeg)
- [ ] Check why HEIF files are slow to decode (on client, it takes ~5 seconds 
on i5 8350U)
- [ ] Add `.7z`, `.rar` and other archive types for file table previews
- [ ] Add `.docx`, `.pptx`, `.odt`, `.odf`, `.ods`, and other for previews
- [ ] Add `.dng` and other raw image formats support for previews
- [ ] **Family/Group accounts**
  - [ ] Let two or more usernames share a common root directory with mutual
    read/write privileges.
  - [ ] Add settings to control whether group members may add/remove other
    users, set quotas, etc.
- [ ] **Misc future ideas**
  - [ ] Server-side filename sanitisation for illegal characters.
  - [ ] Explicit **move** and **copy** endpoints (avoid awkward rename paths).
- [ ] Fix i18n in:
  - [ ] Actions modal
  - [x] Shared links remainings
    - [ ] "CDN Embed..." not fixed
    - [ ] operation type (e.g. `download`, `view`, `embed`, etc.)
    - [ ] Expired [date]
    - [ ] "📊 Stats: [folder name]"
  - [ ] Error-related pages -- untested
  - [ ] Translate the `⚠ Due to server capacity demand, new items are kept for 
  7 days. Retention will return to 30 days once space is freed.` (not i18n, 
  rather l10n issue with missing key -- no, it's i18n)
- [ ] Add more animations to:
  - [ ] Closing the profile menu
  - [ ] File selection (checkmark appearance and disappearance)
  - [ ] `fd-sel-bar` animations of appearance and disappearance
  - [ ] `profile-panel-overlay` closing
  - [ ] `share-manager-overlay` closing
  - [ ] `trash-overlay` closing
- [ ] Add loading wheels/bars/things to:
  - [ ] Stats button for shared links manager
  - [ ] Profile infos
- [ ] Add caching for:
  - [ ] Profile picture
- [ ] Add compression for:
  - [ ] JSON responces that are large
  - [ ] `.md` files
- [ ] Upload ends successfully even if the upload of one of the files fails 
(for example because of the quota)
- [ ] Downloading the ZIP doesn't show the actual thing that happening behind 
the scene (aka it just shows "Downloading via browser...")
- [ ] Status page doesn't updates fully (e.g. uptime)
- [ ] Status page doesn't load the amount of files on server on first load

### Server-side changes:

#### Critical:
- [ ] Sometimes FluxDrop makes config connections, resulting in 404, but right 
now I can't replicate it so I don't know why and I can't give any clues when 
that happens and after what -- they are caused on network switch
- [ ] Trash bin file preview inside folders
- [ ] Hash are not moved/re-attached to a file after move
- [ ] Maybe cancel the file hashing or avoid the ~~async~~ multithreaded file 
hash after canceling the ZIP download, or do it only if server is unused or via 
`nice`

#### High:
- [ ] Ability to download the shared folders without JS (fallback option)
- [ ] Update the helpers functionality
- [ ] Document the new proxy method that is currently used with my Immich 
instance
- [ ] Check code for security flaws/vulnerabilities
- [ ] Background hashsums (do it via `nice` so it will execute when server 
isn't fully utilized, as background thing) -- make it as improvement for the 
current `maintenance window`
  - [ ] Use those hashes for silent file check activity in background -- 
  specifiable time period in server config
    - [ ] Add parchives to avoid file damages on server
    - [ ] Add some kind of messages if files got corrupted on server side and 
    was unrecoverable

#### Medium:
- [ ] Make caching or optimize the quota size counting for reducing the time 
that is needed to process the 150k+ items -- made for status page, later for 
FluxDrop file manager
- [ ] Update the services (and exclude the entry in the `.gitignore`)
- [ ] Add hash (maintenance) logs to the debug category for main log file (keep 
the separate file work always)
- [ ] Fix CSP for used domain other than `PUBLIC_DOMAIN` (e.g. accessing 
FluxDrop from fluxdrop.me, and it loads the link relative to arseniusgen.uk.to 
as specified in `PUBLIC_DOMAIN`)

#### Low:
- [ ] Reduce amount of re-imports inside the code if this will add overall 
overhead
- [ ] Add server ability to push the additional data before client will request 
them (pre-caching; like folder structures, quota, file properties, download 
tokens (pre-generate the download tokens for files to fasten up the ping 
issues (aka preview tokens), or resolve the issues that FluxDrop is very 
unstable in bad internet areas) or something else) -- merged into the rela... 
No it's not since that entry issues the JSON multi-answer instead on only 
related to fetch/question
- [ ] Add checkers for external HTTP and HTTPS hosters
- [ ] Add "enhanced" previews (bg activity that makes thumbs via FFmpeg for 
any type of file that's supported, thumbs can be included into the quota, or 
excluded from quota)
- [ ] Add partial content support for CatBox API and CDN itself for it's 
static hoster -- doesn't CDN have that already?
- [ ] Make special player with "video preview support", aka "slow internet 
mode" (re-convert the uploaded videos to the FluxDrop with AV1 to reduce 
bandwidth and resolution)
- [ ] Reimplement the CDN path purpose, fix it's errors

#### Lowest:
- [ ] Make separate "testing" server where I would be able to test everything 
before pushing to the real one
- [ ] Migration to other host platform for HTTP and HTTPS efficiency and 
optimizations (Python; go to gunicorn or something else) -- WIP, low priority
- [ ] (future) Replace the server hardware (aka FluxDrop + home NAS with proper 
storage media)
- [ ] (at some unnecessary point) Divide snippets to dedicated HTML, JS and CSS
- [ ] Discover ways to build own page via modules (zero-code; not necessary 
since I can just remember CSS and HTML, and do that by hands)

---

## Items that needs additional checks or implementations:
- [ ] Missing ZIP's files may be never displayed on client
- [ ] Check the acceptance modal loader on slow internet when new terms will be 
made/applied
- [ ] Dark mode auto switch
- [ ] HSTS redirect should work correctly
- [x] Add the visualization for retry cycles -- should be added, need testing

---

## Done items that are pending for removal as finished:
(end of release note there)

- [x] Add file info modal



---

*Note: **the "Done items that are pending for removal as finished" will purge 
the entries inside it when the release version will be ready and released***

*Note: **additional notes is now moved to the [DEVNOTES.md](/DEVNOTES.md), 
please reach to it to acknowledge those notes***
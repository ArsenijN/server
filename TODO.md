# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

---

- [ ] **Family/Group accounts**
  - [ ] Let two or more usernames share a common root directory with mutual
    read/write privileges.
  - [ ] Add settings to control whether group members may add/remove other
    users, set quotas, etc.

- [ ] **Legacy usage without JS** — at minimum, users should be able to
  download shared files without JavaScript enabled.

- [ ] **Misc future ideas**
  - [ ] Server-side filename sanitisation for illegal characters.
  - [ ] Explicit **move** and **copy** endpoints (avoid awkward rename paths).

- [ ] Optimize FluxDrop for mobile screens, regular 16:9 and other aspect 
ratios, later on make an mobile version of the FluxDrop as an installable app 
via Chrome or as "native" Android Material Design one
- [ ] Fix every FluxDrop snippet and site (UIs) to work properly with mobile 
and non-16:9 screens
- [ ] Trash bin folder preview
- [ ] Make caching or optimize the quota size counting for reducing the time 
that is needed to process the 150k+ items
- [ ] Add server ability to push the additional data before client will request 
them (pre-caching; like folder structures, quota, file properties, download 
tokens (pre-generate the download tokens for files to fasten up the ping 
issues (aka preview tokens), or resolve the issues that FluxDrop is very 
unstable in bad internet areas) or something else)
- [ ] Fix CSP making bad things to the snippets (I assume; for IP Beacon at 
least - since it shows the CSP doing it's work)
- [ ] Test why quota can't be changed (at least in dynamic mode, caused by 
dynamic insufficient free space at the CDN drive?)
- [ ] Add quota "space analyzer" (like WizTree or Filelight or whatever - it 
will display what files takes the most, where and what)
- [ ] Fix issues with resuming the download (in FluxDrop file manager at least)
- [ ] Make download work as chunk-based in FluxDrop UI, keeping the regular 
octet-stream for legacy usage
- [ ] Add self-resume on network switch (offline handler shows and hides, but 
download doesn't continue)
- [ ] Fix HSTS redirects for FluxDrop file manager (currently doesn't work) -
means http to https on cdn (file manager) since login works ok (forwards to 
https) -- needs CDN migration to regular HTTP/HTTPS ports or single port to fix
- [ ] Add file streaming (archive and stream to the server; one stream - a lot 
of files) feature to site UI from `batch_tar_upload.py`
- [ ] Make AJAX-like updates for the file manager (no visual reloads of the 
content)
- [ ] Add file picker to file browser (checkbox-styled or as "click on the 
`border-t` to select one)
  - [ ] Add ability to use regular keyboard shortcuts (shift for multiple file 
  pick, ctrl to specific, ctrl+shift for multiple from latest pick with ctrl; 
  aka regular file browser behavior like on Windows)
  - [ ] Add ability to double-click on the `border-t` to open the file/folder
- [ ] Add loading wheel to the right of "Upload" button between prep and upload 
states - make it appear before new entry in `Uploads` or `Downloads` appears, 
also, bring the label to the static part so it will not scroll
- [ ] Add image placeholders between image fetch and display
- [ ] Check why HEIF files are slow to decode (on client, it takes ~5 seconds 
even on i5 10400)
- [ ] Add "enhanced" previews (bg activity that makes thumbs via FFmpeg for 
any type of file that's supported, thumbs can be included into the quota, or 
excluded from quota)
- [ ] Add folder downloads and size to the `share` snippet
- [ ] Auto negotiation for upload type (folder or file)
- [ ] Add dark theme switch, or at least make addons work properly and test 
them
- [ ] Add variable chunk sizes on demand for different internet speeds and 
optimizations
- [ ] Improve user iterations by adding auto-reconnect on dropped connection 
(e.g. switched networks) - this means semi-constant pings to the server on 
download or/and upload
- [ ] Add handler for dropped connection mid upload/download with relable way 
to tell it (via pings or continuous connections)
- [ ] Add file info modal
  - [ ] Basics (file modify time, size, etc.)
  - [ ] Background hashsums (do it via `nice` so it will execute when server 
  isn't fully utilized, as background thing)
    - [ ] Use those hashes for silent file check activity in background
      - [ ] Add parchives to avoid file damages
      - [ ] Add some kind of messages if files got corrupted on server side and 
      was unrecoverable 
- [ ] Sand off the UI and textes, fix small inconsistences in UI (like on 
rename function)
- [ ] i18n support (language changes)
- [ ] Add checkers for external HTTP and HTTPS hosters
- [ ] Merge (or forward) HTTP and HTTPS hoster's regular ports with CDN's ports 
for more ideal links and simplicity
- [ ] Add `.7z` and `.rar` for file table previews (and other ones)
- [ ] Add .docx, .pptx, .odt, .odf, .ods, and so on documents
- [ ] Make special player with "video preview support", aka "slow internet 
mode" (re-convert the uploaded videos to the FluxDrop with AV1 to reduce 
bandwidth and resolution)
- [ ] (not necessary) Divide snippets to dedicated HTML, JS and CSS


- [ ] Delete "CDN" path as it serves no purpose and doesn't work (line 5718 in 
`server_cdn.py`). Seems like it was made to make "shared" folder for any user 
of FluxDrop, but true usage is unknown since it's seems like undocumented and 
was introduced in one of the edit sessions without need to be made
- [ ] Test the dynamic quota with larger drive for CDN (after server config 
upgrade; line 6621)


- [ ] Make proper header and footer for the main FluxDrop UI
- [ ] Discover ways to build own page via modules (zero-code; not necessary 
since I can just remember CSS and HTML, and do that by hands)
- [ ] Add "proper" loading wheels (1 second as least amount of time for the 
"apply" and other important features, more pleasant loadings for the file 
manager)


- [ ] Make HTTP and HTTPS hosters work properly as standalone utilities without 
any FluxDrop and CDN
- [ ] Divide FluxDrop and HTTP/HTTPS hosters into separate repos


- [x] Migration to other host platform for HTTP and HTTPS efficiency and 
optimizations (Python; go to gunicorn or something else) - WIP
- [ ] (future) Replace the server hardware (aka FluxDrop + home NAS with proper 
storage media)


- [ ] Custom right-click menu


- [x] Add the ability of partial streaming on trash bin previews
- [ ] Fix 206 not working in trash bin preview
- [ ] Add progressbar for blob fetches
- [ ] Add "view background connectivity debug console" in settings to see small 
one-liner somewhere at the bottom of the UI that will say what site currently 
try to fetch or do (at least via Internet)
- [ ] Fix "Allow only FluxDrop users to upload" doesn't work as intended ( - 
expected to be so no one can upload to folder except the registered users on 
FluxDrop)
- [ ] Make upload settings as drop-out menu for choosing who actually can 
upload (anyone or only FluxDrop users)
- [ ] Add stats window loading wheel/bar since bad internet causes high wait 
times without knowing what it is doing
- [ ] Fix the background media playing if internet is very bad and seems like 
only when attempt to reach for file was made after the preview window is 
closed (internet hang)
- [ ] Make avatar support (pre-scale down to 64x64 px, compress via AVIF or JPG)
- [ ] Add fix for the timed out chunks causing full file reupload from the part 
where it's failed instead of pushing only the unloaded/wrong part of the file 
(aka reduce very large internet overhead)
- [ ] Add close by click on the dimmed space into the links manager
- [ ] Make "X" non-scrollable in links manager (so can be closed without need 
to scroll to the top)
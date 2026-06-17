# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

---

## Items that are pending for implementations:

### Important without category (critical before release)

### UI
- [ ] Markdown parser does not understand:
  - [ ] `***` following with the new line inside the text and then `***` again
- [ ] Add "landing page" for CatBox API to use it from the browser, and also
- [ ] Add "CatBox API usage" page for CatBox API
- [ ] Make proper header and footer for the main FluxDrop UI
- [ ] Add MIDI and modules player (tracker music). Inspired by modarchive.org
- [ ] Footer versioning: make versioning system the same as the current with 
server (like v0.17.2.4)
- [x] Add file info modal
  - [ ] Background hashsums (do it via `nice` so it will execute when server 
  isn't fully utilized, as background thing)
    - [ ] Use those hashes for silent file check activity in background
      - [ ] Add parchives to avoid file damages
      - [ ] Add some kind of messages if files got corrupted on server side and 
      was unrecoverable 
- [ ] Fix the i18n translating the breadcrumbs and some other things that it 
should not (like file and folder names, nicknames, etc.)
- [ ] Add the visualization for retry cycles

### UX
- [ ] Make the file info also work as turn on-off: is present on screen - show 
the infos for the selected (or last selected) file, on item change - change the 
display of infos
- [ ] Ability to download the shared folders without JS (fallback option)
- [ ] Make caching or optimize the quota size counting for reducing the time 
that is needed to process the 150k+ items -- made for status page, later for 
FluxDrop file manager
- [ ] Make an mobile version of the FluxDrop as an installable app 
via Chrome or as "native" Android Material Design one
- [ ] Add multiple files streaming (archive and stream to the server; one 
stream - a lot of files) feature to site UI from `batch_tar_upload.py`
- [ ] Make file upload multithreaded (2+ files processing simultaneously on 
upload)
- [ ] Make AJAX-like updates for the file manager (no visual reloads of the 
content)
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

### Server-side changes:

#### Critical:
- [ ] Add `debug` mode for the code like CDN and static hosters so they will 
not track some things to reduce the overhead time that is spent to write a log 
to a file
- [ ] Sometimes FluxDrop makes config connections, resulting in 404, but right 
now I can't replicate it so I don't know why and I can't give any clues when 
that happens and after what -- they are caused on network switch
- [ ] Trash bin file preview inside folders

#### Medium:
- [ ] Update the services (and exclude the entry in the `.gitignore`)

#### Low:
- [ ] Make separate "testing" server where I would be able to test everything 
before pushing to the real one
- [ ] Reduce amount of re-imports inside the code
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

---

## Done items that are pending for removal as finished:
(end of release note there)

- [x] Add ability to double-click on the `border-t` to open the file/folder
- [x] Instead of errors like "failed to fetch" after internet reconnect, 
ALWAYS catch it and DO NOT drop the hard error - RETRY until it IS successfull,
 or at least the N times (reliable way to resume whatever operation is going) 
 -- should be already fixed by resumable file downloads, but not after when 
 internet is resolved -- will be rephrased:
- [x] ~~Ensure that FluxDrop will retry whatever operation is failed because of 
the internet switch~~
- [x] Catch 'failed to fetch' errors - retry until success or N times (reliable 
resume). It should be already fixed for resumable downloads, but ensure it will
work after internet reconnect
- [x] Pause button may not work rn -- it's not but UI may bug so it can display 
"Missing chunks" but actually it then ends successfully -- check as fixed, 
needs retest
- [x] Client still can fail with Chunk timeout even with new retry attempts 
(uploads) -- check as fixed, needs retest
- [x] Add file info modal: Basics (file modify time, size, etc.)
- [x] Markdown parser does not understand: The tables
- [x] Markdown parser does not understand: The new line inside code blocks
- [x] Delete "CDN" path as it serves no purpose and doesn't work (line 5718 in 
`server_cdn.py`). Seems like it was made to make "shared" folder for any user 
of FluxDrop, but true usage is unknown since it's seems like undocumented and 
was introduced in one of the edit sessions without need to be made -- in the 
Terms and Policy, the same CDN may be mentioned with some explanatory of it's 
existence there -- aha! The CDN is made so user can separate it's drive and not 
clog the own drive with hosting materials, and also, I think that it can be 
easily managed via API (or will be). The next patch will change that "delete" 
to "implement" -- purge as reimplement the CDN purpose

---

*Note: **the "Done items that are pending for removal as finished" will purge 
the items inside it when the release version will be ready***

*Note: **additional notes is now moved to the [DEVNOTES.md](/DEVNOTES.md), 
please reach to it to acknowledge those notes***
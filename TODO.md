# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

---

- [ ] Fix plain text password and login (!!!)
> key to key password to server 
> kinda resolved via HSTS and HTTPS

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
via Chrome
- [ ] Review the `script.js` for comments, etc.
- [ ] Trash bin folder preview
- [ ] Make caching or optimize the quota size counting for reducing the time 
that is needed to process the 150k+ items
- [ ] Add server ability to push the additional data before client will request 
them (pre-caching, like folder structures or file properties or something else)
- [x] Add message for HTML if styles are not loaded (aka "Loading styles... 
Stuck there for long time? Check the internet, try reloading the page and check 
console for errors")
  - [ ] Make it appear also in plain HTML without need in `<script>`
- [ ] Fix CSP making bad things to the snippets (I assume; for IP Beacon at 
least - since it shows the CSP doing it's work)
- [ ] Test why quota can't be changed (at least in dynamic mode, caused by 
dynamic insufficient space at the CDN drive?)
- [ ] Add quota "space analyzer" (like WizTree or Filelight or whatever - it 
will display what files takes the most, where and what)
- [ ] Fix Markdown "intended support for new lines" (80/88 chars per line 
agreement)
- [ ] Fix issues with resuming the download (in FluxDrop file manager at least)
- [ ] Make download work as chunked-based in FluxDrop UI, keeping the regular 
octet-stream for legacy usage
- [ ] Add self-resume on network switch (offline handler shows and hides, but 
download doesn't continue)
- [ ] Fix beacon token deactivation/deletion even on usage - still there
- [ ] Fix HSTS redirects for FluxDrop file manager (currently doesn't work) -
means http to https on cdn (file manager) since login works ok (forwards to 
https)
- [ ] Fix spaces at the end of folder names causes delete fail - rename works 
OK with them
- [x] Add some kind of file streaming so upload of a folders will be faster 
(but secure) - one stream, a lot of files
  - [ ] Add this feature to site UI from `batch_tar_upload.py`
- [ ] Make AJAX-like updates for the file manager (no visual reloads of the 
content)
- [ ] Add file picker to file browser (checkbox-styled)
  - [ ] Add ability to use regular keyboard shortcuts (shift for multiple file 
  pick, ctrl to specific, ctrl+shift for multiple from latest pick with ctrl; 
  aka regular file browser behavior)
- [x] Cancel background file fetch (download) for preview if preview modal is 
closed (reduce wasted amount of internet traffic)
- [ ] Add loading wheel to the right of "Upload" button between prep and upload 
states - make it appear before new entry in `Uploads` or `Downloads` appears, 
also, bring the label to the static part so it will not scroll
- [ ] Add image placeholders between image download and display
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
- [ ] Fix every FluxDrop snippet and site (UIs) to work properly with mobile 
and non-16:9 screens
- [ ] Add checkers for external HTTP and HTTPS hosters
- [ ] Merge (or forward) HTTP and HTTPS hoster's regular ports with CDN's ports 
for more ideal links and simplicity
- [ ] Add PDF preview (at least via browser's util)
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


- [ ] Add landing page for FluxDrop - I really want start to draft it out
- [ ] Add ToS and PP docs - WIP
- [ ] Make proper header and footer for the main FluxDrop UI
- [ ] Add autoupdate "agreement" (when newer ToS or PP appears - user must 
accept it within)
- [ ] Discover ways to build own page via modules (zero-code; not necessary 
since I can just remember CSS and HTML, and do that by hands)
- [ ] Add "proper" loading wheels (1 second as least amount of time for the 
"apply" and other important features, more pleasant loadings for the file 
manager)


- [ ] Make HTTP and HTTPS hosters work properly as standalone utilities without 
any FluxDrop and CDN


- [ ] Migration to other host platform for HTTP and HTTPS efficiency and 
optimizations (Python; go to gunicorn or something else)
- [ ] (future) Replace the server hardware (aka FluxDrop + home NAS with proper 
storage media)


- [ ] Custom right-click menu



Note for myself: the realistic "safe to deploy publicly" checklist, in order 
of importance:

1. Fix B7 — force HTTPS for all auth/API paths. This is the single most 
important one.
2. Fix B2 — hash session tokens before storing. One DB backup or misconfigured 
file permission undoes all your auth work otherwise.
3. Fix B8 — add HSTS so browsers remember to always use HTTPS for your domain.
4. Add B9 (CSP) before you add any of the preview features from your TODO — 
PDF, Markdown, and archive previews are XSS-heavy territory and you want the 
CSP in place first.
5. Fix B6 — login length caps, to prevent the bcrypt DoS from distributed 
sources.



> **HSTS rollout plan:** Deploy with `max-age=300` first. Test that HTTPS works perfectly from a fresh browser. Then increase to `max-age=31536000`. Once set to a large value browsers will *always* use HTTPS for your domain — reversing it is hard, so confirm everything works first.
> 💡 Once you move inline scripts to `script.js` and inline styles to `tailwindcss.css`, you can drop `'unsafe-inline'` from both `script-src` and `style-src` for a significantly stronger policy.

> **Note:** Aborted fetches throw a `DOMException` with `name === 'AbortError'`.
> The existing `catch (err)` block at the bottom of `previewFile` will catch
> it and show "Preview failed: AbortError" for a brief flash — to suppress
> that, optionally add at the top of the catch:
>
> ```js
>     } catch (err) {
>         if (err.name === 'AbortError') return; // modal was closed, ignore
>         bodyEl.innerHTML = `<p style="color:#ef4444;...">Preview failed: ...`;
> ```


If your server doesn't support `inline=1` yet, the
simplest cross-browser fix is to embed via `<object>` with a fallback link,
which forces inline rendering in most browsers regardless of the header.

Option B — server_cdn.py: add `inline=1` support to the download handler

Find the section where `Content-Disposition` is set for the download endpoint
and add the inline flag check.  Search for the string `attachment; filename`
inside the download handler:

**Find (may appear 1–2 times in the download path):**
```python
            'Content-Disposition': f'attachment; filename="{quoted_name}"',
```

**Replace with:**
```python
            'Content-Disposition': (
                f'inline; filename="{quoted_name}"'
                if parsed_qs.get('inline', ['0'])[0] == '1'
                else f'attachment; filename="{quoted_name}"'
            ),
```

> Make sure `parsed_qs` is in scope where you make this change.  If the
> download handler already parses query params into a dict, use whatever
> variable name it uses.  If not, add near the top of the handler:
> ```python
> from urllib.parse import parse_qs
> parsed_qs = parse_qs(urllib.parse.urlparse(self.path).query)
> ```

line 1824:
> The "Browse" inline tree is scaffolded here with a placeholder message
> because the trash items are stored under an internal `.trash` directory
> path that the current list API (`/api/v1/list/…`) does not expose.
> To implement it fully, add `GET /api/v1/trash/<id>/list` in `server_cdn.py`
> that walks `trash_path` and returns the same JSON structure as the normal
> list endpoint.  The client-side scaffold above calls `btn.dataset.id` — 
> swap the placeholder `panel.innerHTML` for a real `apiCall` once the
> endpoint exists.
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
    403 or empty result. - result: FluxDrop user's files are safe from direct access without proper auth
  - Provide a little script/CLI command to generate per-file access tokens.
- [ ] **Tree download**
  - Allow downloading an entire folder as a `.zip` archive from the API.
  - Support partial-range requests so streaming large files (video/audio)
    can be used for simple hosting links.
- [ ] **Hosting links / streaming support**
  - Similar to share links but intended for embedding (useful for
    video/audio playback) with optional bandwidth throttling or expiry.
- [ ] **Family/Group accounts**
  - Let two or more usernames share a common root directory with mutual
    read/write privileges.
  - Add settings to control whether group members may add/remove other
    users, set quotas, etc.
- [ ] **Misc future ideas**
  - Implement per-user quotas and statistics.
  - Add server-side sanitisation for filenames with illegal characters.
  - Replace Tailwind CDN with a build step for production CSS.
  - Add explicit **move** and **copy** endpoints so users can relocate or
    duplicate items without constructing awkward rename paths.
  - Compute and return **folder size** in directory listings (sum of
    contained file sizes) rather than a dash, enabling quota display.
  - "Desecretify" the repository: move all hardcoded secrets/credentials out
    of Python files into the `server/Web/secrets/` directory (or similar),
    leaving example/sample files in source control.

Feel free to break these into issues or milestones as work proceeds.

Own list for ToDo:

- [x] **Safe download links**: use special tokens to download the files, not 
the user token

Aaaaand a lot more since I made a lot of changes in code and forgot to actually 
capture them in changes :)

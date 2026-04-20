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



```
That's a good instinct — the CDN path is vestigial but the underlying idea (a shared space between users) is actually worth keeping as a concept, just rethought properly. Before writing any patches let me read what the CDN path actually does today.Now I have a full picture. Let me lay this out clearly before suggesting anything:

---

**What CDN actually is today:**

There are actually *two* separate "shared" concepts tangled together:

1. **`CDN_UPLOAD_DIR`** (`secrets/CDN_uploads`) — what the "Browse CDN" button navigates to. It's a globally-shared flat directory that any logged-in user can browse. It has partial support wired through `download_token`, `list`, `zip`, `rename`, `delete`, etc. — but the server comment literally says *"purpose is unknown... marked for removal"*. The `ownerType = 'catbox'` check in `script.js` is a leftover reference to this.

2. **`CATBOX_UPLOAD_DIR`** (`CB_uploads`) — a completely *separate* thing used by the catbox-style anonymous upload API (the `/user/api.php` endpoint), not the file manager at all. This is the Litterbox/Catbox clone feature.

So the "Browse CDN" button goes to `CDN_uploads/`, which is a dead-end shared folder with no upload UI, no quota, no permissions — it just happens to be listable.

---

**The "Family shared folder" rethink:**

Your instinct is right. The infrastructure for a proper shared space is mostly already there — you just need to decide on the data model. There are two realistic approaches:

**Option A — Shared folder per-group (simpler):** Create a `groups` table, each group has a `group_id` and maps to a real directory like `SERVE_ROOT/FluxDrop/groups/<group_id>/`. Members are listed in a `group_members` table. The existing list/download/upload/delete endpoints get a third path prefix `/group/<group_id>/` alongside `/cdn/` and `/`. Permissions are: any member can read/write, only the group owner (or admin) can add/remove members or delete the group.

**Option B — Shared subfolder inside one user's tree (simpler to implement):** One user "owns" a folder and grants other specific users access to it via a share token with write permission. This is basically the existing share system with write access added. Less flexible but almost zero new backend code.

For a family use case Option A is the right model — it's symmetric, nobody "owns" the vacation photos folder, and it survives if the original user leaves. Option B is fine for "let my partner upload to my invoices folder" but feels wrong for a proper shared space.

---

**What I'd suggest doing now vs later:**

Right now — **remove the broken CDN button from the UI** and replace it with a greyed-out "Shared space (coming soon)" placeholder, or just hide it. The `CDN_UPLOAD_DIR` infrastructure can stay in the server for now since it's not hurting anything, and the path prefix `/cdn/` can be repurposed as `/group/` later without much churn.

Later, when you want to build it properly — the new things needed are: `groups` + `group_members` DB tables, a `/group/<id>/` path resolver in the 6–7 places that currently have the `/cdn/` branch, a group management UI (create group, invite by username, leave), and a quota decision (does shared space count against the owner? split evenly? separate pool?).

Want me to write the patch to remove/hide the CDN button now, or sketch out the full group schema and migration as a design doc first?
```



# Current problems
```
nothing
```
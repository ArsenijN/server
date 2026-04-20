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





# Current problems
```
nothing
```
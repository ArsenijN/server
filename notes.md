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





# Current problems (not)
```
arsen@MiWiFi-RD15-srv:~/servers/self-host/site/Web$ tail -n 50 LogsCDN.txt 
[2026-04-16 09:19:45] File "/opt/python3.14.2/lib/python3.14/http/server.py", line 496, in handle
    self.handle_one_request()
    ~~~~~~~~~~~~~~~~~~~~~~~^^
[2026-04-16 09:19:45] File "/opt/python3.14.2/lib/python3.14/http/server.py", line 484, in handle_one_request
    method()
    ~~~~~~^^
[2026-04-16 09:19:45] File "/home/arsen/servers/self-host/site/Web/server_cdn.py", line 4025, in do_GET
    return self._handle_trash_file_stream(int(trash_item_pattern_preview.group(1)))
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[2026-04-16 09:19:45] File "/home/arsen/servers/self-host/site/Web/server_cdn.py", line 5017, in _handle_trash_file_stream
    if row['is_dir']:
       ~~~^^^^^^^^^^
[2026-04-16 09:19:45] TypeError: tuple indices must be integers or slices, not str
[2026-04-16 09:19:45] ----------------------------------------
[2026-04-16 09:19:45] ----------------------------------------
[2026-04-16 09:19:45] Exception occurred during processing of request from
[2026-04-16 09:19:45] ('88.154.16.44', 54634)
[2026-04-16 09:19:45] Traceback (most recent call last):
[2026-04-16 09:19:45] File "/opt/python3.14.2/lib/python3.14/socketserver.py", line 697, in process_request_thread
    self.finish_request(request, client_address)
    ~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^
[2026-04-16 09:19:45] File "/opt/python3.14.2/lib/python3.14/socketserver.py", line 362, in finish_request
    self.RequestHandlerClass(request, client_address, self)
    ~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[2026-04-16 09:19:45] File "/home/arsen/servers/self-host/site/Web/server_cdn.py", line 2810, in __init__
    super().__init__(*args, directory=SERVE_ROOT, **kwargs)
    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[2026-04-16 09:19:45] File "/opt/python3.14.2/lib/python3.14/http/server.py", line 732, in __init__
    super().__init__(*args, **kwargs)
    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^
[2026-04-16 09:19:45] File "/opt/python3.14.2/lib/python3.14/socketserver.py", line 766, in __init__
    self.handle()
    ~~~~~~~~~~~^^
[2026-04-16 09:19:45] File "/opt/python3.14.2/lib/python3.14/http/server.py", line 496, in handle
    self.handle_one_request()
    ~~~~~~~~~~~~~~~~~~~~~~~^^
[2026-04-16 09:19:45] File "/opt/python3.14.2/lib/python3.14/http/server.py", line 484, in handle_one_request
    method()
    ~~~~~~^^
[2026-04-16 09:19:45] File "/home/arsen/servers/self-host/site/Web/server_cdn.py", line 4025, in do_GET
    return self._handle_trash_file_stream(int(trash_item_pattern_preview.group(1)))
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[2026-04-16 09:19:45] File "/home/arsen/servers/self-host/site/Web/server_cdn.py", line 5017, in _handle_trash_file_stream
    if row['is_dir']:
       ~~~^^^^^^^^^^
[2026-04-16 09:19:45] TypeError: tuple indices must be integers or slices, not str
[2026-04-16 09:19:45] ----------------------------------------
[2026-04-16 09:19:48] 31.43.242.8 - - [16/Apr/2026 09:19:48] "POST /beacon/ping HTTP/1.1" 200 -
[2026-04-16 09:20:13] Updating blacklist...
```
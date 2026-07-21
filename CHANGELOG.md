# Changelog — 2026-07-20

Commentary: this changelog may be not up-to-date always, strong recomendation 
to use Readme's patch notes across Git commits

## Fixed

### Immich archive downloads corrupted / "Unexpected end of data" (server_https.py)
`_proxy_to_host()` buffered the *entire* response into memory (`resp.read()`)
whenever the backend didn't send a `Content-Length` header — which is exactly
what Immich's `/api/download/archive` does, since it streams a zip it's
building on the fly. On a 300+-asset / multi-GB album export this meant:

- The whole archive sat in process RAM before a single byte reached the client.
- If anything interrupted that read partway (a stall between chunks, a
  backend hiccup), the exception fell through to the generic error handler,
  which called `send_response(502)` — **after** `send_response(200)` and the
  original headers had already gone out. The stray second status line landed
  inside what the client thought was still body data, corrupting the archive.

**Fix:** stream unknown-length responses as proper chunked transfer-encoding
instead of buffering, matching how `_proxy_to_cdn()` already streams
Content-Length-known responses. Both streaming paths now catch mid-transfer
errors locally and just drop the connection (`close_connection = True`)
instead of attempting a second response. The top-level exception handler now
checks whether headers were already sent before trying to emit an error
response at all.

Also raised the `gallery.arseniusgen.dev` per-host proxy timeout from 120s to
900s — this timeout applies per `recv()` call, not to the total transfer, so
it only needs to cover the longest gap between chunks during archive
generation, not the whole download.

### HTTP server restart loop, round 2 — /healthz didn't exist (server_http.py)
After the scheme fix, the health check correctly reached `http://127.0.0.1:8080/healthz` —
but `server_http.py` never had a `/healthz` route at all. It fell through to
`SimpleHTTPRequestHandler`'s static file lookup, found no file literally named
`healthz` in `SERVE_DIRECTORY`, and returned a legitimate `404`. Same
3-strikes restart loop, new root cause. `server_https.py` has had a fast-path
`/healthz` handler at the top of `do_GET` all along; `server_http.py` simply
never got the equivalent.

**Fix:** added the same fast-path `/healthz` → `200 ok` handler to
`server_http.py`, positioned first in `do_GET`, before blacklist checks,
CDN proxying, or static file serving.

### HTTP server restart loop, every ~90–110s (shared.py)
`_health_check_socket()` hardcoded `https://` in its self-ping URL regardless
of which server it was checking. The HTTP health check (`label="HTTP"`) was
sending a TLS ClientHello at the plain-HTTP listener on port 8080. The server
correctly rejected it (`400 Bad request version`), the health check saw that
as `SSL: WRONG_VERSION_NUMBER`, and 3 consecutive "failures" triggered
`restart_server()` — restarting a server that was never actually broken,
roughly every 90–110 seconds for as long as the process had been up.

**Fix:** scheme is now chosen from `label` (`http` for the HTTP check,
`https` for the HTTPS check), and the SSL context is only built for the
HTTPS case.

### WebSocket tunnel thread/memory leak (server_https.py)
`_proxy_to_host()`'s WS tunnel (used for the Immich reverse proxy) set
`settimeout(None)` on both the client and backend sockets — no read/write
timeout, ever. If a client disappeared without a clean TCP close (phone
sleep, WiFi→cellular handoff, NAT mapping expiry), the kernel never told
Python the peer was gone, and `recv()` blocked forever: 3 threads leaked per
dead connection, permanently, for the life of the process. This is the
~1.3 GB RSS growth over ~35 days of uptime, forcing the process into swap.

**Fix:** finite-but-generous socket timeout (300s, well above socket.io's
~25s heartbeat) plus OS-level TCP keepalive as a backstop, on both legs of
the tunnel. A timeout in `_pipe()` is now treated as a normal dead-peer close
rather than falling into the generic exception path.

## Files changed
- `server_https.py`
- `shared.py`
- `server_http.py`

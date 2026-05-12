// FluxDrop Service Worker
// Strategy:
//   - Static shell assets (HTML, JS, CSS, icons) → cache-first, update in background
//   - API calls (/api/, /auth/) → network-only, never cached
//   - Everything else → network-first, fall back to cache, then offline page
//
// PATH NOTE: The app lives at /fluxdrop_pp/ so all asset URLs must include
// that prefix.  The SW is registered from /fluxdrop_pp/index.html which sets
// its scope to /fluxdrop_pp/ — requests outside that scope are never seen.
// Navigation requests for /fluxdrop_pp/files/* must serve /fluxdrop_pp/index.html
// (SPA routing) rather than trying to fetch the directory as a real file.

const CACHE_NAME  = 'fluxdrop-v-d9b038a7';  // replaced by build.sh — do not edit manually
const OFFLINE_URL = '/fluxdrop_pp/offline.html';
const APP_BASE    = '/fluxdrop_pp';


// ── StreamSaver: in-flight download registry ──────────────────────────────
// mitm.html posts a message here with the stream + port; the fetch handler
// below intercepts the matching URL and pipes the stream as a response.
// This replaces the separate streamsaver/sw.js — one SW, one scope.
const _ssMap = new Map();

// StreamSaver keepalive ping (mitm.html polls this to keep the SW alive)
// and stream registration messages.
self.addEventListener('message', event => {
    // ── FluxDrop: hard-reload cache clear ────────────────────────────────
    if (event.data && event.data.type === 'SKIP_AND_CLEAR') {
        event.waitUntil(
            caches.keys()
                .then(keys => Promise.all(keys.map(k => caches.delete(k))))
                .then(() => {
                    if (event.ports && event.ports[0]) event.ports[0].postMessage('cleared');
                })
        );
        return;
    }

    // ── StreamSaver: keepalive ping ───────────────────────────────────────
    if (event.data === 'ping') return;

    // ── StreamSaver: stream registration ─────────────────────────────────
    const data = event.data;
    if (!data || !data.url) return;

    const port     = event.ports[0];
    const metadata = new Array(3); // [stream, data, port]
    metadata[1] = data;
    metadata[2] = port;

    if (data.readableStream) {
        metadata[0] = data.readableStream;
    } else if (data.transferringReadable) {
        port.onmessage = evt => {
            port.onmessage = null;
            metadata[0] = evt.data.readableStream;
        };
    } else {
        metadata[0] = _ssCreateStream(port);
    }

    _ssMap.set(data.url, metadata);
    port.postMessage({ download: data.url });
});

const PRECACHE_URLS = [
    '/fluxdrop_pp/',
    '/fluxdrop_pp/index.html',
    '/fluxdrop_pp/script.js',
    '/fluxdrop_pp/tailwindcss.css',
    '/fluxdrop_pp/icon.svg',
    '/fluxdrop_pp/offline.html',
    '/fluxdrop_pp/assets/all.min.css',
    '/fluxdrop_pp/assets/heic2any.min.js',
    '/fluxdrop_pp/assets/Inter.css',
    '/fluxdrop_pp/assets/jszip.min.js',
    '/fluxdrop_pp/assets/marked.min.js',
    '/fluxdrop_pp/assets/untar.min.js',
    '/fluxdrop_pp/assets/fonts/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa0ZL7SUc.woff2',
    '/fluxdrop_pp/assets/fonts/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa1pL7SUc.woff2',
    '/fluxdrop_pp/assets/fonts/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa1ZL7.woff2',
    '/fluxdrop_pp/assets/fonts/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa2JL7SUc.woff2',
    '/fluxdrop_pp/assets/fonts/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa2pL7SUc.woff2',
    '/fluxdrop_pp/assets/fonts/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa2ZL7SUc.woff2',
    '/fluxdrop_pp/assets/fonts/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa25L7SUc.woff2',
    '/fluxdrop_pp/assets/streamsaver/StreamSaver.js',
    '/fluxdrop_pp/assets/streamsaver/mitm.html',
    '/fluxdrop_pp/assets/streamsaver/sw.js',
];

// ── Install ───────────────────────────────────────────────────────────────
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE_URLS))
    );
    self.skipWaiting();
});

// ── Activate ─────────────────────────────────────────────────────────────
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys()
            .then(keys => Promise.all(
                keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
            ))
            .then(() => self.clients.claim())
            .then(() => self.clients.matchAll({ type: 'window' }))
            .then(clients => clients.forEach(c => c.postMessage({ type: 'SW_UPDATED' })))
    );
});

// ── StreamSaver: readable stream factory ─────────────────────────────────
function _ssCreateStream(port) {
    return new ReadableStream({
        start(controller) {
            port.onmessage = ({ data }) => {
                if (data === 'end')    return controller.close();
                if (data === 'abort') { controller.error('Aborted'); return; }
                controller.enqueue(data);
            };
        },
        cancel() { port.postMessage({ abort: true }); }
    });
}


// ── Message: SKIP_AND_CLEAR ───────────────────────────────────────────────
// Sent by _fdHardReload() in script.js before triggering location.reload().
// Deletes all caches so the reload fetches everything fresh from the server.
self.addEventListener('message', event => {
    if (event.data && event.data.type === 'SKIP_AND_CLEAR') {
        event.waitUntil(
            caches.keys()
                .then(keys => Promise.all(keys.map(k => caches.delete(k))))
                .then(() => {
                    // Reply so _fdHardReload's Promise resolves promptly
                    if (event.ports && event.ports[0]) event.ports[0].postMessage('cleared');
                })
        );
    }
});

// ── Fetch ─────────────────────────────────────────────────────────────────
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // ── StreamSaver: intercept registered download URLs ───────────────────
    // These are fake URLs mitm.html registered via postMessage; we serve the
    // piped stream as the response so the browser saves it as a file.
    if (_ssMap.has(event.request.url)) {
        const [stream, data, port] = _ssMap.get(event.request.url);
        _ssMap.delete(event.request.url);

        const headers = new Headers({
            'Content-Type':             'application/octet-stream; charset=utf-8',
            'Content-Security-Policy':  "default-src 'none'",
            'X-Content-Type-Options':   'nosniff',
        });
        const h = new Headers(data.headers || {});
        if (h.has('Content-Length'))      headers.set('Content-Length',      h.get('Content-Length'));
        if (h.has('Content-Disposition')) headers.set('Content-Disposition', h.get('Content-Disposition'));

        event.respondWith(new Response(stream, { headers }));
        port.postMessage({ debug: 'StreamSaver: download started' });
        return;
    }

    // StreamSaver keepalive ping (Firefox path)
    if (url.pathname.endsWith('/ping')) {
        event.respondWith(new Response('pong'));
        return;
    }

    // Cross-origin (API port 64800, external fonts, etc.) — never intercept.
    if (url.origin !== self.location.origin) return;

    const path = url.pathname;

    // API, auth, share, beacon — network-only; never cache.
    if (path.startsWith('/api/') || path.startsWith('/auth/') ||
        path.startsWith('/share/') || path.startsWith('/beacon')) {
        return;
    }

    // SPA navigation: any request for a path under /fluxdrop_pp/files/*
    // is a client-side route, not a real file — serve index.html from cache.
    if (event.request.mode === 'navigate' &&
        path.startsWith(APP_BASE + '/files')) {
        event.respondWith(
            caches.match('/fluxdrop_pp/index.html')
                .then(r => r || fetch('/fluxdrop_pp/index.html'))
        );
        return;
    }

    // Static shell assets: cache-first with background revalidation.
    const isShellAsset = PRECACHE_URLS.some(p =>
        path === p || path === p.replace(/\/+$/, '')
    );

    if (isShellAsset) {
        event.respondWith(
            caches.open(CACHE_NAME).then(async cache => {
                const cached = await cache.match(event.request);
                // Always revalidate in background — keeps cache warm without blocking
                const networkFetch = fetch(event.request).then(netResp => {
                    if (netResp && netResp.status === 200) {
                        cache.put(event.request, netResp.clone());
                    }
                    return netResp;
                }).catch(() => null);
                return cached || networkFetch || caches.match(OFFLINE_URL);
            })
        );
        return;
    }

    // Everything else: network-first, fall back to cache, then offline page.
    event.respondWith(
        fetch(event.request).catch(async () => {
            const cached = await caches.match(event.request);
            if (cached) return cached;
            if (event.request.mode === 'navigate') {
                return caches.match(OFFLINE_URL);
            }
            return Response.error();
        })
    );
});

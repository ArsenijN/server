// FluxDrop Service Worker
// Strategy:
//   - Static shell assets (HTML, JS, CSS, icons) → cache-first, update in background
//   - API calls (/api/, /auth/) → network-only, never cached
//   - Everything else → network-first, fall back to cache, then offline page

const CACHE_NAME    = 'fluxdrop-v3';    // ensure client gets new things properly by changing the cache version
const OFFLINE_URL   = '/offline.html';

// Assets to pre-cache on install. Keep this list to the bare minimum needed
// to render the shell while offline so the user sees the offline message.
const PRECACHE_URLS = [
    '/',
    '/index.html',
    '/script.js',
    '/tailwindcss.css',
    '/icon.svg',
    '/offline.html',
];

// ── Install ───────────────────────────────────────────────────────────────
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE_URLS))
    );
    // Take over immediately rather than waiting for the old SW to become idle
    self.skipWaiting();
});

// ── Activate ─────────────────────────────────────────────────────────────
self.addEventListener('activate', event => {
    // Delete caches from old SW versions
    event.waitUntil(
        caches.keys().then(keys =>
            Promise.all(
                keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
            )
        ).then(() => self.clients.claim())
         // P9: Tell all open tabs that a new version is ready
         .then(() => self.clients.matchAll({ type: 'window' }))
         .then(clients => clients.forEach(c => c.postMessage({ type: 'SW_UPDATED' })))
    );
});

// ── Fetch ─────────────────────────────────────────────────────────────────
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // Never intercept cross-origin requests (fonts, CDN libs, API server on
    // a different port — all different origins from the page origin).
    if (url.origin !== self.location.origin) return;

    // API and auth: network-only.  Caching API responses would be wrong.
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/auth/')) {
        return; // let the browser handle it normally
    }

    // Static shell assets: cache-first.
    // If we have it cached, return it immediately and also fetch a fresh copy
    // in the background to keep the cache up to date (stale-while-revalidate).
    const isShellAsset = PRECACHE_URLS.some(p => {
        const norm = p === '/' ? '/index.html' : p;
        return url.pathname === norm || url.pathname === p;
    });

    if (isShellAsset) {
        event.respondWith(
            caches.open(CACHE_NAME).then(async cache => {
                const cached = await cache.match(event.request);
                // Background update — don't await it
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
            // For navigation requests, show the offline page
            if (event.request.mode === 'navigate') {
                return caches.match(OFFLINE_URL);
            }
            // For other requests just let them fail
            return Response.error();
        })
    );
});

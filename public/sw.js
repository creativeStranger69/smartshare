/**
 * sw.js - SERVICE WORKER (what makes the website installable as an app)
 * ------------------------------------------------------------------
 * It caches only the small "app shell" (page, styles, script, icons) so the app opens
 * instantly and shows a screen even with no network. It NEVER caches /api, /files, /upload or
 * socket.io - chat data and private files must always come live from the server.
 * Strategy: network first (users always get the newest version), cache as the fallback.
 */
const CACHE = 'smartshare-shell-v1';
const SHELL = ['/', '/index.html', '/style.css', '/app.js', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;
  if (/^\/(api|files|upload|socket\.io|healthz)/.test(url.pathname)) return;   // live data: bypass the cache
  e.respondWith(
    fetch(req).then((res) => {
      if (res.ok && SHELL.includes(url.pathname)) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
      return res;
    }).catch(() => caches.match(req).then((hit) => hit || (req.mode === 'navigate' ? caches.match('/') : Response.error())))
  );
});

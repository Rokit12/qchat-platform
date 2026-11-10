// Service worker: offline app shell + Web Push notifications.
// Push payloads never contain message content (the server can't read it) — only who it's from.
const CACHE = 'qchat-v2';
const SHELL = ['/', '/index.html', '/app.js', '/style.css', '/icon.svg', '/manifest.webmanifest', '/e2ee-worker.js'];
self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  // network first (always get updates), cache as offline fallback
  e.respondWith(fetch(e.request).then((r) => { if (r.ok) { const copy = r.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)); } return r; })
    .catch(() => caches.match(e.request).then((r) => r || caches.match('/index.html'))));
});
self.addEventListener('push', (e) => {
  let d = {}; try { d = e.data.json(); } catch {}
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (wins.some((w) => w.visibilityState === 'visible')) return; // app is open and will notify itself
    const call = d.kind === 'call', isLive = d.kind === 'live';
    await self.registration.showNotification(call ? 'Incoming call' : isLive ? '🔴 Live now' : 'New message', {
      body: call ? `@${d.from} is calling you on QChat` : isLive ? `@${d.from} started a live video` : `New encrypted message from @${d.from}`,
      tag: call ? 'call-' + d.from : 'msg-' + d.from, renotify: true, icon: '/icon.svg', badge: '/icon.svg',
      requireInteraction: call, data: { from: d.from },
    });
  })());
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (wins[0]) { wins[0].focus(); wins[0].postMessage({ op: 'open', from: e.notification.data?.from }); }
    else await self.clients.openWindow('/#chat=' + encodeURIComponent(e.notification.data?.from || ''));
  })());
});

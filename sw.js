const CACHE_NAME = 'tatapay-v2';
const urlsToCache = [
  '/',
  '/index.html'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
  self.skipWaiting(); // ← Force la mise à jour immédiate
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
    )).then(() => self.clients.claim()) // ← Prend contrôle immédiatement
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    fetch(event.request) // ← Réseau d'abord
      .then(response => {
        const clone = response.clone();
        caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        return response;
      })
      .catch(() => caches.match(event.request)
        .then(r => r || caches.match('/index.html'))
      )
  );
});

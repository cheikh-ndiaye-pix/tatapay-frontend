// Service Worker TataPay — cache les fichiers essentiels pour que le scan/génération
// de QR (et l'app elle-même) continuent de fonctionner même sans connexion,
// une fois que la page a été chargée au moins une fois avec du réseau.

const CACHE_NAME = 'tatapay-cache-v1';

// Fichiers indispensables au fonctionnement hors-ligne :
// - la page elle-même
// - jsQR : lecture des QR codes (scan)
// - qrcode.js : génération locale des QR codes (achat/ticket)
const PRECACHE_URLS = [
  './',
  './index.html',
  'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js',
  'https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return Promise.allSettled(
        PRECACHE_URLS.map((url) =>
          cache.add(new Request(url, { cache: 'reload' })).catch((e) => {
            console.warn('[sw] échec mise en cache', url, e);
          })
        )
      );
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k !== CACHE_NAME)
          .map((k) => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

// Stratégie : réseau d'abord, cache en secours (et on rafraîchit le cache
// quand le réseau répond, pour rester à jour dès qu'une connexion existe).
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});

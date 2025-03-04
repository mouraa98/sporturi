// public/sw.js
const CACHE_NAME = 'tabela-campeonatos-v1';
const ASSETS = [
  '/',
  '/css/styles.css',
  '/assets/logo.png',
  '/assets/favicon.png',
  '/assets/favicon.png',
  '/views/index.ejs',
  '/views/login.ejs',
  '/views/user.ejs',
  '/views/admin.ejs',
  '/views/edit-time.ejs'
];

// Instala o Service Worker e armazena os assets em cache
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(ASSETS))
  );
});

// Intercepta as requisições e serve os assets do cache
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => response || fetch(event.request))
  );
});
// AgilFac — service worker simples: permite instalar como app e guarda só arquivos estáticos.
// Páginas e dados sempre vêm da rede (nada de dado de produção fica em cache).
const CACHE = 'agilfac-static-v1';
const STATIC = ['/public/styles.css', '/public/icons/icon-192.png', '/public/icons/icon-512.png'];
const OFFLINE_HTML = '<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sem conexão</title><body style="font-family:Arial,sans-serif;padding:32px;text-align:center"><h2>Sem conexão com a internet</h2><p>O AgilFac precisa de internet para lançar. Verifique o Wi-Fi e tente novamente.</p><button onclick="location.reload()" style="padding:12px 20px;font-size:16px">Tentar de novo</button></body></html>';

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(STATIC)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/public/')) {
    event.respondWith(fetch(req).then(res => {
      const copy = res.clone();
      caches.open(CACHE).then(cache => cache.put(req, copy));
      return res;
    }).catch(() => caches.match(req)));
    return;
  }
  if (req.mode === 'navigate') {
    event.respondWith(fetch(req).catch(() => new Response(OFFLINE_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })));
  }
});

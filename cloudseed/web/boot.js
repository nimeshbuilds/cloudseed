/* cloudseed console bootstrap (runs before the page renders; the server adds it to index.html and locked.html).

   The access token never lives in a cookie: cookies are not scoped to a port, so one would be sent to every other
   server on 127.0.0.1. Instead the link's ?token= is kept in this tab's sessionStorage (scoped to this exact origin,
   port included) and removed from the address bar and history entry. A reload of "/" lands on the locked page,
   which re-opens the console with the stored token; a token the server refuses (rotated) is forgotten.

   It also applies the theme picked in the console (localStorage cs-theme, see app.js) before the first paint: the
   locked page has no other script (the CSP allows no inline one), and the console does not flash the system theme. */
(() => {
  'use strict';
  try { const t = localStorage.getItem('cs-theme'); if (t === 'dark' || t === 'light') document.documentElement.dataset.theme = t; } catch (_) { /* storage blocked: the system theme */ }
  const KEY = 'cs-token';
  const store = {
    get() { try { return sessionStorage.getItem(KEY) || ''; } catch (_) { return ''; } },
    set(v) { try { sessionStorage.setItem(KEY, v); } catch (_) { /* storage disabled: a reload needs the link again */ } },
    del() { try { sessionStorage.removeItem(KEY); } catch (_) { /* nothing stored */ } },
  };
  let q;
  try { q = new URLSearchParams(location.search); } catch (_) { return; }
  const hadToken = q.has('token');
  const strip = () => {
    if (!hadToken) return;
    q.delete('token');
    const rest = q.toString();
    try { history.replaceState(history.state, '', location.pathname + (rest ? '?' + rest : '') + location.hash); } catch (_) { /* old browser: keep the URL */ }
  };
  const meta = document.querySelector('meta[name="cs-token"]');
  const tok = meta ? meta.getAttribute('content') : '';
  if (tok && tok !== '__CS_TOKEN__') { store.set(tok); strip(); return; }   // the unlocked console
  // the locked page
  if (hadToken) { store.del(); strip(); return; }                           // that token was refused: show the lock
  const saved = store.get();
  if (saved) {
    document.documentElement.style.visibility = 'hidden';                   // no flash of the lock screen
    location.replace('/?token=' + encodeURIComponent(saved));
  }
})();

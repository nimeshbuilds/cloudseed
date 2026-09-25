/* cloudseed console. Vanilla JS, no dependencies. Every button runs a cloudseed command via /api/run and streams the output. */
(() => {
  'use strict';
  const TOKEN = document.querySelector('meta[name="cs-token"]').content;
  // the ?token= link from `cs ui` has done its job once the page is served: API calls send the token from this page (it
  // is never a cookie) and boot.js keeps it in this tab's sessionStorage for reloads. boot.js already removed it from the
  // address bar, the history and session restore; this is the fallback when that script did not run.
  try { if (new URLSearchParams(location.search).has('token')) history.replaceState(null, '', location.pathname + location.hash); } catch { /* old browser: harmless */ }
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const NATIVE = /^(BUTTON|INPUT|SELECT|TEXTAREA|SUMMARY|LABEL|FORM|OPTION)$/;
  const el = (tag, attrs = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') n.className = v; else if (k === 'html') n.innerHTML = v; else if (k.startsWith('on')) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v === true ? '' : v);
    }
    // anything clickable that is not a native control (cards, tiles, chips, tabs, steps) is also reachable and operable from the keyboard
    if (attrs.onclick && !NATIVE.test(n.tagName) && !(n.tagName === 'A' && n.hasAttribute('href'))) {
      if (!n.hasAttribute('role')) n.setAttribute('role', 'button');
      if (!n.hasAttribute('tabindex')) n.setAttribute('tabindex', '0');
      n.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === n && !e.metaKey && !e.ctrlKey && !e.altKey) { e.preventDefault(); n.click(); } });
    }
    for (const k of kids.flat(Infinity)) if (k !== null && k !== undefined && k !== false) n.append(k.nodeType ? k : document.createTextNode(String(k)));
    return n;
  };
  // Two guards keep a double-click, or Enter pressed twice, from starting the same job twice:
  //  * run() drops an identical request (same action and arguments) while one is on its way: the first call shows the
  //    job and reports any error once, the duplicate returns null;
  //  * api() shows the pressed button as busy until the server answers (for at least a double-click's length) and, for
  //    1.5 s after the answer, hands an identical /api/run request the same answer instead of starting a new job.
  // Failures are not remembered. A busy button keeps keyboard focus (it is aria-disabled, not disabled: a disabled
  // button drops focus to the page), and clicks on it are swallowed here, before any handler sees them.
  let pressed = null; const PENDING = new Map();
  const isBusy = (b) => !!b && (b.classList.contains('busy') || b.getAttribute('aria-disabled') === 'true');
  document.addEventListener('click', (e) => {
    const b = e.target.closest ? e.target.closest('button') : null;
    if (isBusy(b)) { e.preventDefault(); e.stopImmediatePropagation(); return; }   // (also stops a form submit)
    pressed = b; setTimeout(() => { pressed = null; }, 0);
  }, true);
  const api = (path, body) => {
    const key = path === '/api/run' && body ? JSON.stringify(body) : '';
    const hit = key && PENDING.get(key);
    if (hit && hit.until && Date.now() < hit.until) return hit.p;
    const p = request(path, body);
    if (key) {
      const entry = { p, until: 0 }, btn = pressed, t0 = Date.now(); PENDING.set(key, entry);
      if (btn) { btn.classList.add('busy'); btn.setAttribute('aria-disabled', 'true'); btn.setAttribute('aria-busy', 'true'); }
      const release = () => { if (btn) setTimeout(() => { btn.classList.remove('busy'); btn.removeAttribute('aria-disabled'); btn.removeAttribute('aria-busy'); }, Math.max(0, 700 - (Date.now() - t0))); };
      p.then(() => { entry.until = Date.now() + 1500; setTimeout(() => { if (PENDING.get(key) === entry) PENDING.delete(key); }, 1500); release(); },
        () => { if (PENDING.get(key) === entry) PENDING.delete(key); release(); });
    }
    return p;
  };
  // the fetch itself: a failed request throws an Error carrying .status (0 = no answer) and .data (the JSON body). The
  // server's hint (e.g. which address to open) is part of the message; a refused token says how to get a new link.
  const request = async (path, body) => {
    let r;
    try { r = await fetch(path, { method: body ? 'POST' : 'GET', headers: { 'X-CS-Token': TOKEN, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }); }
    catch {
      const log = STATE && STATE.ui && STATE.ui.log ? `; log: ${STATE.ui.log}` : '; cs ui logs';
      const err = new Error(`the console server did not answer (is it running? cs ui status${log})`); err.status = 0; throw err;
    }
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const err = new Error((data.error || r.statusText || `HTTP ${r.status}`) + (data.hint && r.status !== 401 ? ` (${data.hint})` : '')); err.status = r.status; err.data = data;
      if (r.status === 401) { err.message = TOKEN_MSG; err.announced = tokenGone(); }   // announced: its own toast already explains it
      throw err;
    }
    return data;
  };
  const TOKEN_MSG = 'this console tab is no longer authorized (the UI token changed): open the new link with cs ui';
  // a message in the corner (the polite live region reads it; an error is an alert unless opts.quiet: its field says it)
  const toast = (msg, kind = '', ms = 4000, opts = {}) => { const t = el('div', { class: 'toast ' + kind, role: kind === 'bad' && !opts.quiet ? 'alert' : null }, msg); $('#toasts').append(t); setTimeout(() => t.remove(), ms); };
  // one modal at a time; opts: { narrow } for a form-sized dialog, and/or onClose (or opts itself a function), which runs
  // when the modal is closed or replaced (so a pending confirmation resolves). Focus moves in and back via syncLayers.
  // body may be one node or a list of them.
  let modalOnClose = null;
  const modal = (title, body, opts) => {
    const o = typeof opts === 'function' ? { onClose: opts } : (opts || {});
    const prev = modalOnClose; modalOnClose = null; if (prev) prev();
    $('#modal-title').textContent = title; $('.modal-card').classList.toggle('narrow', !!o.narrow); const b = $('#modal-body'); b.innerHTML = ''; b.append(...[].concat(body)); $('#modal').classList.remove('hidden');
    modalExplain(o.explain);   // (opts.explain: the page its "?" opens)
    modalOnClose = o.onClose || null;
  };
  const modalOpen = () => !$('#modal').classList.contains('hidden');
  // the open dialog's "?" beside its title (none when q is undefined)
  const modalExplain = (q) => { const old = $('.modal-head > .xq'); if (old) old.remove(); if (q !== undefined && q !== null) $('#modal-title').after(explainBtn(q, $('#modal-title').textContent)); };
  // what the open dialog shows, to put it back later exactly as it was (detached nodes keep typed values and handlers)
  const modalSnapshot = () => (modalOpen() ? { title: $('#modal-title').textContent, narrow: $('.modal-card').classList.contains('narrow'), nodes: Array.from($('#modal-body').childNodes), explain: ($('.modal-head > .xq') || { dataset: {} }).dataset.explain } : null);
  const closeModal = () => { $('#modal').classList.add('hidden'); const f = modalOnClose; modalOnClose = null; if (f) f(); };
  $('#modal-close').onclick = closeModal;
  $('#modal').addEventListener('click', (e) => { if (e.target === $('#modal')) closeModal(); });
  // timestamps arrive as UTC ISO strings; show them in the viewer's time zone (the exact value goes in a tooltip)
  const fmtTime = (iso) => { if (!iso) return '—'; const d = new Date(iso); return isNaN(d) ? String(iso).replace('T', ' ').slice(0, 19) : d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }); };
  const store = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage blocked: the setting lasts for this page only */ } },
    del: (k) => { try { localStorage.removeItem(k); } catch { /* storage blocked */ } } };
  // keyboard hints name the key this computer has: ⌘ on Apple devices, Ctrl elsewhere (both work everywhere)
  const MOD = /mac|iphone|ipad|ipod/i.test((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '') ? '⌘' : 'Ctrl+';
  // POSIX shell quoting for command previews: a copied command pastes into bash/zsh with exactly the argv the console runs
  const shq = (s) => { s = String(s); return /^[\w@%+:,./-][\w@%+=:,./-]*$/.test(s) ? s : "'" + s.replace(/'/g, "'\\''") + "'"; };
  const cmdLine = (argv) => ['cloudseed', ...(argv || [])].map(shq).join(' ');
  const copyText = async (text, what) => {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
      else { const ta = el('textarea', { style: 'position:fixed;top:0;left:0;opacity:0' }); ta.value = text; document.body.append(ta); ta.select(); const ok = document.execCommand('copy'); ta.remove(); if (!ok) throw new Error('the browser refused'); }
      toast(`${what} copied`, 'ok');
    } catch (e) { toast(`✖ Could not copy the ${what.toLowerCase()} (${e.message || e}); select it and copy by hand`, 'bad', 6000); }
  };
  const ICONS = {
    overview: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="5" rx="2"/><rect x="13" y="11" width="8" height="10" rx="2"/><rect x="3" y="14" width="8" height="7" rx="2"/></svg>',
    create: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>',
    envs: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 18a4 4 0 1 1 .5-7.97A6 6 0 0 1 19 9a4 4 0 0 1-1 8.9"/><path d="M12 12v9M9 18l3 3 3-3"/></svg>',
    platform: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l8 4.5v9L12 20l-8-4.5v-9z"/><path d="M12 11l8-4.5M12 11v9M12 11L4 6.5"/></svg>',
    resilience: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
    actions: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg>',
    reports: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/></svg>',
    agents: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="7" width="16" height="12" rx="3"/><path d="M12 3v4M8 12h.01M16 12h.01M9 16h6"/></svg>',
    creds: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>',
    help: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 0 1 5 0c0 1.5-2.5 2-2.5 3.5M12 17h.01"/></svg>',
    doctor: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 8L9 4l-3 8H2"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>',
    refresh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/></svg>',
  };
  const icon = (name) => ICONS[name].replace('<svg ', '<svg aria-hidden="true" focusable="false" ');
  const NAV = [['overview', 'Overview', '1'], ['create', 'Create', '2'], ['envs', 'Environments', '3'], ['platform', 'Platform', '4'], ['resilience', 'Resilience', '5'], ['actions', 'All actions', '6'], ['reports', 'Reports', '7'], ['agents', 'Agents & MCP', '8'], ['creds', 'Credentials', '9'], ['help', 'Help', '0']];
  const CLOUD = { aws: 'AWS', gcp: 'GCP', azure: 'AZ', vmware: 'VM' };

  let STATE = null, ACTIONS = [], VIEW = 'overview', PLATFORM_STATUS = {};
  const RENDER = {};                              // per-view render counter: an older async render never draws over a newer one
  const PLAT_FILTER = { q: '', g: '', i: '' };    // platform filters survive re-renders
  const currentEnv = () => (STATE ? STATE.envs.find((e) => e.id === $('#current-env').value) : null) || null;
  const envArgs = () => { const e = currentEnv(); return e ? { cloud: e.cloud, env: e.env } : {}; };
  const ssGet = (k) => { try { return sessionStorage.getItem(k); } catch { return null; } };
  const ssSet = (k, v) => { try { sessionStorage.setItem(k, v); } catch { /* private mode */ } };

  // ---------------------------------------------------------------- theme / rail
  // The theme follows the system (live) until the toggle picks one; picking the system's own theme again goes back to
  // following it. The button shows the theme it switches to and says so in its name.
  const darkMq = matchMedia('(prefers-color-scheme: dark)');
  const systemTheme = () => (darkMq.matches ? 'dark' : 'light');
  const pinnedTheme = () => { const t = store.get('cs-theme'); return t === 'dark' || t === 'light' ? t : null; };
  const applyTheme = () => {
    const t = pinnedTheme() || systemTheme(); document.documentElement.dataset.theme = t;
    const next = t === 'dark' ? 'light' : 'dark', b = $('#theme-btn');
    b.setAttribute('aria-label', `Switch to the ${next} theme`); b.title = `Switch to the ${next} theme` + (pinnedTheme() ? '' : ` (now following your system's ${t} theme)`);
  };
  applyTheme();
  if (darkMq.addEventListener) darkMq.addEventListener('change', applyTheme);
  $('#theme-btn').onclick = () => { const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; if (next === systemTheme()) store.del('cs-theme'); else store.set('cs-theme', next); applyTheme(); };
  // the rail collapses to icons on wide screens (remembered), and is an off-canvas menu at 900px and below
  const narrow = matchMedia('(max-width: 900px)');
  const setRail = (collapsed) => {
    $('#app').classList.toggle('collapsed', collapsed);
    const b = $('#rail-collapse'); b.setAttribute('aria-expanded', String(!collapsed));
    b.title = (collapsed ? 'Expand sidebar' : 'Collapse sidebar') + ` (${MOD}B)`; b.setAttribute('aria-label', collapsed ? 'Expand sidebar' : 'Collapse sidebar');
    store.set('cs-rail', collapsed ? '1' : '0');
  };
  $('#menu-btn').title = `Menu (${MOD}B)`;
  $('#palette-btn .palette-icon').textContent = MOD + 'K';
  const setNav = (open) => {
    $('#app').classList.toggle('nav-open', open); $('#menu-btn').setAttribute('aria-expanded', String(open)); syncLayers();   // the page behind the open menu is inert
    if (open) ($('#nav .active') || $('#nav [role="button"]')).focus(); else if ($('#rail').contains(document.activeElement)) $('#menu-btn').focus();
  };
  const toggleRail = () => (narrow.matches ? setNav(!$('#app').classList.contains('nav-open')) : setRail(!$('#app').classList.contains('collapsed')));
  setRail(store.get('cs-rail') === '1');
  $('#rail-collapse').onclick = toggleRail;
  $('#menu-btn').onclick = toggleRail;
  $('#app').addEventListener('click', (e) => { if (e.target === $('#app')) setNav(false); });   // the dimmed backdrop behind the open menu
  narrow.addEventListener('change', () => setNav(false));
  // a view picked from the keyboard (Enter/Space: a click without a pointer) moves focus to its content
  const focusMain = () => $('#main').focus({ preventScroll: true });
  for (const [id, label, key] of NAV) $('#nav').append(el('a', { 'data-view': id, html: icon(id), title: `${label} (${key})`, 'aria-label': label, onclick: (ev) => { go(id); if (ev.detail === 0) focusMain(); } }, el('span', {}, label), el('span', { class: 'k', 'aria-hidden': 'true' }, key)));
  // the skip link jumps past the rail and the top bar without leaving a #main in the address bar
  $('#skip').onclick = (ev) => { ev.preventDefault(); focusMain(); };

  // ---------------------------------------------------------------- activity drawer
  const jobs = new Map();
  const seenRunning = new Set();   // jobs this page saw running: only those are announced when they finish
  const announced = new Set();     // ... and only once (re-opening an old tab replays its 'done' event)
  const inFlight = new Set();      // /api/run requests on their way: a double click never starts the same job twice (see api())
  const INTERRUPTED = new Set();   // jobs this page sent an interrupt to: they end "interrupted", not "failed"
  const JOB_DONE = new Map();      // job id -> what to do once it ends (the wizard follows its own setup runs)
  let activeJob = null, es = null;
  const drawer = $('#console');
  const setDrawer = (open) => drawer.classList.toggle('open', open);   // inert / aria-expanded follow via syncDrawer
  const openDrawer = () => setDrawer(true);
  $('#toggle-console').onclick = () => setDrawer(!drawer.classList.contains('open'));
  $('#console-close').onclick = () => setDrawer(false);
  // A closed drawer (and everything behind an open dialog) is taken out of the tab order; dialogs get focus when they
  // open and hand it back when they close. Observing the classes covers every place that opens or closes them.
  const syncDrawer = () => { const open = drawer.classList.contains('open'); drawer.inert = !open; $('#toggle-console').setAttribute('aria-expanded', String(open)); if (!open && drawer.contains(document.activeElement)) $('#toggle-console').focus(); };
  new MutationObserver(syncDrawer).observe(drawer, { attributes: true, attributeFilter: ['class'] }); syncDrawer();
  // topmost first; a dialog focuses its first text field (never a button, which could be a destructive one), else its close button
  const layers = [[$('#palette'), () => $('#palette-input')], [$('#modal'), () => $('#modal-body input:not([type=hidden]):not([type=checkbox]),#modal-body select,#modal-body textarea') || $('#modal-close')]];
  const inLayer = (node) => layers.some(([n]) => n.contains(node));
  let returnTo = null, lastOutside = null;
  document.addEventListener('focusin', (e) => { if (!inLayer(e.target)) lastOutside = e.target; });
  document.addEventListener('focusout', (e) => { if (!e.relatedTarget && !inLayer(e.target)) lastOutside = null; });
  const syncLayers = () => {
    const open = layers.filter(([n]) => !n.classList.contains('hidden'));
    if (open.length && !returnTo) { const a = document.activeElement; returnTo = a && a !== document.body && !inLayer(a) ? a : lastOutside; }
    $('.shell').inert = open.length > 0 || $('#app').classList.contains('nav-open'); $('#rail').inert = open.length > 0; $('#skip').inert = $('.shell').inert;
    if (open.length) {
      if (!open.some(([n]) => n.contains(document.activeElement))) open[0][1]().focus();
    } else if (returnTo) {
      const back = returnTo; returnTo = null;
      const lost = !document.activeElement || document.activeElement === document.body || inLayer(document.activeElement);
      if (lost && back.isConnected && back !== document.body && !inLayer(back)) back.focus();
    }
  };
  for (const [n] of layers) new MutationObserver(syncLayers).observe(n, { attributes: true, attributeFilter: ['class'], childList: true, subtree: true });
  $('#job-cancel').onclick = async () => {
    const j = jobs.get(activeJob);
    if (!j || !j.running) return toast('Nothing is running in this tab');
    // the server says what happened (first / second interrupt, killed, or why nothing was signalled)
    try {
      const r = await api(`/api/jobs/${encodeURIComponent(j.id)}/cancel`, {});
      // (the server's count of interrupts: the button names the next one)
      if (r.cancelled) { INTERRUPTED.add(j.id); trackJob(j.id, { interrupted: true, interrupts: typeof r.interrupts === 'number' ? r.interrupts : (Number(j.interrupts) || 0) + 1 }); renderTabs(); }
      toast(`${r.cancelled ? '' : '✖ '}${j.label}: ${r.message || (r.cancelled ? 'interrupt sent' : 'it had already finished')}`, r.cancelled ? '' : 'bad', r.cancelled ? 8000 : 5000); }
    catch (e) { fail(e); }
  };
  $('#job-copy').onclick = () => { const t = $('#job-output').textContent; if (!t.trim()) return toast('Nothing to copy yet'); copyText(t, 'Output'); };
  // The handle resizes the drawer with a mouse, a finger or a pen (pointer events) and from the keyboard (it is a focusable
  // separator: ↑/↓ step, Shift for bigger steps, Home/End for the smallest/largest size).
  (() => {
    const h = $('#drawer-handle'), LO = 140;
    const hi = () => Math.max(LO, innerHeight - 160);   // the handle and the page above it stay reachable
    const clamp = (px) => Math.max(LO, Math.min(px, hi()));
    const setH = (px) => { drawer.style.setProperty('--drawer-h', clamp(px) + 'px'); };
    let y0 = 0, h0 = 0;
    h.addEventListener('pointerdown', (e) => { if (e.button !== 0) return; e.preventDefault(); try { h.setPointerCapture(e.pointerId); } catch { /* an old browser: the move events still arrive */ } y0 = e.clientY; h0 = drawer.offsetHeight; drawer.style.transition = 'none'; document.body.style.userSelect = 'none'; });
    h.addEventListener('pointermove', (e) => { if (h.hasPointerCapture && h.hasPointerCapture(e.pointerId)) setH(h0 + (y0 - e.clientY)); });
    const end = () => { document.body.style.userSelect = ''; drawer.style.transition = ''; };
    for (const n of ['pointerup', 'pointercancel', 'lostpointercapture']) h.addEventListener(n, end);
    h.addEventListener('keydown', (e) => {
      const cur = drawer.offsetHeight, step = e.shiftKey ? 96 : 24;
      const to = { ArrowUp: cur + step, ArrowDown: cur - step, PageUp: cur + 96, PageDown: cur - 96, Home: LO, End: hi() }[e.key];
      if (to === undefined) return; e.preventDefault(); drawer.style.transition = 'none'; setH(to); requestAnimationFrame(() => { drawer.style.transition = ''; });
    });
    addEventListener('resize', () => { const cur = parseFloat(drawer.style.getPropertyValue('--drawer-h')); if (cur) setH(cur); });
    // the live height (clamped, animated, 0 when closed): the separator reports it and the toasts stay above the drawer
    const track = () => {
      const px = drawer.offsetHeight; document.documentElement.style.setProperty('--drawer-live', px + 'px');
      h.setAttribute('aria-valuemin', String(LO)); h.setAttribute('aria-valuemax', String(hi())); h.setAttribute('aria-valuenow', String(Math.max(LO, Math.min(px, hi()))));
    };
    if (window.ResizeObserver) new ResizeObserver(track).observe(drawer);
    track();
  })();
  // Closed frame rows (╭─╮ │…│ ╰─╯) and header rules (━━ Title ━━━) are drawn at the CLI's fixed width: they keep their
  // shape (and scroll sideways on a narrow screen); everything else, errors included, wraps.
  // colour by the leading glyph first (looking inside panel rows and terraform's "│ Error:" boxes), then by whole words
  const colorize = (line) => {
    const frame = /^\s*(?:╭.*╮|╰─*╯|│.*│)\s*$/.test(line) || /^\s*━━ .*━{4,}\s*$/.test(line);
    const body = line.replace(/^\s*(?:[│|┃]\s*)?/, '');
    let cls = '';
    if (/^(✖|\[exit code|\[lost)/.test(body) || /^(Error\b|ERROR\b|Traceback\b)/.test(body)) cls = 'bad';
    else if (/^(▲|\[interrupted|\[incomplete)/.test(body) || /^(Warning|INCOMPLETE|UNKNOWN)\b/.test(body)) cls = 'warn';
    else if (/^(✔|\[done\])/.test(body)) cls = 'ok';
    else if (/^\$ /.test(body)) cls = 'cmd';
    else if (/^[○–]/.test(body) || /\bnot (installed|ready|running|found|healthy|connected|logged in)\b/i.test(body)) cls = 'dim';
    else if (/^(●|◆|━━)/.test(body)) cls = 'info';
    else if (/\bApply complete!|^PASS\b|\bSuccess(fully)?\b/.test(body)) cls = 'ok';
    else if (/\b[1-9]\d* (failed|errors?)\b|\bFAIL(ED)?\b|\bError:/.test(body)) cls = 'bad';
    else if (/^\s*(│|╭|╰|╷|╵)/.test(line)) cls = 'dim';
    return el('span', { class: frame ? (cls + ' box').trim() : cls }, line + '\n');
  };
  const SEEN = new Map();   // when this page first saw a job, for entries the server has not timestamped yet
  const jobTime = (j) => { const d = j.started ? new Date(j.started) : null; if (!SEEN.has(j.id)) SEEN.set(j.id, new Date()); return d && !isNaN(d) ? d : SEEN.get(j.id); };
  const jobCmd = (j) => cmdLine((j && j.argv) || []);
  // two ways to lose a job: the server forgot it (404 after a restart: `gone`, no output left), or it knows the job
  // ended while no console was running and could not record its exit code (lost, rc -1: its output is still there)
  const LOST_LINE = '[lost: the console server restarted and no longer tracks this job; its output is gone. Check the environment (Status / Troubleshoot) before running it again.]';
  const ENDED_UNKNOWN_LINE = '[lost: the job ended while the console server was not running, so its exit code is unknown. Check the environment (Status / Troubleshoot) before running it again.]';
  // a job the user interrupted (from this page, or as the server reports it) ended on purpose: "interrupted", not "failed"
  const interrupted = (j) => !!j && !j.running && j.rc !== 0 && (!!j.interrupted || INTERRUPTED.has(j.id) || j.rc === 130);
  const jobStatusText = (j) => j.lost ? 'lost (console server restarted)' : j.running === undefined ? 'loading…' : j.running ? 'running…' : j.rc === 0 ? `finished in ${j.seconds}s`
    : interrupted(j) ? `interrupted after ${j.seconds}s (exit ${j.rc})` : jobState(j) === 'incomplete' ? `incomplete assessment in ${j.seconds}s (exit 3); see Reports` : `exit ${j.rc} after ${j.seconds}s`;
  // one word for a job's state (tab tooltips, the narrow-screen status glyph)
  const jobState = (j) => (!j ? '' : j.lost ? 'lost' : j.running ? 'running' : j.rc === 0 ? 'ok' : j.rc === undefined || j.rc === null ? '' : interrupted(j) ? 'interrupted'
    : j.rc === 3 && (j.argv || [])[0] === 'scan' && j.argv[1] === 'architecture' ? 'incomplete' : 'bad');
  function renderTabs() {
    const tabs = $('#job-tabs'); tabs.innerHTML = '';
    // repeated runs of one action are told apart by their start time; the tooltip carries the full command
    for (const j of Array.from(jobs.values()).slice(-8).reverse()) {
      const at = jobTime(j), k = jobState(j);
      const st = { lost: 'lost (console server restarted)', running: 'running', ok: 'finished', incomplete: 'incomplete assessment (exit 3)', interrupted: `interrupted (exit ${j.rc})`, bad: `failed (exit ${j.rc})` }[k] || '';
      tabs.append(el('a', { class: j.id === activeJob ? 'active' : '', 'aria-current': j.id === activeJob ? 'true' : null, title: `${j.argv ? jobCmd(j) : j.label}\nstarted ${at.toLocaleString()}${st ? ' · ' + st : ''}`, onclick: () => showJob(j.id) },
        el('span', { class: 'dot ' + (k === 'running' ? 'run' : k), 'aria-hidden': 'true' }), j.label + (j.lost ? ' (lost)' : k === 'interrupted' ? ' (interrupted)' : k === 'incomplete' ? ' (incomplete)' : ''),
        el('span', { class: 't' }, at.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }))));
    }
    const running = Array.from(jobs.values()).filter((j) => j.running).length;
    $('#activity-count').textContent = running ? String(running) : '';
    $('#activity-dot').classList.toggle('run', running > 0);
    const aj = jobs.get(activeJob);
    $('#job-cancel').disabled = !(aj && aj.running); $('#job-copy').disabled = !aj;
    // the next interrupt, as the server counts them (from any tab, and across a console restart): the first is Ctrl-C
    // (Terraform stops cleanly and saves its state), the second stops Terraform at once, the third kills the job
    const sent = aj && aj.running ? Number(aj.interrupts) || 0 : 0, cb = $('#job-cancel');
    cb.textContent = sent >= 2 ? 'Kill' : sent === 1 ? 'Stop now' : 'Interrupt';
    cb.title = sent >= 2 ? 'Kill the job now (it cannot clean up)' : sent === 1 ? 'Interrupt again: Terraform stops immediately (a remote state lock may need terraform force-unlock)'
      : 'Interrupt like Ctrl-C: Terraform stops cleanly, saves its state and releases the lock';
    $('#job-status').dataset.state = jobState(aj);   // a glyph stands in for the text on narrow screens
    $('#job-output').dataset.empty = jobs.size ? 'Pick a job above to see its output.' : 'No activity yet. Every action you run streams its output here live.';
  }
  // merge what we know about a job (server data wins, the label given at start is kept)
  function trackJob(id, fields) {
    const cur = jobs.get(id);
    const j = cur ? { ...cur, ...fields, label: cur.label || fields.label } : { id, ...fields };
    delete j.lines;
    jobs.set(id, j);
    if (j.running) seenRunning.add(id);
    return j;
  }
  // a job this page saw running has ended: say so once, forget cached cluster status (installs change it)
  function announce(j) {
    if (!seenRunning.has(j.id) || announced.has(j.id) || j.running) return false;
    announced.add(j.id);
    if (j.lost) toast(`✖ ${j.label}: lost (the console server restarted)`, 'bad', 6000);
    else if (interrupted(j)) toast(`▲ ${j.label} interrupted (exit ${j.rc})`, 'warn');
    else if (jobState(j) === 'incomplete') toast(`▲ ${j.label}: incomplete evidence; see Reports`, 'warn');
    else toast(j.rc === 0 ? `✔ ${j.label} finished` : `✖ ${j.label} failed (exit ${j.rc})`, j.rc === 0 ? 'ok' : 'bad');
    PLATFORM_STATUS = {};
    const done = JOB_DONE.get(j.id); if (done) { JOB_DONE.delete(j.id); try { done(j); } catch (err) { console.error(err); } }
    return true;
  }
  // the console's token was rotated or the server now has another one: every call fails until the new link is opened
  let tokenWarned = false;
  const tokenGone = () => { if (tokenWarned) return false; tokenWarned = true; $('#job-status').textContent = 'not authorized'; toast('✖ This console tab is no longer authorized (the UI token changed). Open the new link: cs ui', 'bad', 15000); return true; };
  // an error toast, unless the error was already explained (a refused token)
  const fail = (e, prefix = '') => { if (!(e && e.announced)) toast('✖ ' + prefix + (e && e.message || e), 'bad', 6000); };
  // the token works again (e.g. undo put the old one back): the next refusal is explained again
  const tokenBack = () => { if (!tokenWarned) return; tokenWarned = false; if ($('#job-status').textContent === 'not authorized') $('#job-status').textContent = ''; };
  let refreshTimer = null;
  const scheduleRefresh = () => { clearTimeout(refreshTimer); refreshTimer = setTimeout(() => { loadState().then(() => refreshView()).catch(() => { /* the next poll retries */ }); }, 250); };
  // a clean output pane; the command goes in the header line above it (quoted as a shell would need it)
  function jobHeader(id) { $('#job-output').innerHTML = ''; const j = jobs.get(id) || {}; const cmd = $('#job-cmd'); cmd.textContent = j.argv ? '$ ' + jobCmd(j) : ''; cmd.title = cmd.textContent; }
  function jobFinished(data) {
    const j = trackJob(data.id, { ...data, running: false, lost: !!data.lost });   // the server's lost flag (rc -1) is kept
    if (j.id === activeJob) { $('#job-status').textContent = jobStatusText(j); const out = $('#job-output'); out.append(colorize(j.lost ? ENDED_UNKNOWN_LINE : j.rc === 0 ? '[done]' : interrupted(j) ? `[interrupted (exit code ${j.rc})]` : jobState(j) === 'incomplete' ? '[incomplete assessment: required evidence is missing or stale; see Reports (exit code 3)]' : `[exit code ${j.rc}]`)); out.scrollTop = out.scrollHeight; }
    renderTabs();
    if (announce(j)) scheduleRefresh();
  }
  function markLost(id) {
    const cur = jobs.get(id); if (!cur || cur.gone) return;
    const j = trackJob(id, { running: false, rc: null, lost: true, gone: true });
    if (id === activeJob) { $('#job-status').textContent = jobStatusText(j); $('#job-output').append(colorize(LOST_LINE)); }
    renderTabs(); announce(j);
  }
  // ask the server about one job (its stream failed, or the state list no longer carries it)
  async function checkJob(id, fromStream) {
    let j;
    try { j = await api(`/api/jobs/${encodeURIComponent(id)}`); }
    catch (e) {
      if (e.status === 404) return markLost(id);
      if (e.status === 401) { tokenGone(); return; }
      if (fromStream && activeJob === id) { $('#job-status').textContent = 'the console server is not answering; retrying…'; setTimeout(() => { if (activeJob === id && !es) showJob(id); }, 5000); }
      return;
    }
    if (j.running) { trackJob(id, j); renderTabs(); if (fromStream && activeJob === id) setTimeout(() => { if (activeJob === id && !es) showJob(id); }, 1500); return; }
    if (fromStream && activeJob === id) { jobHeader(id); const out = $('#job-output'); for (const l of j.lines || []) out.append(colorize(l)); }
    jobFinished(j);
  }
  function showJob(id) {
    activeJob = id;
    if (es) { es.close(); es = null; }
    jobHeader(id);
    const j0 = jobs.get(id) || {};
    $('#job-status').textContent = jobStatusText(j0);
    renderTabs(); openDrawer();
    if (j0.gone) { $('#job-output').append(colorize(LOST_LINE)); return; }
    const out = $('#job-output');
    const src = es = new EventSource(`/api/jobs/${encodeURIComponent(id)}/stream?token=${encodeURIComponent(TOKEN)}`);
    const mine = () => es === src && activeJob === id;
    // Every line carries its number as the event id. When the browser reconnects it sends the last one it saw and the
    // server continues after it, so the output shown so far stays; a line that arrives twice anyway is skipped.
    let shown = 0;
    src.onopen = () => { if (!mine()) return; if ((jobs.get(id) || {}).running !== false) $('#job-status').textContent = 'running…'; };
    src.onmessage = (ev) => {
      if (!mine()) return;
      const n = Number(ev.lastEventId);
      if (n > 0) { if (n <= shown) return; shown = n; }
      out.append(colorize(JSON.parse(ev.data))); out.scrollTop = out.scrollHeight;
    };
    src.addEventListener('done', (ev) => { if (!mine()) return; src.close(); es = null; jobFinished(JSON.parse(ev.data)); });
    src.onerror = () => {
      if (!mine()) { src.close(); return; }
      if (src.readyState === EventSource.CONNECTING) { $('#job-status').textContent = 'reconnecting…'; return; }   // the browser retries by itself
      src.close(); es = null; checkJob(id, true);   // closed for good (404 after a server restart, ...): find out what happened
    };
  }
  // A confirmation step for anything that changes infrastructure, installs/removes software or runs a task. It shows the
  // exact command (the server's 409 answer carries it). When it replaced a dialog (a filled-in form), Cancel - or a run
  // that could not start - puts that dialog back as it was.
  function confirmRun(action, args, label, info = {}) {
    return new Promise((resolve) => {
      const back = modalSnapshot();
      let settled = false; const finish = (v) => { if (!settled) { settled = true; resolve(v); } };
      const restore = () => {
        modal(back.title, back.nodes, { narrow: back.narrow, explain: back.explain });
        const btn = $('#modal-body button[type="submit"]'); if (btn) setTimeout(() => btn.focus(), 0);
      };
      const tick = el('input', { type: 'checkbox' });
      const target = args && args.cloud ? (args.env ? `${args.cloud}-${args.env}` : `${args.cloud} (its default environment)`) : null;
      const destroy = action === 'cloudseed_destroy';
      const runBtn = el('button', { class: 'btn rose', disabled: true, onclick: async () => { settled = true; closeModal(); const job = await run(action, { ...args, confirm: true }, label); if (!job && back) restore(); resolve(job); } },
        destroy ? `Destroy ${target || 'the environment'}` : '▶ Run');
      tick.onchange = () => { runBtn.disabled = !tick.checked; };
      modal('Confirm: ' + label, el('div', {},
        destroy ? destroyConfirmNote(args, target) : el('p', {}, info.message || 'This changes infrastructure, installs or removes software, or runs a task.'),
        target && !destroy ? el('p', { class: 'small' }, 'Environment: ', el('b', {}, target)) : null,
        info.argv ? el('div', {}, el('h4', {}, 'Command that will run'), el('pre', { class: 'cmd-preview' }, cmdLine(info.argv))) : null,
        el('label', { class: 'check', style: 'margin-top:12px' }, tick, el('span', {}, 'I understand what this does')),
        el('div', { class: 'row', style: 'margin-top:12px' }, el('button', { class: 'btn ghost', onclick: () => { if (back) { finish(null); restore(); } else closeModal(); } }, back ? '← Back' : 'Cancel'), el('span', { class: 'spacer' }), runBtn)),
      { narrow: true, onClose: () => finish(null) });
      modalExplain(actionXq(action));
      setTimeout(() => tick.focus(), 0);
    });
  }
  // A job this page did not start (a conflict names the one already working on the environment): learn its own label
  // and command from the server before showing it, so its tab is never labelled with the action that was refused.
  async function adoptJob(id) {
    if (!jobs.has(id)) {
      const listed = ((STATE && STATE.jobs) || []).find((x) => x.id === id);
      let j = listed;
      if (!j) { try { j = await api(`/api/jobs/${encodeURIComponent(id)}`); } catch { j = { running: true, label: 'running job' }; } }
      trackJob(id, { ...j, id });
    }
    showJob(id);
  }
  // A job's label names the environment it acts on (unless it already does), so tabs, toasts and the Activity list can
  // be told apart: 'vpn status · aws-dev'.
  const jobLabel = (action, args, label) => {
    label = label || String(action).replace('cloudseed_', '') || 'command';
    const tgt = args && args.cloud ? (args.env ? `${args.cloud}-${args.env}` : args.cloud) : '';
    return tgt && !label.includes(tgt) && !(args.env && label.includes(`${args.cloud}/${args.env}`)) ? `${label} · ${tgt}` : label;
  };
  // Start a job (always a registry action; the server builds the command). Errors are shown once, here; callers get
  // the job id or null (never a rejection). info.message words the confirmation, should the server ask for one.
  async function run(action, args, label, info = {}) {
    if (!action) { toast('✖ nothing to run', 'bad'); return null; }
    label = jobLabel(action, args, label);
    const key = JSON.stringify([action, args || null]);
    if (inFlight.has(key)) return null;
    inFlight.add(key);
    try {
      const r = await api('/api/run', { action, args, label });
      if (r.needs_confirm && !(args && args.confirm)) { inFlight.delete(key); return confirmRun(action, args || {}, label, { ...info, argv: r.argv }); }
      if (!r.job) throw new Error(r.error || 'the console server started nothing');
      trackJob(r.job, { id: r.job, label, running: true, argv: r.argv });
      showJob(r.job);
      return r.job;
    } catch (e) {
      const d = e.data || {};
      // 409 {needs_confirm, argv}: the tick dialog shows the exact command and sends it again with confirm:true
      if (!(args && args.confirm) && (d.needs_confirm || (e.status === 400 && /confirm/i.test(e.message)))) {
        inFlight.delete(key);
        return confirmRun(action, args || {}, label, { ...info, argv: d.argv });
      }
      if (d.job) adoptJob(d.job);   // 409 {conflict, job}: another job is working on that environment - show it
      fail(e);
      return null;
    } finally { inFlight.delete(key); }
  }
  // one-click buttons: the environment the page shows (ea) is bound when the page is drawn, never re-read at click time
  const quick = (name, args, label, ea = envArgs()) => run(name, { ...ea, ...args }, label || name.replace('cloudseed_', ''));

  // ---------------------------------------------------------------- schema forms
  // One labelled input in three parts - the label, the control, then a notes slot for the hint and any error - so a
  // form grid lines up every row's inputs (subgrid). The label is prop.label, else the server's title, else a wizard
  // question's prompt, else the argument name; that name stays visible as a small mono hint whenever the label says
  // something else. prop.hint (for plain arguments: the description) is shown under the input. placeholder = a sample
  // value, never a real one.
  function field(name, prop, required, value, placeholder) {
    const key = name.replace(/^var:/, ''), isVar = name.startsWith('var:');
    const text = prop.label || prop.title || (isVar && prop.description) || key;
    const showKey = isVar || (text !== key && text.toLowerCase() !== key.replace(/_/g, ' ').toLowerCase());   // (a variable's name is what --var takes)
    const hintText = prop.hint !== undefined ? prop.hint : !isVar && prop.description && prop.description !== text ? prop.description : null;
    let input;
    if (prop.type === 'boolean') {
      input = el('input', { type: 'checkbox', name }); if (value) input.checked = true;
      return el('label', { class: 'check' }, input, el('span', {}, el('b', {}, text), showKey ? el('span', { class: 'key' }, key) : null, hintText ? el('span', { class: 'muted small' }, ' — ' + hintText) : null));
    }
    if (prop.enum) {
      // a saved or configured value outside the list (a custom agent, an older answer) stays selectable
      const cur = value === undefined || value === null ? '' : String(value), opts = cur && !prop.enum.includes(cur) ? [...prop.enum, cur] : prop.enum;
      input = el('select', { name }, ...opts.map((v) => el('option', { value: v }, v === '' ? '(default)' : v)));
      if (!required && !opts.includes('')) input.prepend(el('option', { value: '' }, '(default)'));
      input.value = value ?? (required ? prop.enum[0] : '');
    } else if (prop.type === 'object') input = el('textarea', { name, placeholder: placeholder || '{"key": "value"}', 'data-kind': 'json', 'data-type': 'object' }, value ? JSON.stringify(value, null, 2) : '');
    // free-form list values (helm --set: `hosts={a,b}` holds commas) take one entry per line; word lists are comma-separated
    else if (prop.type === 'array' && (prop.lines || prop['x-lines'])) input = el('textarea', { name, rows: 3, placeholder: placeholder || 'one entry per line', 'data-kind': 'lines' }, Array.isArray(value) ? value.join('\n') : value || '');
    else if (prop.type === 'array') input = el('input', { name, placeholder: placeholder || 'comma-separated', 'data-kind': 'list', value: Array.isArray(value) ? value.join(',') : value || '' });
    // whole numbers only, within the schema's bounds (the browser marks 2.5 or 0 nodes as invalid before anything is sent)
    else if (prop.type === 'integer') input = el('input', { name, type: 'number', step: '1', inputmode: 'numeric', min: prop.minimum, max: prop.maximum, placeholder, value: value ?? '' });
    else if (prop.multiline) input = el('textarea', { name, rows: 3, placeholder }, value ?? '');
    // a secret is typed blind, and never offered to (or saved by) the browser's password manager
    else input = el('input', { name, type: prop.secret ? 'password' : undefined, autocomplete: prop.secret ? 'new-password' : prop.autocomplete, placeholder, value: value ?? '' });
    if (required) { input.setAttribute('aria-required', 'true'); if (!prop.enum) input.required = true; }
    const lbl = el('span', { class: 'lbl' }, text + (required ? ' *' : ''), showKey ? el('span', { class: 'key' }, key) : null);
    return el('label', { class: prop.wide ? 'wide' : null }, lbl, input, el('span', { class: 'notes' }, hintText ? el('span', { class: 'hint' }, hintText) : null));
  }
  // one input -> value (undefined = left blank); throws with a readable message on bad JSON / numbers
  function readField(inp) {
    if (inp.type === 'checkbox') return inp.checked;   // unticked is an explicit false: otherwise a saved true could never be turned off
    const v = inp.value.trim(); const nm = inp.name.replace(/^var:/, '');
    if (v === '') { if (inp.type === 'number' && inp.validity && inp.validity.badInput) throw new Error(`${nm}: not a number`); return undefined; }
    if (inp.dataset.kind === 'json') {
      let x; try { x = JSON.parse(v); } catch { throw new Error(`${nm}: not valid JSON`); }
      if (inp.dataset.type === 'object' && (x === null || typeof x !== 'object' || Array.isArray(x))) throw new Error(`${nm}: must be a JSON object like {"key": "value"}`);
      return x;
    }
    if (inp.dataset.kind === 'lines') return v.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    if (inp.dataset.kind === 'list') return v.split(',').map((s) => s.trim()).filter(Boolean);
    if (inp.type === 'number') {
      const n = Number(v); if (!Number.isFinite(n)) throw new Error(`${nm}: not a number`);
      if (inp.step === '1' && !Number.isInteger(n)) throw new Error(`${nm}: a whole number`);
      if (inp.min !== '' && n < Number(inp.min)) throw new Error(`${nm}: at least ${inp.min}`);
      if (inp.max !== '' && n > Number(inp.max)) throw new Error(`${nm}: at most ${inp.max}`);
      return n;
    }
    return v;
  }
  function readForm(form) {
    const out = {};
    for (const inp of $$('input,select,textarea', form)) {
      if (!inp.name || inp.closest('[hidden]')) continue;   // a field the chosen action does not use is not sent
      const v = readField(inp);
      if (v !== undefined) out[inp.name] = v;
    }
    return out;
  }
  const effectChip = (a) => {
    const eff = a.effect || (a.always_destructive ? 'changes' : a.destructive ? 'depends' : 'read-only');
    return eff === 'changes' ? el('span', { class: 'chip seed' }, 'changes things') : eff === 'depends' ? el('span', { class: 'chip', title: 'read-only or state-changing, depending on the action and arguments' }, 'may change things') : el('span', { class: 'chip leaf' }, 'read-only');
  };
  // Argument labels in words (the argument name itself stays visible next to them when they differ), and per-form
  // presentation: a multi-line task, helm --set values one per line, clearer wording where the registry is terse.
  const KEY_LABELS = { env: 'Environment', no_headliner: 'Skip the research brief', purge_state: 'Also delete the remote state storage', purge: 'Also delete the local directory',
    set: 'Helm values (--set)', args: 'Arguments' };
  const humanKey = (k) => KEY_LABELS[k] || k.split('_').map((w) => WORDS[w] || w).join(' ').replace(/^./, (c) => c.toUpperCase());
  const FORM_UI = {
    cloudseed_agentic: { task: { multiline: true, wide: true }, model: { description: "model id; blank = the agent's selected model" }, no_headliner: { description: 'no headliner research brief before this task' } },
    cloudseed_use: { model: { description: "model id; blank = the agent's default model" } },
    cloudseed_platform: { set: { lines: true, description: 'helm --set overrides, one key=value per line (a list like hosts={a,b} stays one value; put mode= on a line of its own)' } },
    cloudseed_destroy: { purge: { description: 'also remove the local environment directory; config.json and the SSH keys stay in the undo history, VPN keys, logs and reports do not' } },
    cloudseed_managed: { profile: { description: "blank = the profile of the environment selected at the top (else the 'default' one)" } },
    cloudseed_scan: { profile: { when: { kind: ['architecture', 'host', 'all'] } }, max_age_days: { when: { kind: ['architecture'] }, label: 'Evidence freshness (days)' },
      json: { when: { kind: ['architecture'] }, label: 'JSON output' }, framework: { when: { kind: ['kube', 'cloud'] } }, hosts: { when: { kind: ['host', 'stig', 'all'] } } },
    // fields that apply to some actions only (`when`: shown for those values; `need`: required for those values)
    cloudseed_skill: { agent: { when: { action: ['install'] } }, dir: { when: { action: ['install'] } }, name: { when: { action: ['install', 'show'] }, need: { action: ['show'] } } },
    cloudseed_vpn: { name: { need: { action: ['add-user', 'revoke'] } } },
    // (how the HTTP server is deployed - port, bearer token, login service - is setup's alone)
    cloudseed_mcp: { clients: { when: { action: ['setup', 'connect', 'disconnect'] }, need: { action: ['connect', 'disconnect'] } }, transport: { when: { action: ['setup', 'connect'] } },
      port: { when: { action: ['setup'] } }, auth: { when: { action: ['setup'] } }, service: { when: { action: ['setup'] } } },
  };
  // a field's label: the wording above, else the server's title (every /api/actions field has one), else its name in words
  const fieldLabel = (a, name) => { const prop = ((a.schema || {}).properties || {})[name] || {}, ui = (FORM_UI[a.name] || {})[name] || {}; return ui.label || prop.label || KEY_LABELS[name] || prop.title || humanKey(name); };
  // does a `when` / `need` rule hold for the values of the form's other fields ({action: ['install']}: its action is install)
  const ruleHolds = (rule, vals) => Object.entries(rule).every(([k, allowed]) => allowed.includes(vals[k] === undefined || vals[k] === null ? '' : String(vals[k])));
  const scanProfileOptions = (kind) => kind === 'architecture' ? ['production', 'lab'] : ['cis', 'stig'];
  // placeholders: sample values for a form's fields, shown greyed out (never sent)
  function actionForm(a, presets = {}, compact = false, placeholders = {}) {
    const form = el('form', { class: compact ? '' : 'card', 'data-form': a.name });
    if (!compact) form.append(el('h3', {}, a.name.replace('cloudseed_', '').replace(/_/g, ' '), explainBtn(actionXq(a.name), actionTitle(a.name)), effectChip(a)), el('p', { class: 'muted small' }, a.description));
    const grid = el('div', { class: 'form-grid' });
    const required = a.schema.required || [], ui = FORM_UI[a.name] || {};
    const ruled = [];   // [name, label element, its rules]: fields shown / required depending on another field
    for (const [name, prop] of Object.entries(a.schema.properties || {})) {
      if (name === 'confirm') continue;
      let value = presets[name];
      if (value === undefined && (name === 'cloud' || name === 'env') && currentEnv()) value = envArgs()[name];
      const f = field(name, { ...prop, ...(ui[name] || {}), label: fieldLabel(a, name) }, required.includes(name), value, placeholders[name]);
      if (ui[name] && (ui[name].when || ui[name].need)) ruled.push([name, f, ui[name]]);
      grid.append(f);
    }
    form.append(grid);
    // the values the rules look at (unparsable input counts as blank here; submitting reports it)
    const ruleVals = () => { const o = {}; for (const inp of $$('input,select,textarea', form)) if (inp.name) { try { o[inp.name] = readField(inp); } catch { o[inp.name] = undefined; } } return o; };
    const needed = (vals) => ruled.filter(([, , r]) => r.need && ruleHolds(r.need, vals) && !(r.when && !ruleHolds(r.when, vals))).map(([n]) => n);
    let confirm = null;
    const syncRules = () => {
      if (!ruled.length) return;
      const vals = ruleVals();
      if (a.name === 'cloudseed_scan') {
        if (confirm) {
          confirm.hidden = ['architecture', 'fips', 'reports'].includes(vals.kind);
          if (confirm.hidden) $('input', confirm).checked = false;
        }
        const input = $('[name="profile"]', form), options = ['', ...scanProfileOptions(vals.kind)];
        if (input && Array.from(input.options).map((o) => o.value).join(',') !== options.join(',')) {
          const previous = input.value;
          input.replaceChildren(...options.map((value) => el('option', { value }, value || '(default)')));
          input.value = options.includes(previous) ? previous : '';
        }
      }
      for (const [name, lab, r] of ruled) {
        const shown = !r.when || ruleHolds(r.when, vals), req = shown && !!r.need && ruleHolds(r.need, vals);
        lab.hidden = !shown;
        // (a hidden field is never required: the browser would refuse to submit a form over a control nobody can see)
        const inp = $(`[name="${CSS.escape(name)}"]`, lab), txt = $('.lbl', lab);
        if (inp && inp.type !== 'checkbox' && !required.includes(name)) { inp.required = req && inp.tagName !== 'SELECT'; if (req) inp.setAttribute('aria-required', 'true'); else inp.removeAttribute('aria-required'); }
        if (txt && txt.firstChild && txt.firstChild.nodeType === 3 && !required.includes(name)) txt.firstChild.textContent = txt.firstChild.textContent.replace(/ \*$/, '') + (req ? ' *' : '');
      }
    };
    form.addEventListener('change', syncRules); form.addEventListener('input', syncRules); syncRules();
    // always-destructive actions run only once the tick is set (the button says so by being disabled); for the others
    // the tick is optional: a call that turns out to change something brings up the confirmation with its command
    const tick = a.destructive ? el('input', { type: 'checkbox', name: 'confirm' }) : null;
    const runBtn = el('button', { type: 'submit', class: 'btn ' + (a.always_destructive ? 'rose' : 'primary'), disabled: !!a.always_destructive, title: a.always_destructive ? 'Tick the confirmation first' : null }, '▶ Run');
    if (tick && a.always_destructive) tick.addEventListener('change', () => { runBtn.disabled = !tick.checked; runBtn.title = tick.checked ? '' : 'Tick the confirmation first'; });
    confirm = tick ? el('label', { class: 'check' }, tick, el('span', {}, a.always_destructive ? 'I understand this changes infrastructure or runs a task' : 'Confirm changes (apply, install, add, remove, run …)')) : null;
    form.append(el('div', { class: 'row form-actions' }, confirm, el('span', { class: 'spacer' }), runBtn));
    syncRules();
    form.onsubmit = async (ev) => {
      ev.preventDefault();
      let args;
      try { args = readForm(form); } catch (e) { return toast('✖ ' + e.message, 'bad', 6000); }
      // required fields, plus those the chosen action needs (a VPN client's name, the skill show prints)
      const need = required.concat(needed(ruleVals()).filter((k) => !required.includes(k)));
      const missing = need.filter((k) => args[k] === undefined || args[k] === '' || (Array.isArray(args[k]) && !args[k].length));
      if (missing.length) { const f = $(`[name="${CSS.escape(missing[0])}"]`, form); if (f) f.focus(); return toast('✖ Fill in: ' + missing.map((k) => fieldLabel(a, k)).join(', '), 'bad', 6000); }
      // (Databricks / Snowflake use the profile of the environment in the form's cloud / env fields, which start as the
      // environment selected at the top: choosing one on this page never changes the CLI's current environment)
      // the job label says which action of the tool ran (dr schedule, vpn add-user; run() adds the environment)
      const job = await run(a.name, args, [a.name.replace('cloudseed_', '').replace(/_/g, ' '), args.action || args.kind].filter(Boolean).join(' '));
      if (job) { delete form.dataset.dirty; if ($('#modal-body').contains(form)) closeModal(); }
    };
    return form;
  }
  const action = (name) => ACTIONS.find((a) => a.name === name);
  const WORDS = { ssh: 'SSH', vpn: 'VPN', dr: 'DR', mcp: 'MCP', ip: 'IP', id: 'ID', cidr: 'CIDR', url: 'URL', os: 'OS', cis: 'CIS', k8s: 'Kubernetes', finops: 'FinOps', kubectl: 'kubectl', helm: 'helm' };
  const actionTitle = (name) => { const w = name.replace('cloudseed_', '').split('_').map((x) => WORDS[x] || x).join(' '); return w.charAt(0).toUpperCase() + w.slice(1); };
  const kv = (...pairs) => el('div', { class: 'kv' }, pairs.map(([k, val, cls]) => [el('span', { class: 'k' }, k), el('span', { class: cls || '' }, val)]));
  const heading = (text) => el('h3', { tabindex: '-1', 'data-focus': 'heading' }, text);
  const emptyState = (title, text, ...actions) => el('div', { class: 'card empty' }, el('h3', {}, title), el('p', { class: 'muted' }, text), actions.length ? el('div', { class: 'row' }, ...actions) : null);
  // a group of role=radio cards: arrow keys move the selection, like native radio buttons
  // (the new choice takes focus before it is clicked, so the redraw puts focus back on it; locked choices are skipped)
  const radios = (group) => { group.addEventListener('keydown', (ev) => { const d = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[ev.key]; if (!d) return; const r = $$('[role="radio"]:not([aria-disabled="true"])', group); const i = r.indexOf(document.activeElement); if (i < 0) return; ev.preventDefault(); const t = r[(i + d + r.length) % r.length]; t.focus(); t.click(); }); return group; };
  // Destroying deletes the cloud resources for good. Say which environment, how much it holds, what the purge options
  // also remove, and exactly what ↶ Undo can bring back (the configuration and SSH keys, with new hosts) and what not.
  const DESTROY_FINE_PRINT = 'The cloud resources are deleted for good: ↶ Undo can re-create the environment from its saved configuration and SSH keys, but with new hosts and addresses. '
    + 'purge_state also deletes the remote Terraform state storage (not recoverable). purge also removes the local environment directory: config.json and the SSH keys stay in the undo history '
    + 'until that entry is undone, discarded or pushed out of the history by newer changes; VPN keys and profiles, logs and reports are not kept.';
  const destroyNote = (presets) => {
    const e = STATE.envs.find((x) => x.cloud === presets.cloud && x.env === presets.env) || null;
    return el('div', { class: 'callout danger', role: 'note' }, el('b', {}, e ? `This deletes the cloud resources of ${e.id}` : 'This deletes the cloud resources of the environment'),
      e ? kv(['resources in state', String(e.resources)], ['region', e.region || '—'], ['Terraform state', e.state || '—'], ['working directory', e.workdir, 'mono']) : null,
      el('p', { class: 'small', style: 'margin:8px 0 0' }, 'Leave targets empty to destroy everything. ' + DESTROY_FINE_PRINT));
  };
  // the destroy confirmation says what this very call deletes (only some targets, or everything plus what purge adds)
  const destroyConfirmNote = (args, target) => {
    const where = target || 'the environment', targets = (args.targets || []).filter(Boolean);
    const also = [args.purge_state ? 'its remote Terraform state storage (not recoverable)' : '', args.purge ? 'its local directory (config.json and the SSH keys stay in the undo history; VPN keys, logs and reports do not)' : ''].filter(Boolean);
    return el('div', { class: 'callout danger', role: 'note' },
      el('b', {}, targets.length ? `Deletes only ${targets.join(', ')} in ${where}` : `This deletes the cloud resources of ${where}`),
      also.length ? el('p', { class: 'small', style: 'margin:6px 0 0' }, 'Also deleted: ' + also.join('; ') + '.') : null,
      targets.length ? null : el('p', { class: 'small', style: 'margin:6px 0 0' }, '↶ Undo can re-create it from its saved configuration and SSH keys, with new hosts and addresses.'));
  };
  // placeholders: sample values shown in the empty fields (e.g. a VPN client name), never sent as values
  const openAction = (name, presets = {}, placeholders = {}) => {
    const a = action(name); if (!a) return toast(`✖ unknown action ${name}`, 'bad');
    const e = currentEnv();
    const target = presets.cloud && presets.env ? `${presets.cloud}-${presets.env}` : (a.schema.properties || {}).env && e ? e.id : '';
    modal([actionTitle(name), presets.action, target].filter(Boolean).join(' · '),
      el('div', {}, el('p', { class: 'muted small', style: 'margin:0 0 14px' }, a.description), name === 'cloudseed_destroy' ? destroyNote(presets.cloud ? presets : envArgs()) : null, actionForm(a, presets, true, placeholders)), { narrow: true, explain: actionXq(name) });
  };
  // verdict words of the CLI and its reports ('FAIL - 2 failed' counts by its first word): PASS green; FAIL, INTERRUPTED,
  // ERROR red; INCOMPLETE/UNKNOWN/INCONCLUSIVE (nothing proved), N/A, SKIP amber; '?' neutral
  const verdictClass = (v) => {
    const t = String(v === undefined || v === null ? '' : v).trim().toUpperCase().split(/[\s:,]/)[0];
    return /^(PASS|PASSED|OK)$/.test(t) ? 'leaf' : /^(FAIL|FAILED|INTERRUPTED|ERROR|CRITICAL|HIGH)$/.test(t) ? 'rose'
      : /^(INCOMPLETE|UNKNOWN|INCONCLUSIVE|NOT_APPLICABLE|N\/A|NA|SKIP|SKIPPED|WARN|WARNING|MEDIUM|PARTIAL)$/.test(t) ? 'seed' : '';
  };
  const verdictChip = (label, v) => !v ? el('span', { class: 'chip' }, label + ': —') : el('span', { class: 'chip ' + verdictClass(v.verdict), title: v.detail }, `${label} ${v.verdict}`);

  // ---------------------------------------------------------------- explain: "?" buttons and the Explain panel
  // A "?" opens the Explain panel on one `cs explain` query: the page the CLI prints (GET /api/explain = the server's
  // explain.lookup), drawn as a page, or exactly as the terminal prints it. It is static documentation, so every
  // answer is kept for the session. The names list (GET /api/explain/names) gives the "?" tooltips their one-line
  // summary and the palette its "Explain: …" entries. tests/test_explain_web.py checks that every query this file
  // names (explainBtn / openExplain / explain: literals, the XQ_* tables, the dynamic families) is one lookup() finds.
  Object.assign(ICONS, {
    xq: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M9.6 9.3a2.5 2.5 0 0 1 4.8.9c0 1.7-2.4 2.2-2.4 3.6"/><path d="M12 17.2h.01"/></svg>',
    copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>',
    open: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
  });
  const XKIND = { index: 'Index', feature: 'Feature', target: 'Target', command: 'Command', topic: 'Topic', group: 'Platform group', item: 'Platform item', variable: 'Variable' };
  const XCLOUD = { aws: 'AWS', gcp: 'GCP', azure: 'Azure', vmware: 'VMware' };
  // the page each view's "?" (and the ? key) explains
  const XQ_VIEW = { overview: 'overview', create: 'setup', envs: 'envs', platform: 'platform', resilience: 'dr', actions: 'ui', reports: 'scan', agents: 'agentic', creds: 'creds', help: '' };
  // the wizard's Basics fields: the stack variable each one sets (or the closest page: AWS takes its region from the provider)
  const XQ_BASICS = {
    aws: { env: 'envs', name: 'variable aws name', region: 'target aws', state: 'state', cidr: 'variable aws vpc_cidr', allow_ip: 'variable aws allowed_ssh_cidrs', workdir: 'envs', tags: 'variable aws tags' },
    gcp: { env: 'envs', name: 'variable gcp name', region: 'variable gcp region', state: 'state', cidr: 'variable gcp network_cidr', allow_ip: 'variable gcp allowed_ssh_cidrs', workdir: 'envs', tags: 'variable gcp labels' },
    azure: { env: 'envs', name: 'variable azure name', region: 'variable azure location', state: 'state', cidr: 'variable azure network_cidr', allow_ip: 'variable azure allowed_ssh_cidrs', workdir: 'envs', tags: 'variable azure tags' },
    vmware: { env: 'envs', name: 'variable vmware name', cidr: 'variable vmware private_cidr', workdir: 'envs' },
  };
  // run modes of the wizard's last step, vault groups of the Credentials page, report kinds
  const XQ_MODE = { plan: 'plan', dry_run: 'setup', apply: 'apply' };
  const XQ_CREDS = { aws: 'target aws', gcp: 'target gcp', azure: 'target azure', agents: 'agentic', services: 'services', custom: 'creds' };
  const XQ_REPORT = { drill: 'dr', report: 'chaos', scan: 'scan' };
  const XQ_POPULAR = ['overview', 'network', 'bastion', 'kubernetes', 'vpn', 'state', 'platform', 'dr', 'chaos', 'scan', 'fips', 'mcp'];
  // an action's page is its command's (cloudseed_update_ip -> command update-ip); the exceptions are listed
  const XQ_ACTION = { cloudseed_vpn_connect: 'command vpn' };
  const actionXq = (name) => XQ_ACTION[name] || 'command ' + String(name).replace(/^cloudseed_/, '').replace(/_/g, '-');
  // what each scan button runs, for its tooltip (cs help scan)
  const SCAN_WHAT = { all: 'Every security scan that applies, one report each, then a summary', architecture: 'Well-Architected assessment of saved configuration and evidence; no live cloud checks', cis: 'CIS Kubernetes Benchmark with kube-bench (the profile of the distribution)',
    kube: 'kubescape posture scan: the NSA and MITRE ATT&CK frameworks', images: 'Vulnerabilities in the running workloads (trivy)',
    host: 'OpenSCAP CIS benchmark on every host reachable over SSH (bastion, VPN, local nodes)', stig: 'DISA STIG on the hosts (and the Kubernetes STIG on EKS)',
    cloud: 'prowler: the newest CIS benchmark of the cloud account', fips: 'FIPS 140 end to end: kernels, SSH/TLS algorithms, endpoints, images and installed items' };

  const xqNorm = (q) => String(q === undefined || q === null ? '' : q).trim().toLowerCase().replace(/\s+/g, ' ');
  let XNAMES = null, xnamesP = null;
  const XSUM = new Map(), XCACHE = new Map();
  // every explainable name once ({kind, name, summary, query}); found by its query and by "<kind> <name>"
  const loadNames = () => {
    if (XNAMES) return Promise.resolve(XNAMES);
    if (!xnamesP) {
      xnamesP = api('/api/explain/names').then((r) => {
        const list = Array.isArray(r && r.names) ? r.names : [];
        for (const n of list) { if (!XSUM.has(n.query)) XSUM.set(n.query, n); const k = `${n.kind} ${n.name}`; if (!XSUM.has(k)) XSUM.set(k, n); }
        XNAMES = list; return list;
      }, (err) => { xnamesP = null; throw err; });
    }
    return xnamesP;
  };
  const xqInfo = (q) => { q = xqNorm(q); return q ? XSUM.get(q) || null : { kind: 'index', name: 'everything', summary: 'Every feature, target, command, topic, platform group and item, and setup variable cloudseed can explain.' }; };
  const xqFind = (q) => { const n = XSUM.get(xqNorm(q)); return n ? n.query : null; };

  // The "?" button: small, round, a real button (keyboard, screen readers: "Explain <label>"); its tooltip is the
  // page's one-line summary. opts: cls (a variant class), fk (a focus key kept across redraws).
  const explainBtn = (q, label, opts = {}) => el('button', { type: 'button', class: 'xq' + (opts.cls ? ' ' + opts.cls : ''), 'data-explain': xqNorm(q), 'data-fk': opts.fk || null, 'aria-haspopup': 'dialog',
    'aria-label': 'Explain ' + (label || q || 'cloudseed'), html: icon('xq'), onclick: (ev) => { ev.preventDefault(); ev.stopPropagation(); openExplain(q, { from: ev.currentTarget }); } });
  // A "?" beside a form field's label. The field keeps its own accessible name (label text, argument name, hint), not
  // the button's: the label points at the field explicitly, and the field is labelled by those parts only.
  let xqSeq = 0;
  const labelExplain = (lab, q, what) => {
    const ctl = lab && $('input,select,textarea', lab); if (!ctl || q === undefined || q === null) return lab;
    if (!ctl.id) ctl.id = 'xf-' + (++xqSeq);
    const check = lab.classList.contains('check'), host = check ? $(':scope > span', lab) : $('.lbl', lab); if (!host) return lab;
    const parts = [];
    for (const n of Array.from(host.childNodes)) {
      const part = n.nodeType === 1 ? n : el('span', {}, n.textContent); if (part !== n) n.replaceWith(part);
      if (!part.id) part.id = ctl.id + '-p' + parts.length; parts.push(part.id);
    }
    const hint = check ? null : $('.notes .hint', lab); if (hint) { if (!hint.id) hint.id = ctl.id + '-h'; parts.push(hint.id); }
    const btn = explainBtn(q, what || (host.textContent || '').replace(/\s*\*\s*$/, '').trim(), { fk: 'xq:' + (ctl.name || ctl.id) });
    if (check && host.firstElementChild) host.firstElementChild.after(btn); else host.append(btn);
    lab.htmlFor = ctl.id; ctl.setAttribute('aria-labelledby', parts.join(' '));
    return lab;
  };
  // a "?" at the top-right corner of a card that is itself a control (the wizard's cloud and mode cards): beside it, not inside it
  const xqCorner = (node, q, label) => el('div', { class: 'xq-host' }, node, explainBtn(q, label, { fk: 'xq:' + (node.dataset.fk || q) }));

  // ---- the tooltip: the summary of the page a "?" opens (after a short hover, or at once on keyboard focus)
  const xtip = $('#xtip'); let xtipFor = null, xtipTimer = 0;
  const hideTip = () => { clearTimeout(xtipTimer); if (xtipFor) { xtipFor.removeAttribute('aria-describedby'); xtipFor = null; } xtip.classList.remove('show'); xtip.hidden = true; };
  const showTip = (b) => {
    if (!b.isConnected) return;
    // what kind of page, its one-line summary, and the same page in a terminal
    const q = b.dataset.explain || '', info = xqInfo(q);
    xtip.innerHTML = '';
    xtip.append(el('span', { class: 'k' }, info ? (XKIND[info.kind] || info.kind) + (info.kind === 'variable' ? ' · ' + (XCLOUD[info.name.split(' ')[0]] || '') : '') : 'Explain'),
      el('span', { class: 's' }, info ? info.summary : 'Opens the explanation: the page cs explain prints.'), el('code', { class: 'c' }, ('cs explain ' + q).trim()));
    xtip.hidden = false; xtip.classList.remove('show'); xtip.style.left = '0px'; xtip.style.top = '0px';
    const r = b.getBoundingClientRect(), w = xtip.offsetWidth, h = xtip.offsetHeight, pad = 8;
    let top = r.top - h - 10, side = 'above';
    if (top < pad) { top = r.bottom + 10; side = 'below'; }
    const left = Math.round(Math.max(pad, Math.min(r.left + r.width / 2 - w / 2, innerWidth - w - pad)));
    xtip.style.left = left + 'px'; xtip.style.top = Math.round(top) + 'px'; xtip.dataset.side = side;
    xtip.style.setProperty('--ax', Math.round(Math.max(12, Math.min(w - 12, r.left + r.width / 2 - left))) + 'px');
    b.setAttribute('aria-describedby', 'xtip'); xtipFor = b;
    requestAnimationFrame(() => { if (xtipFor === b) xtip.classList.add('show'); });
  };
  const xqOf = (t) => (t && t.closest ? t.closest('.xq') : null);
  document.addEventListener('pointerover', (e) => {
    const b = xqOf(e.target); if (!b || e.pointerType !== 'mouse' || b === xtipFor) return;
    if (!XNAMES) loadNames().catch(() => null);
    clearTimeout(xtipTimer); xtipTimer = setTimeout(() => showTip(b), 380);
  });
  document.addEventListener('pointerout', (e) => { const b = xqOf(e.target); if (!b || (e.relatedTarget && b.contains(e.relatedTarget))) return; hideTip(); });
  let xtipQuiet = false;   // while the closing panel gives focus back (closeExplain)
  document.addEventListener('focusin', (e) => {
    const b = xqOf(e.target);
    if (b && xtipQuiet) return;
    if (b && b.matches(':focus-visible')) { clearTimeout(xtipTimer); xtipTimer = setTimeout(() => showTip(b), 150); } else if (xtipFor || xtipTimer) hideTip();
  });
  document.addEventListener('focusout', (e) => { if (xqOf(e.target) && (xtipFor === xqOf(e.target) || xtipTimer)) hideTip(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && xtipFor) hideTip(); }, true);
  addEventListener('scroll', () => { if (xtipFor) hideTip(); }, true); addEventListener('resize', () => { if (xtipFor) hideTip(); });

  // ---- page rendering (the panel and the Help page share it). A text section is laid out for a 100-column terminal;
  // xpBlocks reflows it: hard-wrapped prose becomes paragraphs, "- " bullets lists (their indented continuation lines
  // joined), "term   description" rows definitions (a line indented to the description column continues it, a less
  // indented one is a note under the term), and a line is a command row only when it is one of the page's own commands
  // (lookup()'s `commands`, the same cut the server makes). A section drawn with box characters stays preformatted.
  const xpBlocks = (lines, cmds) => {
    const known = new Set(cmds || []), out = []; let cur = null;
    lines = (lines || []).map((l) => String(l).replace(/\s+$/, ''));
    if (lines.some((l) => /[│┃║╭╮╰╯┌┐└┘├┤┬┴┼]/.test(l))) return [{ type: 'pre', text: lines.join('\n') }];
    const flush = () => { if (cur) out.push(cur); cur = null; };
    const start = (b) => { flush(); cur = b; return b; };
    for (const line of lines) {
      const t = line.trim(); if (!t) { flush(); continue; }
      const ind = line.length - line.replace(/^\s+/, '').length;
      const cm = /^(cloudseed|cs) (\S.*)$/.exec(t);
      if (cm) {
        const head = cm[2].split(/\s+#|\s{3,}|\s+·\s+/)[0].trim();
        if (known.has('cs ' + head)) {
          const note = cm[2].slice(head.length).trim().replace(/^[#·]\s*/, '');
          if (!cur || cur.type !== 'cmd') start({ type: 'cmd', ind, rows: [] });
          cur.rows.push({ cmd: cm[1] + ' ' + head, key: 'cs ' + head, note });
          continue;
        }
      }
      const bm = /^[-*•] (\S.*)$/.exec(t);
      if (bm) { if (!cur || cur.type !== 'ul' || cur.ind !== ind) start({ type: 'ul', ind, items: [] }); cur.items.push(bm[1]); continue; }
      if (cur && ind > cur.ind && cur.type !== 'p') {
        if (cur.type === 'ul') { cur.items[cur.items.length - 1] += ' ' + t; continue; }
        const row = cur.rows[cur.rows.length - 1];
        if (cur.type === 'cmd') { row.note = row.note ? row.note + ' ' + t : t; continue; }
        if (row.desc && ind >= row.col - 2 && !row.more) row.desc += ' ' + t; else row.more = row.more ? row.more + ' ' + t : t;
        continue;
      }
      const dm = /^(\S(?:.*?\S)?)\s{2,}(\S.*)$/.exec(t);
      if (dm && dm[1].length <= 40 && dm[1].split(' ').length <= 5 && !/[.,;]$/.test(dm[1])) {
        if (!cur || cur.type !== 'dl' || cur.ind !== ind) start({ type: 'dl', ind, rows: [] });
        cur.rows.push({ term: dm[1], desc: dm[2].replace(/\s{2,}/g, ' '), col: line.indexOf(dm[2], ind + dm[1].length), more: '' });
        continue;
      }
      if (cur && cur.type === 'p' && cur.ind === ind) { cur.text += ' ' + t; continue; }
      start({ type: 'p', ind, text: t });
    }
    flush();
    return out;
  };
  // how a list section is drawn: commands, "key: value" facts, "name — description" entries, or plain bullets
  const xpListKind = (lines) => {
    const ls = (lines || []).filter(Boolean); if (!ls.length) return 'plain';
    if (ls.every((l) => /^(cs|cloudseed) \S/.test(l))) return 'cmd';
    if (ls.every((l) => /^[\w .+[\]-]{1,40}: \S/.test(l))) return 'kv';
    if (ls.every((l) => /^\S+ — \S/.test(l))) return 'links';
    return 'plain';
  };
  const xpCopy = (text, label) => el('button', { type: 'button', class: 'xp-icon', title: 'Copy', 'aria-label': label || 'Copy', html: icon('copy'), onclick: () => copyText(text, 'Command') });
  const xpLink = (text, q, nav) => el('button', { type: 'button', class: 'xp-link', onclick: () => nav(q) }, text);
  const xpPill = (kind, name, q, nav) => el('button', { type: 'button', class: 'xp-pill', onclick: (ev) => nav(q, ev) }, kind ? el('span', { class: 'k' }, kind) : null, el('span', {}, name), el('span', { class: 'arrow', html: icon('open') }));
  // command rows: the command, its note, Copy - and Open for a `cs explain …` of something explainable
  const xpCmds = (rows, ctx) => el('div', { class: 'xp-cmds' }, rows.map(({ cmd, note, key }) => {
    ctx.shown.add(key || cmd);
    const ex = /^(?:cs|cloudseed) explain (.+)$/.exec(cmd), xq = ex && !/[<>|[\]]/.test(ex[1]) ? ex[1].replace(/\s+--json$/, '') : null;
    return el('div', { class: 'xp-cmd' }, el('div', {}, el('code', {}, cmd), note ? el('span', { class: 'note' }, note) : null),
      xq ? el('button', { type: 'button', class: 'xp-icon', title: 'Open', 'aria-label': `Open the explanation of ${xq}`, html: icon('open'), onclick: () => ctx.nav(xq) }) : null,
      xpCopy(cmd, `Copy the command ${cmd}`));
  }));
  const xpTags = (s) => { const tags = []; const text = s.replace(/\s{2,}(\[[^\]]*\]|\(dependency\))/g, (m, t) => { tags.push(t.slice(1, -1)); return ''; }).trim(); return [text, tags]; };
  const xpValue = (k, v, ctx) => {
    if (/^(cs|cloudseed) \S/.test(v)) return xpCmds([{ cmd: v }], ctx);
    if (k === 'group' && xqFind('group ' + v)) return xpLink(v, xqFind('group ' + v), ctx.nav);
    if (/^needs\b/.test(k)) return v.split(/,\s*/).map((x, i) => [i ? ', ' : '', xqFind('item ' + x) ? xpLink(x, xqFind('item ' + x), ctx.nav) : x]);
    return withCode(v);
  };
  const xpList = (lines, ctx) => {
    const kind = xpListKind(lines);
    if (kind === 'cmd') return xpCmds(lines.map((l) => ({ cmd: l, key: l.replace(/^cloudseed /, 'cs ') })), ctx);
    if (kind === 'kv') {
      const pairs = lines.filter(Boolean).map((l) => { const i = l.indexOf(': '); return [l.slice(0, i), l.slice(i + 2)]; });
      const main = pairs.filter(([k]) => !/^values\[/.test(k)), vals = pairs.filter(([k]) => /^values\[/.test(k));
      const grid = (ps, mono) => el('div', { class: 'kv xp-kv' + (mono ? ' mono-v' : '') }, ps.map(([k, v]) => [el('span', { class: 'k' }, k), el('span', {}, mono ? v : xpValue(k, v, ctx))]));
      return [main.length ? grid(main) : null, vals.length ? el('details', { class: 'xp-more' }, el('summary', {}, `Helm values (${vals.length})`), grid(vals, true)) : null];
    }
    if (kind === 'links') {
      return el('ul', { class: 'xp-ul xp-links' }, lines.filter(Boolean).map((l) => {
        const i = l.indexOf(' — '), name = l.slice(0, i), [desc, tags] = xpTags(l.slice(i + 3));
        const q = xqFind('item ' + name) || xqFind('group ' + name) || xqFind(name);
        return el('li', {}, q ? xpLink(name, q, ctx.nav) : el('b', {}, name), el('span', { class: 'muted' }, ' — '), withCode(desc), tags.map((t) => el('span', { class: 'chip outline xp-tag' }, t)));
      }));
    }
    return el('ul', { class: 'xp-ul' }, lines.filter(Boolean).map((l) => {
      const m = /^(\S*(?:\/|\.(?:py|ya?ml|json|jsonl|tf|md|sh|log|ovpn)\b)\S*|<\w+>\S*)(\s.*)?$/.exec(l);
      return el('li', {}, m ? [el('code', { class: 'xp-path' }, m[1]), m[2] ? el('span', { class: 'muted' }, withCode(m[2])) : null] : withCode(l));
    }));
  };
  const xpText = (lines, ctx) => xpBlocks(lines, ctx.commands).map((b) => {
    if (b.type === 'pre') return el('pre', { class: 'xp-pre' }, b.text);
    if (b.type === 'p') return el('p', { class: 'xp-p' }, withCode(b.text));
    if (b.type === 'ul') return el('ul', { class: 'xp-ul' }, b.items.map((x) => el('li', {}, withCode(x))));
    if (b.type === 'cmd') return xpCmds(b.rows, ctx);
    return el('dl', { class: 'xp-dl' }, b.rows.map((row) => {
      const meta = /^default: /.test(row.desc), vq = ctx.cloud ? xqFind(`variable ${ctx.cloud} ${row.term}`) : null;
      return [el('dt', {}, vq && vq !== ctx.self ? xpLink(row.term, vq, ctx.nav) : el('span', {}, row.term), meta ? el('span', { class: 'xp-meta' }, row.desc) : null),
        !meta && row.desc ? el('dd', {}, withCode(row.desc)) : null, row.more ? el('dd', { class: 'more' }, withCode(row.more)) : null];
    }));
  });
  // the index: everything explainable by kind, with a filter; the long groups (commands, items, variables) start folded
  const XINDEX_OPEN = new Set(['Features', 'Targets', 'Topics', 'Platform groups']);
  const xpIndex = (r, nav) => {
    const wrap = el('div', { class: 'xp-index' });
    const filter = el('input', { type: 'search', class: 'xp-filter', placeholder: 'Filter everything…', 'aria-label': 'Filter what can be explained', autocomplete: 'off', 'data-nodirty': '', 'aria-describedby': 'xp-filter-n' });
    const count = el('span', { class: 'sr-only', id: 'xp-filter-n', 'aria-live': 'polite' });
    const kinds = { Features: 'feature', Targets: 'target', Commands: 'command', Topics: 'topic', 'Platform groups': 'group', 'Platform items': 'item' };
    const groups = (r.sections || []).map((s) => {
      const kind = kinds[s.heading] || (/variables$/.test(s.heading) ? 'variable' : '');
      const rows = s.lines.map((l) => {
        const i = l.indexOf(' — '), name = i > 0 ? l.slice(0, i) : l, summary = i > 0 ? l.slice(i + 3) : '';
        const q = xqFind(`${kind} ${name}`) || (kind === 'topic' || kind === 'variable' ? (kind === 'variable' ? 'variable ' + name : name) : `${kind} ${name}`);
        const label = kind === 'variable' ? name.replace(/^\S+ /, '') : name;
        const li = el('li', {}, el('button', { type: 'button', class: 'xp-row', onclick: () => nav(q) }, el('b', {}, label), summary ? el('span', {}, summary) : null));
        li.dataset.hay = (name + ' ' + summary).toLowerCase();
        return li;
      });
      const d = el('details', { class: 'xp-group', open: XINDEX_OPEN.has(s.heading) }, el('summary', {}, s.heading, el('span', { class: 'chip' }, rows.length)), el('ul', { class: 'xp-rows' }, rows));
      d.dataset.open = XINDEX_OPEN.has(s.heading) ? '1' : '';
      return [d, rows];
    });
    filter.oninput = () => {
      const q = xqNorm(filter.value), words = q.split(' ').filter(Boolean); let n = 0;
      for (const [d, rows] of groups) {
        let any = 0;
        for (const li of rows) { const hit = words.every((w) => li.dataset.hay.includes(w)); li.hidden = !hit; any += hit ? 1 : 0; }
        n += any; d.hidden = !any; d.open = q ? any > 0 : !!d.dataset.open;
      }
      count.textContent = q ? `${n} match${n === 1 ? '' : 'es'}` : '';
    };
    wrap.append(filter, count, ...groups.map(([d]) => d));
    return wrap;
  };
  // the body of a page: its sections, any command not shown yet, what else the words name, or (not found) suggestions
  const xpPage = (r, nav, opts = {}) => {
    const out = el('div', { class: 'xp-rich' });
    if (!r.found) {
      const dym = r.did_you_mean || [];
      out.append(el('section', { class: 'xp-sec' }, dym.length ? el('h3', { class: 'xp-h' }, 'Did you mean') : null, dym.length ? el('div', { class: 'xp-pills' }, dym.map((q) => xpPill('', q, q, nav))) : null,
        el('div', { class: 'xp-empty' }, el('p', { class: 'muted' }, dym.length ? 'Or look through everything cloudseed can explain.' : 'Nothing by that name. Look through everything cloudseed can explain, or search from the palette.'),
          el('div', { class: 'row' }, el('button', { type: 'button', class: 'btn ghost small', onclick: () => nav('') }, 'Browse everything'), opts.palette ? el('button', { type: 'button', class: 'btn ghost small', onclick: opts.palette }, `Search (${MOD}K)`) : null))));
      return out;
    }
    if (r.kind === 'index') { out.append(xpIndex(r, nav)); return out; }
    const tv = /^(?:variables|outputs) (\w+)$/.exec(r.name || '');
    const ctx = { commands: r.commands || [], shown: new Set(), nav, cloud: r.cloud || (r.kind === 'target' ? r.name : tv ? tv[1] : ''), self: r.query };
    for (const s of r.sections || []) out.append(el('section', { class: 'xp-sec' }, el('h3', { class: 'xp-h' }, s.heading), s.format === 'list' ? xpList(s.lines || [], ctx) : xpText(s.lines || [], ctx)));
    const rest = (r.commands || []).filter((c) => !ctx.shown.has(c));
    if (rest.length) out.append(el('section', { class: 'xp-sec' }, el('h3', { class: 'xp-h' }, 'Commands'), xpCmds(rest.map((c) => ({ cmd: c, key: c })), ctx)));
    if ((r.also || []).length) out.append(el('section', { class: 'xp-sec xp-also' }, el('h3', { class: 'xp-h' }, 'Also explained as'), el('div', { class: 'xp-pills' }, r.also.map((a) => xpPill(XKIND[a.kind] || a.kind, a.name, a.query, nav)))));
    return out;
  };
  const xpHead = (r) => ({
    kind: !r.found ? [el('span', { class: 'chip rose' }, 'Not found')] : [el('span', { class: 'chip brand' }, XKIND[r.kind] || r.kind), r.cloud ? el('span', { class: 'chip' }, XCLOUD[r.cloud] || r.cloud) : null],
    title: r.found ? r.title || r.name : r.query ? `Nothing to explain for “${r.query}”` : 'Nothing to explain',
    summary: r.found ? r.summary : r.error && /too long/.test(r.error) ? r.error : '',
  });
  const xpFetch = async (q) => {
    q = xqNorm(q);
    if (XCACHE.has(q)) return XCACHE.get(q);
    const r = await api('/api/explain?q=' + encodeURIComponent(q));
    XCACHE.set(q, r); return r;
  };

  // ---- the panel: a right-hand sheet (a bottom sheet on phones) over the page. It keeps a history (Back), traps the
  // keyboard while open, closes on Esc or the backdrop, and gives focus back to the "?" that opened it.
  const xp = $('#explain'), xpSheet = $('#xp-sheet'), xpBodyEl = $('#xp-body');
  const XP = { stack: [], from: null, seq: 0, closing: 0, plain: store.get('cs-xp-plain') === '1' };
  const xpOpen = () => !xp.classList.contains('hidden');
  layers.unshift([xp, () => $('#xp-title')]);   // the topmost layer: the page (and a dialog under it) is inert while it is open
  new MutationObserver(syncLayers).observe(xp, { attributes: true, attributeFilter: ['class'], childList: true, subtree: true });
  const xpFocus = () => { const a = document.activeElement; if (!a || a === document.body || !xpSheet.contains(a) || !a.offsetParent) $('#xp-title').focus({ preventScroll: true }); };
  function openExplain(q, opts = {}) {
    q = xqNorm(q); hideTip();
    if (!palette.classList.contains('hidden')) closePalette();   // (a palette entry opened it)
    if (XP.closing) { clearTimeout(XP.closing); XP.closing = 0; xp.classList.remove('closing'); }
    if (!xpOpen()) {
      const a = document.activeElement;
      XP.stack = []; XP.from = opts.from || (a && a !== document.body && !a.closest('.hidden') ? a : null);
    } else if (XP.stack.length) {
      const top = XP.stack[XP.stack.length - 1];
      if (top.q === q) { xpShow(); return; }   // (the page on show: no second history entry)
      top.scroll = xpBodyEl.scrollTop;
    }
    XP.stack.push({ q, scroll: 0 });
    xp.classList.remove('hidden');
    xpShow();
  }
  // opts.instant: no closing animation; opts.keep: leave focus where the caller puts it
  function closeExplain(opts = {}) {
    if (!xpOpen() || XP.closing) return;
    hideTip();
    const back = opts.keep ? null : XP.from, first = XP.stack.length ? XP.stack[0].q : null;
    const done = () => {
      XP.closing = 0; XP.seq++; xp.classList.remove('closing'); xp.classList.add('hidden');
      xtipQuiet = true;   // (focus going back to a "?" shows no tooltip: its page was just on screen)
      syncLayers();   // the page is no longer inert: focus can go back now
      if (opts.keep) { xtipQuiet = false; return; }
      const again = first !== null ? $(`.view.active .xq[data-explain="${CSS.escape(first)}"], #crumb-xq[data-explain="${CSS.escape(first)}"]`) : null;
      const to = back && back.isConnected && back.offsetParent && !back.closest('[inert]') ? back : again;
      if (to) to.focus({ preventScroll: true });
      xtipQuiet = false;
    };
    if (opts.instant || matchMedia('(prefers-reduced-motion: reduce)').matches) { done(); return; }
    xp.classList.add('closing'); XP.closing = setTimeout(done, 170);
  }
  const xpSetHead = (h) => {
    const k = $('#xp-kind'); k.innerHTML = ''; k.append(...h.kind.filter(Boolean));
    $('#xp-title').textContent = h.title; $('#xp-summary').textContent = h.summary || '';
  };
  const xpNav = (q) => openExplain(q);
  const xpFooter = (r) => {
    const f = $('#xp-foot'); f.innerHTML = '';
    if (!r) return;
    f.append(el('span', { class: 'xp-cli-l' }, 'CLI'), el('code', { class: 'xp-cli', title: r.cli }, r.cli), xpCopy(r.cli, `Copy the command ${r.cli}`), el('span', { class: 'spacer' }));
    if (r.found && VIEW !== 'help' && !modalOpen()) f.append(el('button', { type: 'button', class: 'btn ghost small', onclick: () => { const q = r.query; closeExplain({ instant: true, keep: true }); showHelpExplain(q); } }, 'Open in Help'));
  };
  async function xpShow() {
    const top = XP.stack[XP.stack.length - 1]; if (!top) return;
    const seq = ++XP.seq, q = top.q;
    $('#xp-back').hidden = XP.stack.length < 2;
    let r = XCACHE.get(q);
    if (!r || (r.kind === 'index' && !XNAMES)) {
      xpSetHead({ kind: [el('span', { class: 'chip' }, 'Loading')], title: q || 'Everything you can explain', summary: '' });
      xpBodyEl.innerHTML = ''; xpBodyEl.setAttribute('aria-busy', 'true'); xpFooter(null);
      xpBodyEl.append(el('div', { class: 'xp-sk', 'aria-hidden': 'true' }, el('b'), el('i'), el('i'), el('i', { class: 'w70' }), el('b'), el('i', { class: 'w85' }), el('i'), el('i', { class: 'w50' })), el('span', { class: 'sr-only' }, 'Loading…'));
      xpFocus();
      try { [r] = await Promise.all([xpFetch(q), loadNames().catch(() => null)]); }
      catch (err) {
        if (seq !== XP.seq) return;
        xpBodyEl.removeAttribute('aria-busy');
        xpSetHead({ kind: [el('span', { class: 'chip rose' }, 'Error')], title: 'Could not load this explanation', summary: '' });
        xpBodyEl.innerHTML = '';
        xpBodyEl.append(el('div', { class: 'callout warn', role: 'alert', style: 'margin-top:16px' }, el('b', {}, `cs explain ${q}`.trim()), el('p', { class: 'small mono', style: 'margin:6px 0 10px' }, err.message || String(err)),
          el('button', { type: 'button', class: 'btn small primary', html: icon('refresh'), onclick: xpShow }, el('span', {}, 'Retry'))));
        xpFocus();
        return;
      }
      if (seq !== XP.seq) return;
    }
    xpBodyEl.removeAttribute('aria-busy');
    xpSetHead(xpHead(r));
    xpBodyEl.innerHTML = '';
    xpBodyEl.append(XP.plain && r.text ? el('pre', { class: 'help xp-term', tabindex: '0', 'aria-label': `cs explain ${r.query}`.trim() }, r.text) : xpPage(r, xpNav, { palette: () => { closeExplain({ instant: true }); openPalette(); } }));
    xpFooter(r);
    xpBodyEl.scrollTop = top.scroll || 0;
    xpFocus();
  }
  const xpMode = (plain) => {
    XP.plain = plain; store.set('cs-xp-plain', plain ? '1' : '0');
    $('#xp-rich').setAttribute('aria-pressed', String(!plain)); $('#xp-plain').setAttribute('aria-pressed', String(plain));
    if (xpOpen()) { const top = XP.stack[XP.stack.length - 1]; if (top) top.scroll = 0; xpShow(); }
  };
  xpMode(XP.plain);
  $('#xp-rich').onclick = () => xpMode(false); $('#xp-plain').onclick = () => xpMode(true);
  $('#xp-back').onclick = () => { if (XP.stack.length > 1) { XP.stack.pop(); xpShow(); } };
  $('#xp-close').onclick = () => closeExplain();
  $('#xp-scrim').onclick = () => closeExplain();
  xpSheet.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeExplain(); return; }
    if (e.key === 'ArrowLeft' && e.altKey && XP.stack.length > 1) { e.preventDefault(); $('#xp-back').click(); return; }
    if (e.key !== 'Tab') return;
    const f = $$('button, a[href], input, select, textarea, summary, [tabindex]:not([tabindex="-1"])', xpSheet).filter((n) => !n.disabled && n.offsetParent !== null);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1], a = document.activeElement;
    if (e.shiftKey && (a === first || a === $('#xp-title') || !xpSheet.contains(a))) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && (a === last || !xpSheet.contains(a))) { e.preventDefault(); first.focus(); }
  });
  // the page's own "?" in the top bar follows the view (the ? key opens the same page)
  const xqCrumb = (view) => { const b = $('#crumb-xq'), label = (NAV.find((n) => n[0] === view) || [0, view])[1]; b.dataset.explain = XQ_VIEW[view] ?? ''; b.setAttribute('aria-label', `Explain this page (${label})`); };
  $('#crumb-xq').onclick = (ev) => openExplain($('#crumb-xq').dataset.explain, { from: ev.currentTarget });
  // "Open in Help": the page, full width, in the Help view
  function showHelpExplain(q) { helpNext = { explain: xqNorm(q), focus: true }; go('help'); }

  // ---------------------------------------------------------------- views
  const views = {};
  // Views drawn from STATE are redrawn when it changes (a job finished, the poll saw news) - but never while the user
  // is typing in them: a redraw would wipe the input. They are redrawn on the next navigation instead.
  const DATA_VIEWS = new Set(['overview', 'envs', 'platform', 'resilience', 'reports', 'agents', 'creds']);
  function editing(sec) {
    if (!sec) return false;
    if (sec.dataset.dirty || sec.querySelector('[data-dirty]')) return true;
    const a = document.activeElement;
    return !!(a && sec.contains(a) && a.matches('input,textarea,select') && !a.hasAttribute('data-nodirty'));
  }
  const markDirty = (ev) => { const t = ev.target; if (!t || !t.matches || !t.matches('input,textarea,select') || t.hasAttribute('data-nodirty')) return; const holder = t.closest('form') || t.closest('.view'); if (holder) holder.dataset.dirty = '1'; };
  $('#main').addEventListener('input', markDirty); $('#main').addEventListener('change', markDirty);
  // Keyboard focus survives a redraw: the element with the same data-fk, else the one with the same role and text that
  // sits nearest to the old one's place among the view's focusable elements.
  const FOCUSABLE = 'button, a[href], [tabindex]:not([tabindex="-1"]), input, select, textarea, summary';
  const focusMark = (sec) => {
    const a = document.activeElement; if (!a || a === document.body || !sec.contains(a)) return null;
    if (a.dataset && a.dataset.fk) return { fk: a.dataset.fk, caret: typeof a.selectionStart === 'number' ? [a.selectionStart, a.selectionEnd] : null };
    return { i: $$(FOCUSABLE, sec).indexOf(a), tag: a.tagName, text: (a.textContent || '').trim() };
  };
  const focusBack = (sec, m) => {
    if (!m) return;
    let n = m.fk ? sec.querySelector(`[data-fk="${CSS.escape(m.fk)}"]`) : null;
    if (!n && !m.fk) { const all = $$(FOCUSABLE, sec); let best = Infinity; all.forEach((x, i) => { if (x.tagName === m.tag && (x.textContent || '').trim() === m.text && Math.abs(i - m.i) < best) { best = Math.abs(i - m.i); n = x; } }); }
    if (n) { n.focus({ preventScroll: true }); if (m.caret) try { n.setSelectionRange(m.caret[0], m.caret[1]); } catch { /* not a text input */ } }
  };
  function refreshView() {
    if (!STATE || !DATA_VIEWS.has(VIEW)) return;
    const sec = $('#view-' + VIEW);
    // someone is typing here: the view is redrawn later, but its live controls (switches, chips) follow the state now
    if (editing(sec)) { sec.dataset.stale = '1'; if (views[VIEW].patch) views[VIEW].patch(); return; }
    delete sec.dataset.stale;
    const mark = focusMark(sec);
    const top = $('#main').scrollTop;
    let drawn; try { drawn = views[VIEW](); } catch (err) { viewError(err); return; }
    Promise.resolve(drawn).then(() => { $('#main').scrollTop = top; focusBack(sec, mark); }).catch(viewError);
  }
  function viewError(err) { console.error(err); toast('✖ ' + (err && err.message || err), 'bad', 6000); }

  views.overview = () => {
    const v = $('#view-overview'); v.innerHTML = '';
    const s = STATE;
    const clusters = s.envs.filter((e) => e.kubernetes).length, resources = s.envs.reduce((a, e) => a + (e.resources || 0), 0);
    const running = Array.from(jobs.values()).filter((j) => j.running).length;
    v.append(el('div', { class: 'hero' }, el('h2', {}, s.envs.length ? `Good to see you. ${s.envs.length} environment${s.envs.length > 1 ? 's' : ''}, ${clusters} cluster${clusters === 1 ? '' : 's'}.` : 'Welcome to cloudseed'),
      el('p', {}, 'Secure landing zones on AWS, Google Cloud, Azure and local VMware; Kubernetes platforms; DR, chaos and compliance — every action here runs the same cloudseed command the CLI and the MCP server run, streamed live into Activity.'),
      el('div', { class: 'row' }, el('button', { class: 'btn ghost', html: icon('create'), onclick: () => go('create', { env: null }) }, el('span', {}, 'Create environment')), el('button', { class: 'btn ghost', html: icon('platform'), onclick: () => go('platform') }, el('span', {}, 'Platform catalog')),
        el('button', { class: 'btn ghost', html: icon('doctor'), 'data-fk': 'hero:doctor', onclick: () => run('cloudseed_doctor', {}, 'doctor') }, el('span', {}, 'Doctor')), el('button', { class: 'btn ghost', html: icon('search'), 'aria-keyshortcuts': 'Meta+K Control+K', onclick: openPalette }, el('span', {}, 'Search'), el('span', { class: 'kbd', 'aria-hidden': 'true' }, MOD + 'K')))));
    const tiles = el('div', { class: 'tiles' });
    // clickable tiles become buttons (el() adds role/tabindex) and only those lift on hover; colour carries state, never decoration
    const tile = (l, val, sub, cls, onclick) => el('div', { class: 'tile ' + cls, onclick, 'aria-label': onclick ? `${l}: ${val}. ${sub}` : null }, el('div', { class: 'l' }, l), el('div', { class: 'v' }, val), el('div', { class: 's' }, sub));
    const pendingK8s = s.envs.filter((e) => !e.kubernetes && e.vars && e.vars.enable_kubernetes).length;
    tiles.append(tile('Environments', s.envs.length, s.envs.map((e) => e.cloud).filter((c, i, a) => a.indexOf(c) === i).join(' · ') || 'none yet', s.envs.length ? 'brand' : '', () => go('envs')),
      tile('Clusters', clusters, clusters ? s.envs.filter((e) => e.kubernetes).map((e) => e.id).join(', ') : pendingK8s ? `${pendingK8s} enabled, not applied yet` : 'none yet · enable Kubernetes in Create → Options', clusters ? 'leaf' : '', () => (clusters ? go('platform') : go('create', { env: null }))),
      tile('Resources in state', resources, 'across all environments', ''),
      tile('Running jobs', running, `${s.jobs.length} recent`, running ? 'seed' : '', () => setDrawer(!drawer.classList.contains('open'))),
      tile('MCP', s.mcp.url ? (s.mcp.running ? 'up' : 'down') : s.mcp.enabled ? 'stdio' : 'off', s.mcp.url || 'cs setup mcp', s.mcp.running || (s.mcp.enabled && !s.mcp.url) ? 'leaf' : '', () => go('agents')),
      tile('Agent', s.settings.agentic ? (s.settings.agent || 'builtin') : 'off', s.settings.headliner !== false ? 'headliner on' : 'headliner off', s.settings.agentic ? 'leaf' : '', () => go('agents')));
    v.append(tiles);
    const grid = el('div', { class: 'grid cols-3' });
    for (const e of s.envs) grid.append(envCard(e));
    if (!s.envs.length) grid.append(noEnvs());
    v.append(grid);
    const lower = el('div', { class: 'grid cols-2', style: 'margin-top:16px' });
    const tools = el('div', { class: 'card' }, el('h3', {}, 'Toolchain & credentials', explainBtn('dependencies', 'tools and dependencies')));
    for (const [cloud, rows] of Object.entries(s.tools)) {
      // required tools, plus a CLI the cloud needs unless another sign-in is set up (the server marks it `needed`:
      // az without ARM_* service-principal variables) - that one is a warning, not a failure
      const missing = rows.filter((r) => !r.ok && r.required), needed = rows.filter((r) => !r.ok && !r.required && r.needed), fix = missing.concat(needed);
      const chip = missing.length ? el('span', { class: 'chip rose', title: missing.map((r) => `${r.tool}: ${r.desc || 'required'}`).join('\n') }, `${missing.length} missing`)
        : needed.length ? el('span', { class: 'chip seed', title: needed.map((r) => `${r.tool}: ${r.need_note || r.desc || 'needed to sign in'}`).join('\n') }, `${needed.map((r) => r.tool).join(', ')} missing`)
          : el('span', { class: 'chip leaf' }, 'tools ok');
      tools.append(el('div', { class: 'row', style: 'padding:6px 0;border-bottom:1px solid var(--line)' }, el('span', { class: 'glyph sm ' + cloud, 'aria-hidden': 'true' }, CLOUD[cloud]), el('b', {}, s.clouds[cloud].display),
        chip, el('span', { class: 'spacer' }),
        el('button', { class: 'btn ghost small', 'data-fk': 'doctor:' + cloud, onclick: () => run('cloudseed_doctor', { cloud }, 'doctor ' + cloud) }, 'Doctor'),
        fix.length ? el('button', { class: 'btn small primary', 'data-fk': 'install:' + cloud, onclick: () => run('cloudseed_deps', { action: 'install', tools: fix.map((r) => r.tool) }, 'install ' + fix.map((r) => r.tool).join(' ')) }, 'Install') : null));
    }
    tools.append(el('p', { class: 'muted small', style: 'margin-top:10px' }, 'Credentials come from your shell, cloud CLIs, or the local vault → ', el('a', { href: '#', onclick: (e) => { e.preventDefault(); go('creds'); } }, 'Credentials')));
    lower.append(tools);
    const act = el('div', { class: 'card' }, el('h3', {}, 'Activity'));
    const tl = el('div', { class: 'timeline' });
    // the outcome is said in words next to the coloured dot (colour alone carries nothing)
    for (const j of [...s.jobs].reverse().slice(0, 10)) {
      const k = jobState(j), how = j.running ? ' · running' : j.lost ? ' · lost (exit code unknown)' : k === 'ok' ? ` · ok in ${j.seconds}s` : k === 'interrupted' ? ` · interrupted after ${j.seconds}s` : k === 'incomplete' ? ` · incomplete assessment in ${j.seconds}s` : ` · failed (exit ${j.rc}) after ${j.seconds}s`;
      tl.append(el('div', { class: 'tl' }, el('span', { class: 'tdot ' + (j.running ? 'run' : k === 'ok' ? 'ok' : ['interrupted', 'incomplete'].includes(k) ? 'warn' : 'bad'), 'aria-hidden': 'true' }), el('div', {}, el('a', { href: '#', onclick: (e) => { e.preventDefault(); if (!jobs.has(j.id)) trackJob(j.id, j); showJob(j.id); } }, j.label), el('div', { class: 'muted small mono' }, cmdLine(j.argv).slice(0, 90)), el('div', { class: 'muted small' }, fmtTime(j.started) + how))));
    }
    act.append(s.jobs.length ? tl : el('p', { class: 'muted' }, 'Nothing has run yet.'));
    if (s.undo && s.undo.length) { act.append(el('h4', {}, 'Undo history', explainBtn('undo', 'undo')), ...s.undo.slice(0, 5).map((u) => el('div', { class: 'small', style: 'padding:3px 0' }, el('span', { class: 'chip' }, u.scope), ' ', u.summary))); }
    lower.append(act);
    v.append(lower);
  };
  // the empty state of the Overview and the Environments page (one wording for both)
  const noEnvs = () => emptyState('No environments yet', 'Create one: network, bastion, security baseline, optional Kubernetes and VPN. Local VMware needs no cloud account.',
    el('button', { class: 'btn primary', onclick: () => go('create', { env: null }) }, 'Create environment'), el('button', { class: 'btn ghost', onclick: () => showHelp('quickstart') }, 'Quickstart'));

  // Environment cards. The Overview shows them compact, with 'Manage →' to the card on the Environments page; there
  // every card carries its Manage actions, folded away when there are several environments (each card's choice is
  // kept across redraws). An action that cannot work for this environment is disabled, and the reason is written out.
  const MANAGE_OPEN = new Map();
  const manageOpen = (id) => (MANAGE_OPEN.has(id) ? MANAGE_OPEN.get(id) : (STATE.envs || []).length <= 2);
  function envCard(e, full = false) {
    const local = !!((STATE.clouds || {})[e.cloud] || {}).local;
    const cl = { cloud: e.cloud, env: e.env }, fk = (what) => `env:${e.id}:${what}`, vars = e.vars || {}, outs = e.outputs || {};
    const c = el('div', { class: 'card env-card', 'data-env': e.id });
    // name · region · state: a local environment has neither region nor remote state; parts never break inside
    const parts = e.error ? ['configuration unreadable'] : [e.name, !local && e.region, !local && e.state && e.state + ' state'].filter(Boolean);
    const cliDefault = STATE.current_env === e.id;
    c.append(el('div', { class: 'env-head' }, el('div', { class: 'glyph ' + e.cloud, 'aria-hidden': 'true' }, CLOUD[e.cloud]),
      el('div', { class: 'env-title' }, el('h3', { tabindex: '-1' }, e.id, explainBtn(`target ${e.cloud}`, `${XCLOUD[e.cloud] || e.cloud}, the target of ${e.id}`, { fk: fk('xq') })), el('div', { class: 'muted small' }, parts.map((p, i) => [i ? ' · ' : '', el('span', { class: 'nowrap' }, p)]))),
      el('div', { class: 'env-chips' }, e.kubernetes ? el('span', { class: 'chip leaf' }, '☸ kubernetes', explainBtn('kubernetes', 'Kubernetes')) : null, e.vpn ? el('span', { class: 'chip sky' }, 'vpn', explainBtn('vpn', 'the VPN')) : null, e.fips ? el('span', { class: 'chip brand' }, 'FIPS', explainBtn('fips', 'FIPS mode')) : null,
        cliDefault ? el('span', { class: 'chip', title: 'The CLI’s current environment (cs env use): terminal cluster commands - kubectl, helm, node, platform - act on it' }, 'CLI default') : null)));
    if (e.error) c.append(el('div', { class: 'callout warn', role: 'note', style: 'margin:12px 0 0' }, el('b', {}, 'Its configuration cannot be read'), el('p', { class: 'small mono', style: 'margin:6px 0 0' }, e.error)));
    c.append(el('div', { class: 'kv', style: 'margin-top:12px' }, el('span', { class: 'k' }, 'bastion', explainBtn('bastion', 'the bastion')), el('span', { class: 'mono' }, e.bastion_ip || '—'), el('span', { class: 'k' }, 'resources'), el('span', {}, `${e.resources} in state`), el('span', { class: 'k' }, 'network'), el('span', { class: 'mono' }, e.cidr || '—'), el('span', { class: 'k' }, 'updated'), el('span', { title: e.updated || '' }, fmtTime(e.updated))));
    const vd = e.verdicts || {};
    c.append(['dr', 'chaos', 'cis', 'fips', 'architecture'].some((k) => vd[k]) ? el('div', { class: 'verdicts' }, verdictChip('DR', vd.dr), verdictChip('chaos', vd.chaos), verdictChip('CIS', vd.cis), verdictChip('FIPS', vd.fips), vd.architecture ? verdictChip('Architecture', vd.architecture) : null)
      : el('div', { class: 'verdicts muted small' }, 'No DR drills, chaos runs or compliance scans yet'));
    c.append(el('div', { class: 'row', style: 'margin-top:12px' },
      el('button', { class: 'btn small primary', 'data-fk': fk('status'), onclick: () => run('cloudseed_status', cl, 'status ' + e.id) }, 'Status'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('outputs'), onclick: () => run('cloudseed_output', cl, 'outputs ' + e.id) }, 'Outputs'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('troubleshoot'), onclick: () => run('cloudseed_troubleshoot', cl, 'troubleshoot ' + e.id) }, 'Troubleshoot'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('architecture'), onclick: () => openAction('cloudseed_scan', { kind: 'architecture', profile: 'production', max_age_days: 30, ...cl }) }, 'Well-Architected…')));
    // where to go next: a cluster's Platform view (it follows the page's environment), or this card on the Environments page
    const next = e.kubernetes ? el('button', { class: 'btn small ghost', 'data-fk': fk('platform'), onclick: () => selectEnv(e.id).then(() => go('platform')) }, 'Platform →')
      : !full ? el('button', { class: 'btn small ghost', 'data-fk': fk('manage'), onclick: () => showEnvCard(e.id) }, 'Manage →') : null;
    if (next) c.append(el('div', { class: 'env-foot' }, next));
    if (!full) return c;
    const allow = (e.allowed_ssh_cidrs || []).join(', ');
    // a local (VMware) bastion is reached over this machine's NAT network, not the internet: update-ip does not apply there
    const ipOff = local ? { disabled: true, title: `Not applicable to ${e.id}: local VMs are reached over this machine's NAT network, so there is no public-IP allow-list to update` } : { title: 'Replace the SSH allow-list of the bastion with your current public IP' };
    const vpnType = outs.vpn_type || vars.vpn_type;
    const vpnWhy = local ? 'a VPN does not apply to local VMware environments' : !e.vpn ? (vars.enable_vpn ? 'the VPN is enabled but not created yet: apply the environment' : 'no VPN host: turn it on with Change settings (enable_vpn)')
      : vpnType === 'tailscale' ? 'client profiles are an OpenVPN feature; this VPN is Tailscale' : '';
    const sshWhy = e.bastion_ip ? '' : local ? 'the bastion VM reported no address yet: Re-provision reads it again' : 'no bastion address yet: apply the environment';
    const k8sWhy = e.kubernetes ? '' : vars.enable_kubernetes ? 'Kubernetes is enabled but not created yet: apply the environment' : 'no Kubernetes cluster: turn it on with Change settings (enable_kubernetes)';
    const off = (why) => (why ? { disabled: true, title: why.charAt(0).toUpperCase() + why.slice(1) } : {});
    const row = el('div', { class: 'row' },
      el('button', { class: 'btn small ghost', 'data-fk': fk('plan'), onclick: () => run('cloudseed_plan', cl, 'plan ' + e.id) }, 'Plan'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('change'), onclick: () => go('create', { env: e.id }) }, 'Change settings'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('update-ip'), ...ipOff, onclick: () => run('cloudseed_update_ip', cl, 'update-ip ' + e.id, { message: `Detects your current public IP and applies it as the SSH allow-list of ${e.id} with Terraform (auto-approved). It replaces the current list${allow ? ` (${allow})` : ''}.` }) }, 'Update my IP'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('provision'), onclick: () => run('cloudseed_provision', cl, 'provision ' + e.id, { message: `Copies cloudseed to the hosts of ${e.id} and runs the Ansible hardening and tooling on them again.` }) }, 'Re-provision'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('inventory'), onclick: () => run('cloudseed_inventory', cl, 'inventory ' + e.id) }, 'Inventory'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('ssh'), ...off(sshWhy), onclick: () => openAction('cloudseed_ssh', { ...cl, command: 'uptime' }) }, 'SSH command…'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('vpn'), ...off(local ? vpnWhy : ''), onclick: () => run('cloudseed_vpn', { action: 'status', ...cl }, 'vpn status') }, 'VPN'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('vpn-user'), ...off(vpnWhy), onclick: () => openAction('cloudseed_vpn', { action: 'add-user', ...cl }, { name: 'client name, e.g. alice' }) }, 'VPN user…'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('cost'), onclick: () => run('cloudseed_finops', { action: 'estimate', ...cl }, 'cost estimate') }, 'Cost'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('k8s'), ...off(k8sWhy), onclick: () => run('cloudseed_k8s', { action: 'info', ...cl }, 'k8s info') }, 'Kubernetes'),
      el('button', { class: 'btn small ghost', 'data-fk': fk('details'), onclick: () => modal('Details · ' + e.id, el('pre', { class: 'help' }, JSON.stringify({ vars: e.vars, outputs: e.outputs, workdir: e.workdir, provisioned: e.provisioned }, null, 2)), { explain: `variables ${e.cloud}` }) }, 'Details'),
      cliDefault ? null : el('button', { class: 'btn small ghost', 'data-fk': fk('use'), title: `Make ${e.id} the CLI's current environment (cs env use ${e.id}): terminal cluster commands then act on it`, onclick: () => useInTerminal(e.id) }, 'Use in terminal'),
      el('span', { class: 'spacer' }),
      el('button', { class: 'btn small rose', 'data-fk': fk('destroy'), onclick: () => openAction('cloudseed_destroy', cl) }, 'Destroy…'));
    // the reasons for disabled buttons, written out (a tooltip alone never reaches touch or keyboard users)
    const why = [local ? ['Update my IP', 'local VMs are reached over this machine’s NAT network'] : null, sshWhy ? ['SSH command…', sshWhy] : null,
      vpnWhy ? [local ? 'VPN' : 'VPN user…', vpnWhy] : null, k8sWhy ? ['Kubernetes', k8sWhy] : null].filter(Boolean);
    const det = el('details', { class: 'manage', open: manageOpen(e.id) }, el('summary', { 'data-fk': fk('manage-toggle') }, 'Manage'), row,
      why.length ? el('ul', { class: 'why muted small' }, why.map(([b, w]) => el('li', {}, el('b', {}, b), ' ', w))) : null);
    det.addEventListener('toggle', () => MANAGE_OPEN.set(e.id, det.open));
    c.append(det);
    return c;
  }
  // 'Manage →': the environment's card on the Environments page, scrolled into view with its Manage actions open
  function showEnvCard(id) {
    MANAGE_OPEN.set(id, true);
    go('envs');
    const c = $(`#view-envs [data-env="${CSS.escape(id)}"]`); if (!c) return;
    c.scrollIntoView({ block: 'start' }); $('h3', c).focus({ preventScroll: true });
    c.classList.add('flash'); setTimeout(() => c.classList.remove('flash'), 1600);
  }

  views.envs = () => {
    const v = $('#view-envs'); v.innerHTML = '';
    if (!STATE.envs.length) { v.append(noEnvs()); return; }
    const g = el('div', { class: 'grid cols-2' }); for (const e of STATE.envs) g.append(envCard(e, true)); v.append(g);
  };

  // ---------------------------------------------------------------- create / change wizard
  const NAME_RE = /^[a-z][a-z0-9-]{1,23}$/;
  // the smallest whole-number answer setup accepts: node, zone and control-plane counts and VM sizes start at 1, other
  // counts (workload VMs, workers) at 0; a bound the server sends with the question wins
  const intMin = (q) => (typeof q.minimum === 'number' ? q.minimum : /(node_count|az_count|control_planes|_cpus|_memory_mb|_disk_gb)$/.test(q.key) ? 1 : 0);
  const NAME_MSG = 'Use 2-24 lowercase letters, digits or hyphens, starting with a letter.';
  // questions whose default is another question's answer, for servers that do not send q.follows yet
  const FOLLOWS = { 'aws:enable_regional_baseline': 'enable_account_baseline' };
  // (a dotted quad; an octet with a leading zero - 010, which some tools read as octal - is refused, as Python's ipaddress does)
  const ipv4 = (s) => { const m = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/.exec(s); return m && m.slice(1).every((o) => +o <= 255) ? m.slice(1).reduce((a, o) => a * 256 + +o, 0) : null; };
  // The prefix length a netmask (255.255.0.0) or a hostmask (0.0.255.255) stands for, read as the CLI (Python's
  // ipaddress) reads one after the '/': a netmask first, else a hostmask; null when it is neither.
  const maskLen = (m) => {
    const n = ipv4(m); if (n === null) return null;
    for (const x of [n, 2 ** 32 - 1 - n]) for (let p = 0; p <= 32; p++) if (x === 2 ** 32 - 2 ** (32 - p)) return p;
    return null;
  };
  // A CIDR as setup saves it (ipaddress normalizes the prefix): 10.0.0.0/255.255.0.0 is 10.0.0.0/16, so the same
  // network written the other way is no change to send; anything else stays as it is.
  const netText = (s) => { const t = String(s ?? '').trim(), [ip, m, extra] = t.split('/'), p = m !== undefined && extra === undefined && m.includes('.') ? maskLen(m) : null; return p === null ? t : `${ip}/${p}`; };
  const cidrProblem = (s) => {   // a network CIDR: 10.0.0.0/16 or 10.0.0.0/255.255.0.0 (host bits zero), like the CLI's check
    if (s.includes(':')) return `'${s}' is IPv6; cloudseed networks are IPv4 (e.g. 10.0.0.0/16)`;
    const [ip, pfx, extra] = s.split('/'); const n = ipv4(ip);
    // (the prefix: a length, or a netmask / hostmask)
    const p = pfx === undefined || extra !== undefined ? null : /^\d{1,2}$/.test(pfx) ? (+pfx <= 32 ? +pfx : null) : pfx.includes('.') ? maskLen(pfx) : null;
    if (n === null || p === null) return `'${s}' is not a network CIDR (e.g. 10.0.0.0/16)`;
    if (p < 32 && n % 2 ** (32 - p) !== 0) { const net = n - (n % 2 ** (32 - p)); return `'${s}' has host bits set (did you mean ${[24, 16, 8, 0].map((sh) => Math.floor(net / 2 ** sh) % 256).join('.')}/${p}?)`; }
    return null;
  };
  // IPs / CIDRs allowed to SSH to the bastion, checked like the CLI (netutil.validate_cidr_list, which stays the
  // authority): an address with a prefix but host bits set (203.0.113.7/24, pasted from `ip addr`) is refused instead of
  // being widened to its network, and so are 0.0.0.0/0, ranges wider than /8 and lists covering more than two /8s
  const allowProblem = (s) => {
    const dotted = (n) => [24, 16, 8, 0].map((sh) => Math.floor(n / 2 ** sh) % 256).join('.');
    const nets = [];   // [first address, end (exclusive), prefix]
    for (const part of s.split(',').map((x) => x.trim()).filter(Boolean)) {
      const [ip, pfx, extra] = part.split('/');
      if (ip.includes(':')) { if (!/^[0-9a-fA-F:.]+$/.test(ip) || extra !== undefined || (pfx !== undefined && !(/^\d{1,3}$/.test(pfx) && +pfx <= 128))) return `'${part}' is not a valid IP or CIDR`; if (pfx === '0') return 'Refusing ::/0: the bastion must not be open to the whole internet'; continue; }
      // (the prefix: a length, or a netmask / hostmask: 203.0.113.0/255.255.255.0 is a /24, as the CLI reads it)
      const n = ipv4(ip), p = pfx === undefined ? 32 : extra !== undefined ? null : /^\d{1,2}$/.test(pfx) ? (+pfx <= 32 ? +pfx : null) : pfx.includes('.') ? maskLen(pfx) : null;
      if (n === null || p === null) return `'${part}' is not a valid IP or CIDR`;
      const size = 2 ** (32 - p), net = n - (n % size);
      if (net !== n) return `'${part}' has host bits set, so it means ${dotted(net)}/${p} (${size.toLocaleString('en-US')} addresses). Did you mean ${ip}/32 (just that address)${p >= 8 ? `, or ${dotted(net)}/${p} for the whole range` : ''}?`;
      nets.push([net, net + size, p]);
    }
    if (nets.some((x) => x[2] === 0)) return 'Refusing 0.0.0.0/0: the bastion must not be open to the whole internet';
    const wide = nets.filter((x) => x[2] < 8).sort((a, b) => a[2] - b[2])[0];
    if (wide) return `Refusing ${dotted(wide[0])}/${wide[2]}: ranges wider than /8 would open the bastion to a large part of the internet. Allow your own IP (or your office/VPN egress range) instead`;
    let total = 0, end = 0;   // the addresses the list covers together (overlaps counted once)
    for (const [a, b] of nets.slice().sort((x, y) => x[0] - y[0])) if (b > end) { total += b - Math.max(a, end); end = b; }
    if (total > 2 * 2 ** 24) return `Refusing the allow-list: together it covers ${total.toLocaleString('en-US')} addresses (more than two /8 networks). Allow your own IP (or your office/VPN egress range) instead`;
    return null;
  };
  // The whole check the wizard runs on an allow-list: allowProblem, then IPv6 entries, which setup refuses as well (the
  // bastion has an IPv4 address only and every firewall rule cloudseed renders is IPv4). (Only commas = blank: not sent.)
  const allowListProblem = (s) => {
    const p = allowProblem(String(s || ''));
    if (p) return p;
    const v6 = String(s || '').split(',').map((x) => x.trim()).find((x) => x.includes(':'));
    return v6 ? `'${v6}' is an IPv6 address; the bastion only has an IPv4 address and its firewall rules are IPv4-only. Use your public IPv4 address (e.g. curl -4 ifconfig.me)` : null;
  };
  // A yes/no answer as setup reads it (base.as_bool: true/false, yes/no, y/n, on/off, 1/0); anything else is no yes.
  const isYes = (x) => x === true || x === 1 || (typeof x === 'string' && ['true', 'yes', 'y', 'on', '1'].includes(x.trim().toLowerCase()));
  // A setting of a feature that is off (vpn_type without a VPN, the cluster sizing without a cluster, Security Hub
  // without the regional baseline) is not asked by setup and has no effect: its yes/no question (q.depends_on, which
  // the server sends) is not answered yes. The wizard hides it, does not check it and does not send it, so it keeps
  // its saved or built-in value (Cloud.unused). answerOf(q): an answer as it is now (blank = that question's default).
  const unusedIn = (q, qs, answerOf) => { const p = q.depends_on && q.depends_on !== q.key ? qs.find((x) => x.key === q.depends_on) : null; return !!p && !isYes(answerOf(p)); };
  const same = (a, b) => (a === undefined || a === null || a === '' ? '' : typeof a === 'object' ? JSON.stringify(a) : String(a)) === (b === undefined || b === null || b === '' ? '' : typeof b === 'object' ? JSON.stringify(b) : String(b));
  // An answer the CLI takes from the environment or the vault counts only in the region it belongs to (q.env_region:
  // $CLOUDSDK_COMPUTE_ZONE=europe-west1-c counts in europe-west1 only); elsewhere the CLI takes the built-in default,
  // which the server sends as q.stock. The question as it applies in `region`:
  const questionIn = (q, region) => {
    const src = (q.from_env || []).length > 0, applies = src && (!q.env_region || String(region || '').trim().toLowerCase() === String(q.env_region).toLowerCase());
    return src && !applies ? { ...q, default: (q.stock || {}).default ?? '', region_defaults: (q.stock || {}).region_defaults, from_env: [] } : q;
  };
  // The answer setup uses for a question that follows another one (AWS: the regional baseline follows the account-wide
  // one) when none is sent: a saved answer that differs from the saved followed one was chosen on purpose and stays;
  // otherwise (saved equal, or nothing saved) it is the followed question's answer now.
  const followBase = (saved, savedFollowed, followedNow) => (saved !== undefined && (savedFollowed === undefined || !same(saved, savedFollowed)) ? saved : followedNow);
  // Why the saved answer of a deployed environment (resources in its state) cannot change, or '': its GCP project or Azure
  // subscription, and the zone of a zonal GKE cluster (a saved zone outside the region, or one that never existed, is
  // repaired by setup, so it is not fixed). Setup refuses these (the environment would end up half moved).
  const pinnedWhy = (cloud, q, e, region) => {
    const old = e && (Number(e.resources) || 0) > 0 && e.vars ? String(e.vars[q.key] ?? '').trim() : '';
    if (!old) return '';
    if ((q.key === 'project_id' && cloud === 'gcp') || (q.key === 'subscription_id' && cloud === 'azure')) return `cannot change on a deployed environment (setup refuses: ${e.id} has resources in this ${q.key === 'project_id' ? 'project' : 'subscription'}); use a new environment for another one`;
    if (q.key === 'zone' && cloud === 'gcp' && (e.kubernetes || same(e.vars.enable_kubernetes, true))) {
      // (the regions whose -a zone does not exist: from the question, or from its stock default while an environment
      // answer applies and the question itself carries none)
      const irregular = q.region_defaults || (q.stock || {}).region_defaults || {};
      const r = String(region || ''), inRegion = old.startsWith(r + '-') && /^[a-z]$/.test(old.slice(r.length + 1)), missing = !!irregular[r] && old === r + '-a';
      if (inRegion && !missing) return `cannot change on a deployed environment (setup refuses: moving the zonal GKE cluster of ${e.id} would re-create it, its workloads and volumes)`;
    }
    return '';
  };
  // The answer rules the server sends with a question, checked like setup does (the CLI stays the authority): a pattern
  // (an Azure subscription ID is a GUID) and names the cloud refuses (Azure's reserved VM admin user names). '' = fine.
  const answerRule = (q, val, label, display) => {
    const v = String(val === undefined || val === null ? '' : val).trim();
    if (!v) return '';   // a blank answer is the required / from_env check's business
    if (q.pattern) {
      let rx = null; try { rx = new RegExp(q.pattern); } catch { /* a pattern this browser cannot read: the CLI checks it */ }
      if (rx && !rx.test(v)) { const h = q.pattern_hint || ''; return !h ? `${label}: '${v}' is not a valid value` : /^(a|an|the)\s/i.test(h) ? `'${v}' is not ${h}` : `${label}: ${h}`; }
    }
    if (Array.isArray(q.reserved) && q.reserved.map((x) => String(x).toLowerCase()).includes(v.toLowerCase())) return /user/.test(q.key) ? `'${v}' is a name ${display} does not allow as a VM admin user` : `'${v}' is a name ${display} reserves`;
    return '';
  };

  // A long question prompt becomes a short label plus a hint under the input: "Label: detail" splits at the colon, a
  // trailing parenthetical of several words becomes the hint (a unit or a range such as "(MB)" or "(1-20)" stays).
  const splitPrompt = (p) => {
    const t = String(p || '').trim(), i = t.indexOf(': ');
    if (i > 0 && i < 48) return [t.slice(0, i), t.slice(i + 2)];
    const m = /^(.*\S)\s*\(([^()]*)\)\s*\??$/.exec(t);
    return m && m[2].length > 12 && /[\s,;]/.test(m[2]) ? [m[1], m[2]] : [t, null];
  };
  const shortPrompt = (p) => String(p || '').split(/\s\(|\?|: /)[0].trim();

  // The wizard stays built while the user looks elsewhere: coming back (the nav, the 2 key, the palette) resumes the
  // draft. It is built anew for another environment (Change settings), for a new environment (opts.env === null), on
  // Start over (opts.fresh), and when the environment it changes is gone. When the environment it drafts was saved
  // meanwhile - a run of this wizard saved the new environment (a dry run saves it too; a plan keeps nothing, except
  // the plan of a rename), or the environment
  // being changed was saved again - it continues as that environment's Change wizard at the same step and mode, with
  // the answers typed so far carried over (opts.carry) and compared with what is saved now; the tick is asked again.
  let WIZ = null;
  views.create = (opts = {}) => {
    opts = opts || {};
    const v = $('#view-create');
    const envOf = (id) => (id && STATE.envs.find((x) => x.id === id)) || null;
    const want = 'env' in opts ? (opts.env || '') : undefined;
    const cur = WIZ && v.dataset.built ? WIZ : null;
    if (cur && !opts.fresh) {
      const te = envOf(cur.target), saved = cur.savedAs(), mine = want === undefined || want === cur.target;
      // (an explicit "new environment" never turns a draft whose environment now exists into its Change wizard)
      if (mine && saved && (want === undefined || cur.target)) return cur.follow(saved);
      if (mine && !saved && (!cur.target || te)) { cur.resume(); return; }
    }
    const keep = document.activeElement && v.contains(document.activeElement) && document.activeElement.dataset ? document.activeElement.dataset.fk : null;
    v.innerHTML = ''; v.dataset.built = '1';
    const e = envOf(opts.env);
    const clouds = STATE.clouds;
    const started = opts.started || new Set();   // environments a run of this wizard created (or started to)
    // the saved values of the environment being changed: only what differs from them is sent (setup keeps everything else)
    const base = e ? { name: e.name || undefined, region: e.region || undefined, state: e.state || undefined, cidr: e.cidr || undefined, allow_ip: (e.allowed_ssh_cidrs || []).join(',') || undefined, workdir: e.workdir || undefined, tags: { ...(e.tags || {}) } }
      : { name: 'cloudseed', state: 'remote', tags: {} };
    // a new environment gets a name that is still free on the chosen cloud
    const freeEnv = (cloud) => ['dev', 'staging', 'prod', 'lab', 'test'].concat(Array.from({ length: 30 }, (_, i) => `dev${i + 2}`)).find((n) => !STATE.envs.some((x) => x.id === `${cloud}-${n}`)) || 'dev';
    let envTouched = false;
    const data = { cloud: e ? e.cloud : 'aws', env: e ? e.env : freeEnv('aws'), mode: ['plan', 'dry_run', 'apply'].includes(opts.mode) ? opts.mode : 'plan', qvars: {}, touched: new Set(), extra_vars: undefined, advanced: false, jsonErr: {}, name: base.name, state: base.state, cidr: base.cidr, allow_ip: base.allow_ip, workdir: base.workdir, tags: e && Object.keys(base.tags).length ? { ...base.tags } : undefined };
    data.region = e ? base.region : clouds[data.cloud].default_region;
    // the answers of the draft this wizard continues (see above): its changes win over the saved values
    const carried = e && opts.carry && e.cloud === opts.carry.cloud ? opts.carry : null;
    if (carried) {
      for (const k of ['name', 'region', 'state', 'cidr', 'allow_ip']) if (carried[k] !== undefined) data[k] = carried[k];
      if (carried.tags) data.tags = { ...(data.tags || {}), ...carried.tags };
      for (const [k, val] of Object.entries(carried.qvars || {})) { data.touched.add(k); data.qvars[k] = val; }
      // (other variables the run already saved are not sent again)
      const xv = Object.entries(carried.extra_vars || {}).filter(([k, val]) => !same(val, (e.vars || {})[k]));
      if (xv.length) data.extra_vars = Object.fromEntries(xv);
      data.advanced = !!carried.advanced;
    }
    let step = typeof opts.step === 'number' ? Math.max(0, Math.min(3, opts.step)) : 0;
    const c = () => clouds[data.cloud];
    const isChange = () => !!e;
    const crumb = () => { $('#crumb-view').textContent = e ? `Change ${e.id}` : 'Create'; };
    // what this draft has changed (relative to the saved values, or to the defaults of a new environment), to carry it
    // into the Change wizard that continues it: fields that differ, tags that differ, every answer the user touched
    const carry = () => {
      const out = { cloud: data.cloud, qvars: {}, advanced: !!data.advanced };
      for (const k of ['name', 'region', 'state', 'cidr', 'allow_ip']) if (data[k] !== undefined && data[k] !== '' && !same(data[k], base[k])) out[k] = data[k];
      const tags = {}; for (const [k, val] of Object.entries(data.tags || {})) if (!same(val, base.tags[k])) tags[k] = val;
      if (Object.keys(tags).length) out.tags = tags;
      for (const k of data.touched) out.qvars[k] = data.qvars[k];
      if (data.extra_vars) out.extra_vars = { ...data.extra_vars };
      return out;
    };
    // the environment this draft is about, when it was saved since the draft began: a new one a run of this wizard
    // created, or the one being changed, saved again (by a run of this wizard, the CLI or an agent)
    // (its settings, not when they were written: a plan that keeps nothing, or a failed run, puts the same ones back)
    const settingsOf = (x) => JSON.stringify([x.name, x.region, x.state, x.cidr, x.workdir, x.allowed_ssh_cidrs, x.tags, x.vars, (Number(x.resources) || 0) > 0, !!x.kubernetes]);
    const savedAs = () => {
      if (e) { const now = envOf(e.id); return now && now.updated !== e.updated && settingsOf(now) !== settingsOf(e) ? e.id : null; }
      const id = `${data.cloud}-${data.env}`; return started.has(id) && envOf(id) ? id : null;
    };
    const me = WIZ = { target: e ? e.id : '', savedAs, follow: (id) => follow(id, step), resume: crumb };
    // the questions as they apply in the region chosen now (an environment answer bound to another region does not count)
    const qv = (q) => questionIn(q, data.region);
    const questions = () => c().questions.map(qv);
    // a question whose default is another one's answer (AWS: the regional baseline follows the account-wide one)
    const followed = (q) => { const k = 'follows' in q ? q.follows : FOLLOWS[`${data.cloud}:${q.key}`]; return k && k !== q.key ? questions().find((x) => x.key === k) || null : null; };
    // a setting of a feature switched off in this draft (see unusedIn); a blank parent answer counts as its default
    const unused = (q) => unusedIn(q, questions(), (p) => { const v = effective(p); return v === undefined || v === null || (typeof v === 'string' && !v.trim()) ? derivedDefault(p) : v; });
    // A deployed environment (resources in its state) cannot move to another region, project or subscription, nor move
    // a zonal GKE cluster to another zone: setup refuses. pinned(q) says why a saved answer is fixed ('' when it is not).
    const deployed = () => !!e && (Number(e.resources) || 0) > 0;
    // a rename of a deployed environment (setup applies it only after a reviewed plan: never unattended)
    const renaming = (a) => deployed() && !!base.name && a.name !== undefined;
    const pinned = (q) => pinnedWhy(data.cloud, q, e, base.region);
    // a question's default as shown: region-derived defaults (zone = <region>-a) follow the chosen region; the server
    // lists the regions where they do not (q.region_defaults: GCP europe-west1/us-east1 start at zone -b)
    const derivedDefault = (q) => (typeof q.default === 'string' && c().default_region && q.default.startsWith(c().default_region) && data.region && !c().local ? ((q.region_defaults || {})[data.region] || data.region + q.default.slice(c().default_region.length)) : q.default);
    const isDerived = (q) => typeof q.default === 'string' && !!c().default_region && q.default.startsWith(c().default_region) && !c().local;
    const regionMoved = () => isChange() && !c().local && data.region && data.region !== base.region;
    // the answer setup uses when none is sent: the saved one, else the default. A following question follows the answer
    // it follows unless it was saved with a different value on purpose (a region alone: account half off, regional on)
    const baseline = (q) => {
      const saved = e && e.vars ? e.vars[q.key] : undefined, f = followed(q);
      if (f) return followBase(saved, e && e.vars ? e.vars[f.key] : undefined, effective(f));
      return saved !== undefined ? saved : derivedDefault(q);
    };
    // what an answer is now: the user's input when touched, else the saved value (or default) - region-derived ones follow a moved region
    const effective = (q) => (data.touched.has(q.key) ? data.qvars[q.key] : regionMoved() && isDerived(q) ? derivedDefault(q) : baseline(q));
    // a saved answer the user cleared goes back to its default: `--var KEY=null` makes setup forget it (a blank answer is
    // otherwise not sent, and setup would keep the saved value)
    const cleared = (q) => !!(e && e.vars && data.touched.has(q.key) && data.qvars[q.key] === undefined && e.vars[q.key] !== undefined && e.vars[q.key] !== null && e.vars[q.key] !== '' && !same(e.vars[q.key], derivedDefault(q)));
    // (a bare address is saved as its /32 or /128, a netmask as its prefix length: the same list, not a change)
    const cidrList = (x) => String(x || '').split(',').map((y) => y.trim()).filter(Boolean).map(netText).map((y) => (y.includes('/') ? y : y + (y.includes(':') ? '/128' : '/32'))).sort().join(',');
    const buildArgs = () => {
      const args = { cloud: data.cloud, env: data.env };
      // only what differs from the saved value (or the CLI default) is sent: setup keeps everything it is not given
      // (the working directory of an existing environment cannot change: setup refuses another one). A local cloud
      // takes a dedicated private network (--cidr) but no region or remote state.
      for (const k of c().local ? ['name', 'cidr', 'workdir'] : ['name', 'region', 'state', 'cidr', 'workdir']) if (data[k] && !same(k === 'cidr' ? netText(data[k]) : data[k], base[k]) && !(k === 'workdir' && isChange())) args[k] = data[k];
      // omitted = a new environment gets your detected public IP, an existing one keeps its saved list
      // (a list of only commas is blank: an existing environment keeps its saved list)
      if (!c().local && data.allow_ip && cidrList(data.allow_ip) && cidrList(data.allow_ip) !== cidrList(base.allow_ip)) args.allow_ip = data.allow_ip;
      // (local VMs carry no tags)
      const tags = {}; if (!c().local) for (const [k, val] of Object.entries(data.tags || {})) if (!same(val, base.tags[k])) tags[k] = String(val);
      if (Object.keys(tags).length) args.tags = tags;
      const vars = {};
      for (const q of questions()) { if (unused(q)) continue; const val = effective(q); if (cleared(q)) vars[q.key] = null; else if (val !== undefined && !same(val, baseline(q))) vars[q.key] = val; }
      Object.assign(vars, data.extra_vars || {});
      for (const k of ['project_id', 'subscription_id', 'profile']) { if (vars[k] === null) continue; if (vars[k] !== undefined && vars[k] !== '') args[k] = String(vars[k]); delete vars[k]; }
      if (Object.keys(vars).length) args.vars = vars;
      if (data.mode === 'apply') { args.apply = true; args.confirm = true; } if (data.mode === 'dry_run') args.dry_run = true;
      // a plan keeps nothing (setup --preview), except a rename's: setup applies a rename only after a saved plan
      if (data.mode === 'plan' && renaming(args)) args.save = true;
      return args;
    };
    // the same argv the server builds for cloudseed_setup (mcp.py), shell-quoted
    const setupArgv = (a) => {
      const out = ['setup', a.cloud, '--env', a.env, '-y'];
      for (const k of ['name', 'region', 'state', 'cidr', 'allow_ip', 'workdir', 'project_id', 'subscription_id', 'profile']) if (a[k]) out.push('--' + k.replace(/_/g, '-'), String(a[k]));
      for (const [k, val] of Object.entries(a.tags || {})) out.push('--tag', `${k}=${val}`);
      for (const [k, val] of Object.entries(a.vars || {})) out.push('--var', `${k}=${typeof val === 'string' ? val : JSON.stringify(val)}`);
      out.push(a.dry_run ? '--dry-run' : a.apply ? '--auto-approve' : a.save ? '--plan-only' : '--preview');
      return out;
    };
    const cmdText = () => cmdLine(setupArgv(buildArgs()));
    const qLabel = (q) => splitPrompt(q.prompt)[0];
    const answerProblem = (q, val) => answerRule(q, val, qLabel(q), c().display);
    // the region of a deployed environment is fixed (setup refuses a move); Azure takes display names too (East US)
    const normRegion = (r) => { const t = String(r || '').trim(); return data.cloud === 'azure' ? t.replace(/\s+/g, '').toLowerCase() : t; };
    const regionFixed = () => deployed() && !c().local && !!base.region && !!data.region && normRegion(data.region) !== normRegion(base.region);
    // validation mirrors the CLI (names, CIDRs, tags, required answers) so problems show here, not at apply time
    const problems = () => {
      const b = {}, o = {};
      if (!NAME_RE.test(data.env || '')) b.env = 'Environment name: ' + NAME_MSG;
      else if (!isChange() && STATE.envs.some((x) => x.id === `${data.cloud}-${data.env}`)) b.env = `${data.cloud}-${data.env} already exists: pick another name, or use Change settings on it`;
      if (data.name && !NAME_RE.test(data.name)) b.name = 'Name prefix: ' + NAME_MSG;
      if (data.cidr) { const p = cidrProblem(data.cidr); if (p) b.cidr = p; }
      if (!c().local) {
        if (!data.region) b.region = `${c().region_prompt || 'Region'} is required`;
        else if (!/^[A-Za-z0-9][A-Za-z0-9 -]*$/.test(data.region)) b.region = `'${data.region}' does not look like a region`;
        else if (regionFixed()) b.region = `${e.id} is deployed in ${base.region}: the region of a deployed environment cannot change (setup refuses). Create a new environment in ${data.region} instead`;
        if (data.allow_ip) { const p = allowListProblem(data.allow_ip); if (p) b.allow_ip = p; }
        // setup takes tags as --tag KEY=VALUE and splits at the first '=': a key holding '=' would become another tag
        for (const [k, val] of Object.entries(data.tags || {})) {
          if (!k.trim()) b.tags = 'A tag key cannot be empty';
          else if (k.includes('=')) b.tags = `Tag ${k}: a key cannot contain '=' (tags are passed as KEY=VALUE)`;
          else if (k !== k.trim()) b.tags = `Tag '${k}': the key starts or ends with a space`;
          else if (val !== null && typeof val === 'object') b.tags = `Tag ${k}: the value must be text`;
        }
      }
      for (const q of questions()) {
        if (unused(q)) continue;   // (not asked, not sent: setup keeps its saved or built-in value)
        const val = effective(q), blank = val === undefined || val === null || String(val).trim() === '', k = 'var:' + q.key;
        // a blank answer the CLI fills from the environment or the vault (GOOGLE_PROJECT, ARM_SUBSCRIPTION_ID, ...) is fine
        // (qv() drops a source that does not apply in the chosen region)
        if (q.required && !(q.from_env || []).length && blank) o[k] = `${qLabel(q)} is required`;
        else if (q.kind === 'int' && !blank) {
          const n = Number(val), lo = intMin(q), hi = typeof q.maximum === 'number' ? q.maximum : null;
          if (!Number.isInteger(n)) o[k] = `${qLabel(q)}: a whole number`;
          else if (n < lo) o[k] = `${qLabel(q)}: at least ${lo}`;
          else if (hi !== null && n > hi) o[k] = `${qLabel(q)}: at most ${hi}`;
        } else if (!blank && answerProblem(q, val)) o[k] = answerProblem(q, val);
        else if (!blank && pinned(q) && !same(String(val).trim().toLowerCase(), String(e.vars[q.key]).trim().toLowerCase())) o[k] = `${qLabel(q)} ${pinned(q)}. Saved: ${e.vars[q.key]}`;
      }
      // unparsable input (bad JSON / number); not in a hidden setting of a switched-off feature (it is not sent)
      const hidden = new Set(questions().filter(unused).map((q) => 'var:' + q.key));
      for (const [k, msg] of Object.entries(data.jsonErr)) if (hidden.has(k)) continue; else if (k.startsWith('var:') || k === 'extra_vars') o[k] = msg; else b[k] = msg;
      return [b, o];
    };
    const firstBad = () => { const [b, o] = problems(); return Object.keys(b).length ? [1, b] : Object.keys(o).length ? [2, o] : null; };
    // One error line per field, created once and then updated in place: typing never re-announces every error. The
    // input points at its line (aria-describedby), so a screen reader reads it when the field has focus.
    const errId = (k) => 'err-' + k.replace(/[^\w-]/g, '_');
    const showErrors = (errs) => {
      for (const inp of $$('[aria-invalid="true"]', body)) if (!(inp.name in errs)) { inp.removeAttribute('aria-invalid'); inp.removeAttribute('aria-describedby'); const n = document.getElementById(errId(inp.name)); if (n) n.remove(); }
      for (const [k, msg] of Object.entries(errs)) {
        const inp = $(`[name="${CSS.escape(k)}"]`, body); if (!inp) continue;
        const id = errId(k); let n = document.getElementById(id);
        if (!n) { const lab = inp.closest('label'); n = el('span', { class: 'field-err', id }); ((lab && $('.notes', lab)) || lab || inp.parentNode).append(n); }
        if (n.textContent !== msg) n.textContent = msg;
        inp.setAttribute('aria-invalid', 'true'); inp.setAttribute('aria-describedby', id);
      }
    };
    // moving forward past a step with problems (Next, the stepper, Run) shows them instead, and puts focus on the field
    // the message is about (an advanced question is shown first when that is where the problem is)
    const guard = (to) => {
      const bad = firstBad();
      if (!bad || bad[0] >= to) return true;
      const [at, errs] = bad, k0 = Object.keys(errs)[0];
      if (step !== at) { step = at; render(); }
      if (at === 2 && !$(`[name="${CSS.escape(k0)}"]`, body) && !data.advanced) { data.advanced = true; render(); }
      showErrors(errs);
      const f = $(`[name="${CSS.escape(k0)}"]`, body) || $('[aria-invalid="true"]', body); if (f) f.focus();
      toast('✖ ' + Object.values(errs)[0], 'bad', 6000, { quiet: !!f });   // the focused field reads its own error
      return false;
    };
    const hero = el('div', { class: 'hero' }, el('h2', {}, e ? `Change ${e.id}` : 'Create an environment'), el('p', {}, e ? `Only what you change is sent; everything else keeps its saved value. Nothing changes in ${c().display} until you choose Apply on the last step; Plan and Dry run touch no cloud resources and keep ${e.id}'s saved settings as they are (only the plan of a rename saves it, for the Apply).` : 'Four steps. Nothing is created until you choose Apply on the last step; Plan and Dry run are always safe. Your answers are kept while you look elsewhere.'),
      el('div', { class: 'row' }, e ? el('button', { class: 'btn ghost small', onclick: () => go('create', { env: e.id, fresh: true }) }, 'Discard my changes') : el('button', { class: 'btn ghost small', onclick: () => go('create', { env: null, fresh: true }) }, 'Start over'),
        e ? el('button', { class: 'btn ghost small', onclick: () => go('create', { env: null }) }, 'Create a new environment instead') : null));
    const stepper = el('nav', { class: 'stepper', 'aria-label': 'Wizard steps' }); const body = el('div', { class: 'card' });
    const preview = el('div', { class: 'cmd-preview' }); const pvTitle = el('h4', { class: 'section-title' }, 'Live command preview');
    const updatePreview = () => { const t = cmdText(); preview.textContent = t; const rp = $('.review-preview', body); if (rp) rp.textContent = t; };
    const STEPS = ['Cloud', 'Basics', 'Options', 'Review & run'];
    const MODE_WORD = { plan: 'plan', dry_run: 'dry run', apply: 'apply' };
    const add = (...kids) => body.append(...kids.filter(Boolean));   // native append() would print a skipped (null) part as "null"
    let confirmBox = null;
    // continue as the Change wizard of what was saved meanwhile, at step `to`, with the answers typed so far
    const follow = (id, to) => {
      toast(isChange() ? `The saved settings of ${id} changed meanwhile (a run or the CLI saved them): your changes are kept and now compared with them` : `The last run saved ${id}: continuing as Change ${id}, with your answers kept`, '', 7000);
      views.create({ env: id, step: to, mode: data.mode, started, carry: carry(), fresh: true });
    };
    // Run setup. When the environment was saved since this draft began (an earlier run of this wizard saved the new
    // environment, or the one being changed was saved again), the wizard first continues as its Change wizard - the
    // answers kept, the changes shown against what is saved now, the tick asked again. When the run ends, a wizard still
    // on its review follows what the run saved.
    const runSetup = async () => {
      const id = `${data.cloud}-${data.env}`, saved = savedAs();
      if (saved) return follow(saved, 3);
      if (!guard(4)) return;
      if (data.mode === 'apply' && !(confirmBox && confirmBox.checked)) return toast('Tick the confirmation first', 'bad');
      // setup refuses to rename a deployed environment unattended: the plan comes first (see the review)
      if (data.mode === 'apply' && renaming(buildArgs())) return toast(`✖ Renaming ${e.id} replaces most of its resources: run Plan only first (it saves the new name), then Apply`, 'bad', 8000);
      const mode = data.mode;
      const job = await run('cloudseed_setup', buildArgs(), `setup ${id} (${MODE_WORD[mode]})`);
      if (!job) return;
      if (!isChange()) started.add(id);
      // when the run ends: a wizard still showing its review continues on what the run saved (a new environment as its
      // Change wizard); one the user has moved on in keeps what was typed and follows on the next visit or run; after a
      // finished Apply the next visit from elsewhere starts afresh
      JOB_DONE.set(job, (j) => {
        loadState().catch(() => null).then(() => {
          if (WIZ !== me) return;
          if (VIEW === 'create' && step === 3) { const s = savedAs(); if (s) follow(s, 3); }
          else if (VIEW !== 'create' && mode === 'apply' && j.rc === 0) { WIZ = null; delete v.dataset.built; }
        });
      });
    };
    const render = () => {
      // the review always compares with what is saved now (a run that ended while the user was on another step saved it)
      if (step === 3 && savedAs()) return follow(savedAs(), 3);
      const fk = document.activeElement && v.contains(document.activeElement) && document.activeElement.dataset ? document.activeElement.dataset.fk : null;
      stepper.innerHTML = ''; STEPS.forEach((s, i) => stepper.append(el('div', { class: 'st ' + (i === step ? 'active' : i < step ? 'done' : ''), 'aria-current': i === step ? 'step' : null, 'data-fk': 'st:' + i, onclick: () => { if (i > step && !guard(i)) return; step = i; render(); } }, `step ${i + 1}`, el('b', {}, s))));
      body.innerHTML = ''; body.oninput = null; body.onchange = null;   // the Options step's handlers must not run (and wipe errors) on other steps
      pvTitle.hidden = preview.hidden = step === 3;   // the review step shows the command in its own box
      const backBtn = step > 0 ? el('button', { class: 'btn ghost', 'data-fk': 'back', onclick: () => { step--; render(); } }, '← Back') : null;
      if (step === 0) {
        const g = radios(el('div', { class: 'grid cols-4', role: 'radiogroup', 'aria-label': 'Cloud' }));
        for (const [k, cc] of Object.entries(clouds)) {
          const locked = isChange() && k !== e.cloud;   // an existing environment cannot move to another cloud
          g.append(xqCorner(el('div', { class: 'card flat', role: 'radio', 'aria-checked': String(data.cloud === k), 'aria-disabled': locked ? 'true' : undefined, tabindex: data.cloud === k ? '0' : '-1', 'data-fk': 'cloud:' + k, title: locked ? `${e.id} lives on ${clouds[e.cloud].display}; use Create for a new environment elsewhere` : undefined,
            onclick: () => {
              if (locked || data.cloud === k) return;
              // a different cloud starts from that cloud's defaults: nothing of the previous cloud's answers carries over
              // (a network CIDR typed for a cloud is no dedicated VMware network, and the other way round)
              if (!!cc.local !== !!c().local) { data.cidr = undefined; delete data.jsonErr.cidr; }
              data.cloud = k; data.region = cc.default_region; data.qvars = {}; data.touched = new Set(); data.extra_vars = undefined;
              for (const x of Object.keys(data.jsonErr)) if (x.startsWith('var:') || x === 'extra_vars') delete data.jsonErr[x];
              if (!envTouched) data.env = freeEnv(k);
              render();
            } },
            el('div', { class: 'row' }, el('span', { class: 'glyph ' + k, 'aria-hidden': 'true' }, CLOUD[k]), el('b', {}, cc.display)), el('p', { class: 'muted small', style: 'margin-top:8px' }, cc.local ? 'Local VMs on VMware Fusion/Workstation. No cloud account.' : `Login: ${cc.login_hint.split('(')[0]}`)), `target ${k}`, `${cc.display}: what setup builds there`));
        }
        add(heading('Where should it live?'), isChange() ? el('p', { class: 'muted small' }, `${e.id} stays on ${clouds[e.cloud].display}.`) : null, g);
      } else if (step === 1) {
        const form = el('div', { class: 'form-grid' });
        // in Change settings the environment and its working directory are fixed: shown read-only (not required)
        const envField = field('env', { type: 'string', label: 'Environment', description: isChange() ? 'the environment being changed' : 'dev, staging, prod, lab …' }, !isChange(), data.env);
        if (isChange()) { const i = $('input', envField); i.readOnly = true; }
        // renaming a deployed environment replaces most of its resources (they are named after it): setup applies it only
        // after a reviewed plan; the region of a deployed environment cannot change at all (setup refuses)
        form.append(envField, field('name', { type: 'string', label: 'Name prefix', description: deployed() ? `prefix + Project tag of every resource. Renaming replaces most resources of ${e.id}: it is applied only after review (Plan first, then Apply)` : 'prefix + Project tag of every resource' }, false, data.name));
        // (a deployed environment whose config lost its region is not fixed: setup takes the region it is given)
        const regionPinned = deployed() && !!base.region;
        const regionField = !c().local ? field('region', { type: 'string', label: c().region_prompt || 'Region', hint: regionPinned ? `saved: ${base.region}; cannot change on a deployed environment (setup refuses): create a new environment for another region` : isChange() ? `saved: ${base.region || '—'}` : null }, true, data.region) : null;
        if (regionField && regionPinned && !regionFixed()) $('input', regionField).readOnly = true;
        if (!c().local) form.append(regionField, field('state', { type: 'string', label: 'Terraform state', enum: ['remote', 'local'], description: 'remote = a hardened bucket cloudseed creates' }, false, data.state || 'remote'),
          field('cidr', { type: 'string', label: 'Network CIDR', description: isChange() ? `saved: ${base.cidr || '—'}` : 'blank = the first free 10.N.0.0/16' }, false, data.cidr), field('allow_ip', { type: 'string', label: 'SSH allowed from', description: isChange() ? 'IPs/CIDRs allowed to SSH to the bastion: the saved list (blank keeps it; Update my IP replaces it with your current IP)' : 'IP/CIDR allowed to SSH to the bastion (blank = your public IP, detected)' }, false, data.allow_ip));
        // a local cloud: an optional dedicated private network (a second VMware environment with VMs needs its own)
        else form.append(field('cidr', { type: 'string', label: 'Private network', description: isChange() ? `saved: ${base.cidr || 'the built-in host-only network'}; changing it rebuilds every VM` : 'blank = VMware’s built-in host-only network. A dedicated one (e.g. 10.123.0.0/24) needs sudo vmrest with VMREST_USER/VMREST_PASSWORD; a second VMware environment with VMs needs one' }, false, data.cidr));
        const wd = field('workdir', { type: 'string', label: 'Working directory', description: isChange() ? 'where its config, keys and state live (it cannot move)' : 'blank = ~/.cloudseed/envs/<cloud>-<env>' }, false, data.workdir);
        if (isChange()) { const i = $('input', wd); i.readOnly = true; }
        form.append(wd);
        if (!c().local) form.append(field('tags', { type: 'object', label: 'Tags', description: 'extra tags on every resource, e.g. {"team": "platform"}' + (isChange() ? ' (tags are merged: removing one here does not delete it)' : '') }, false, data.tags));
        // each field's "?": the stack variable it sets (XQ_BASICS)
        for (const lab of Array.from(form.children)) { const inp = $('[name]', lab), bq = inp && (XQ_BASICS[data.cloud] || {})[inp.name]; if (bq) labelExplain(lab, bq, ($('.lbl', lab) || lab).firstChild.textContent.replace(/\s*\*\s*$/, '')); }
        // every key is re-read from its own input: a cleared field clears its value (and bad JSON in one field blocks nothing else)
        form.oninput = (ev) => {
          if (ev && ev.target && ev.target.name === 'env') envTouched = true;
          for (const inp of $$('[name]', form)) {
            const k = inp.name; if ((k === 'env' || k === 'workdir') && isChange()) continue;
            let val; try { val = readField(inp); delete data.jsonErr[k]; } catch (err) { data.jsonErr[k] = err.message; continue; }
            if (val === undefined) delete data[k]; else data[k] = val;
          }
          if (data.env === undefined) data.env = '';
          showErrors(problems()[0]); updatePreview();
        };
        body.append(heading('Basics'), form);
      } else if (step === 2) {
        const adv = el('input', { type: 'checkbox' }); adv.checked = !!data.advanced;
        const form = el('div', { class: 'form-grid' });
        const build = () => {
          form.innerHTML = '';
          for (const oq of c().questions) {
            const q = qv(oq);   // (as it applies in the chosen region)
            if (q.advanced && !adv.checked && !data.touched.has(q.key)) continue;
            // label: the prompt's head; hint: its detail plus where a blank answer comes from (the environment or the
            // vault, or the default when a saved answer is cleared), which replaces the prompt's own "(blank = …)"
            const [head, tail] = splitPrompt(q.prompt);
            const src = (q.from_env || []).length ? `$${q.from_env[0]} from your environment or the vault` : '';
            const saved = isChange() && e.vars && e.vars[q.key] !== undefined && q.kind !== 'bool';
            const own = tail && /^blank\s*=/.test(tail) && (src || saved) ? null : tail;
            const blank = saved ? (src ? `blank = back to the default (${src})` : 'blank = back to the default') : src ? `blank = ${src}` : '';
            // an environment answer bound to another region does not count here; a following answer names what it follows;
            // a saved answer a deployed environment cannot change says so (and is read-only)
            const fixed = pinned(q);
            const elsewhere = !fixed && (oq.from_env || []).length && !(q.from_env || []).length ? `$${oq.from_env[0]} counts in ${oq.env_region} only: the default applies in ${data.region}` : '';
            const f = followed(q), follows = f && q.kind === 'bool' ? `unless you change it, it follows “${shortPrompt(f.prompt)}”` : f ? `unless you change it, it follows ${qLabel(f)}` : '';
            const zoneMove = !fixed && deployed() && data.cloud === 'gcp' && q.key === 'zone' ? `changing it re-creates the bastion (and the VPN host) of ${e.id} there, with new SSH host keys` : '';
            // a variable that is set but that setup ignores for this answer (an ARM_SUBSCRIPTION_ID that is no GUID), when
            // nothing else fills a blank answer: the server says why (never with the value)
            const ignored = !(q.from_env || []).length ? (q.ignored_env || []).map((x) => { const p = String(x.problem || ''), lead = `$${x.name} `; return `$${x.name} is set but ignored: ${p.startsWith(lead) ? 'it ' + p.slice(lead.length) : p}`; }).join(' · ') : '';
            const hint = [own, fixed || blank, elsewhere, follows, zoneMove, ignored].filter(Boolean).join(' · ') || null;
            const val = effective(q);
            // a question with a fixed set of answers (when the server lists them) is a select; a saved value outside it stays selectable
            const choices = Array.isArray(q.choices) && q.choices.length ? (val === undefined || val === null || val === '' || q.choices.includes(val) ? q.choices : [val, ...q.choices]) : null;
            const prop = q.kind === 'bool' ? { type: 'boolean', description: q.prompt, hint: follows || null } : q.kind === 'int' ? { type: 'integer', label: head, hint, description: q.prompt, minimum: intMin(q), maximum: q.maximum }
              : choices ? { type: 'string', enum: choices, label: head, hint, description: q.prompt } : { type: 'string', label: head, hint, description: q.prompt };
            const fld = labelExplain(field('var:' + q.key, prop, q.required && !src, val), `variable ${data.cloud} ${q.key}`, `${shortPrompt(q.prompt) || q.key} (${q.key})`);
            const inp = fixed && $('input', fld); if (inp && same(String(val ?? '').trim().toLowerCase(), String(e.vars[q.key]).trim().toLowerCase())) inp.readOnly = true;
            fld.hidden = unused(q);   // (shown again as soon as its feature is switched on: see sync)
            form.append(fld);
          }
        };
        adv.onchange = () => { data.advanced = adv.checked; build(); showErrors(problems()[1]); };
        build();
        const extra = labelExplain(field('extra_vars', { type: 'object', label: 'Other variables', description: 'any other stack variable, e.g. {"az_count": 3, "kubernetes_node_max": 6}  (cs help variables <cloud>)' }, false, data.extra_vars), `variables ${data.cloud}`, `every ${c().display} variable`);
        // only answers the user touched are kept; untouched ones follow their default (or the saved value) and are not sent
        const sync = (ev) => {
          const t = ev && ev.target;
          if (t && t.name && t.name.startsWith('var:')) {
            const k = t.name.slice(4);
            try { const val = readField(t); delete data.jsonErr[t.name]; data.touched.add(k); data.qvars[k] = val; } catch (err) { data.jsonErr[t.name] = err.message; }
          } else if (t && t.name === 'extra_vars') {
            try { data.extra_vars = readField(t); delete data.jsonErr.extra_vars; } catch (err) { data.jsonErr.extra_vars = err.message; }
          }
          // an answer that follows another one shows its new value at once (until it is changed itself)
          for (const q of questions()) {
            if (!followed(q) || data.touched.has(q.key)) continue;
            const i = $(`[name="${CSS.escape('var:' + q.key)}"]`, form), val = effective(q);
            if (i && i.type === 'checkbox') i.checked = same(val, true); else if (i) i.value = val ?? '';
          }
          // a feature switched on or off shows or hides its settings (vpn_type with the VPN, the cluster sizing)
          for (const q of questions()) {
            const i = $(`[name="${CSS.escape('var:' + q.key)}"]`, form), lab = i && i.closest('label');
            if (lab) lab.hidden = unused(q);
          }
          showErrors(problems()[1]); updatePreview();
        };
        body.oninput = sync; body.onchange = sync;
        body.append(heading(c().display + ' options'), el('label', { class: 'check' }, adv, el('span', {}, 'show advanced options')), form, extra);
      } else {
        // a plan changes nothing in the cloud and keeps nothing (setup --preview): an existing environment keeps its saved
        // settings, a new one is not created, and Apply runs the same change for real. A rename of a deployed environment
        // is the exception: setup applies it only after a saved plan, so its plan saves the settings (--plan-only) for the
        // Apply that follows. A dry run of an existing environment renders into a scratch folder and saves nothing.
        const a = buildArgs(); const changes = [];
        const renameNow = renaming(a);
        const modes = [['plan', 'Plan only', renameNow ? `shows what the rename would change; nothing changes in the cloud, but the new settings are saved to ${e.id}, so the Apply that follows applies them`
          : isChange() ? `shows what would change; nothing changes in the cloud and nothing is saved: ${e.id} keeps its settings until you Apply` : 'shows exactly what would be created; nothing changes in the cloud and nothing is saved until you Apply'],
          ['dry_run', 'Dry run', isChange() ? `render + terraform validate, touches nothing in the cloud; the saved settings of ${e.id} stay as they are` : 'render + terraform validate, touches nothing in the cloud'], ['apply', 'Apply', 'creates / updates real, billable resources, then provisions the hosts']];
        const g = radios(el('div', { class: 'grid cols-3', role: 'radiogroup', 'aria-label': 'Run mode' }));
        for (const [m, t, d] of modes) g.append(xqCorner(el('div', { class: 'card flat', role: 'radio', 'aria-checked': String(data.mode === m), tabindex: data.mode === m ? '0' : '-1', 'data-fk': 'mode:' + m, onclick: () => { data.mode = m; render(); } }, el('b', {}, t), el('p', { class: 'muted small', style: 'margin:6px 0 0' }, d)), XQ_MODE[m], t.toLowerCase()));
        const apply = data.mode === 'apply';
        confirmBox = el('input', { type: 'checkbox' });
        // (renaming a deployed environment: setup applies it only after a reviewed plan, so Apply waits for one)
        const blocked = apply && renameNow ? `Renaming ${e.id}: run Plan only first, then Apply` : '';
        // Apply runs only once the tick is set: the button says so by being disabled until then
        const runBtn = el('button', { class: 'btn ' + (apply ? 'rose' : 'primary'), 'data-fk': 'run', disabled: apply, title: blocked || (apply ? 'Tick the confirmation first' : null), onclick: runSetup }, '▶ Run setup');
        confirmBox.onchange = () => { runBtn.disabled = !confirmBox.checked || !!blocked; runBtn.title = blocked || (confirmBox.checked ? '' : 'Tick the confirmation first'); };
        if (isChange()) {
          for (const k of ['name', 'region', 'state', 'cidr', 'workdir']) if (a[k] !== undefined) changes.push(`${k}: ${base[k] || '—'} → ${a[k]}`);
          if (a.allow_ip && !same(a.allow_ip, base.allow_ip)) changes.push(`SSH allow-list: ${base.allow_ip || '—'} → ${a.allow_ip}`);
          for (const [k, val] of Object.entries(a.tags || {})) changes.push(`tag ${k}: ${base.tags[k] ?? '—'} → ${val}`);
          for (const k of ['project_id', 'subscription_id', 'profile']) if (a[k] !== undefined) changes.push(`${k}: ${(e.vars || {})[k] ?? '—'} → ${a[k]}`);
          for (const [k, val] of Object.entries(a.vars || {})) changes.push(`${k}: ${JSON.stringify((e.vars || {})[k] ?? null)} → ${val === null ? 'the default' : JSON.stringify(val)}`);
          // an answer that is not sent but follows one that changed (one never saved - a config from before the question
          // existed - was the answer it follows)
          for (const q of questions()) {
            const f = followed(q), ev = e.vars || {};
            if (!f || unused(q) || (a.vars || {}).hasOwnProperty(q.key)) continue;
            const was = ev[q.key] !== undefined ? ev[q.key] : ev[f.key], now = effective(q);
            if (was !== undefined && !same(was, now)) changes.push(`${q.key}: ${JSON.stringify(was)} → ${JSON.stringify(now)} (it follows ${f.key})`);
          }
        }
        // a new environment: the effective answers in plain words (defaults included), above the exact command
        const show = (x) => (x === undefined || x === null || x === '' ? '—' : x === true ? 'yes' : x === false ? 'no' : typeof x === 'object' ? JSON.stringify(x) : String(x));
        const summary = () => {
          const rows = [['environment', `${data.cloud}-${data.env}`], ['cloud', c().display], ['name prefix', data.name || base.name]];
          if (c().local) rows.push(['private network', data.cidr || 'VMware’s built-in host-only network']);
          else rows.push(['region', data.region || '—'], ['Terraform state', data.state || 'remote'], ['network', data.cidr || 'the first free 10.N.0.0/16'], ['SSH allowed from', (cidrList(data.allow_ip) && data.allow_ip) || 'your public IP (detected)']);
          for (const q of questions()) {
            if ((q.advanced && !data.touched.has(q.key)) || unused(q)) continue;   // (setup does not ask a switched-off feature's settings)
            const val = effective(q);
            rows.push([shortPrompt(q.prompt), (val === undefined || val === '') && (q.from_env || []).length ? `$${q.from_env[0]} (environment or vault)` : show(val)]);
          }
          if (data.extra_vars) for (const [k, val] of Object.entries(data.extra_vars)) rows.push([k, show(val)]);
          return el('div', {}, el('h4', {}, 'What will be set up'), kv(...rows));
        };
        add(heading('Review & run'), g,
          isChange() ? el('div', {}, el('h4', {}, `Changes to ${e.id}`), changes.length ? el('ul', { class: 'small' }, ...changes.map((x) => el('li', {}, x))) : el('p', { class: 'muted small' }, 'No changes to the saved configuration: this runs it as saved.'),
            renameNow ? el('div', { class: 'callout ' + (apply ? 'danger' : 'warn'), role: 'note' }, el('b', {}, `Renaming ${e.id} (${base.name} → ${a.name}) replaces most of its resources`),
              el('p', { class: 'small', style: 'margin:6px 0 0' }, apply ? 'Setup applies a rename only after its plan was reviewed: choose Plan only and run it (it saves the new name), then come back and Apply.'
                : data.mode === 'dry_run' ? 'Its resources are named after it, so Terraform replaces most of them. A dry run only renders and validates the change and saves nothing: to apply the rename, run Plan only (it saves the new name), then Apply.'
                  : 'Its resources are named after it, so Terraform replaces most of them. Review this plan; an Apply afterwards applies it.')) : null) : summary(),
          el('h4', {}, 'Command that will run'), el('div', { class: 'cmd-preview review-preview' }, cmdText()), apply ? el('label', { class: 'check', style: 'margin-top:12px' }, confirmBox, el('span', {}, 'I understand Apply creates billable cloud resources')) : '',
          // one action row: Back on the left, the run on the right (where Next was on the earlier steps)
          el('div', { class: 'row wiz-actions' }, backBtn, el('span', { class: 'spacer' }), el('button', { class: 'btn ghost', onclick: () => copyText(cmdText(), 'Command') }, 'Copy command'), runBtn));
      }
      if (step < 3) body.append(el('div', { class: 'row wiz-actions' }, backBtn, el('span', { class: 'spacer' }), el('button', { class: 'btn primary', 'data-fk': 'next', onclick: () => { if (!guard(step + 1)) return; step++; render(); } }, 'Next →')));
      updatePreview();
      if (step === 1) showErrors(Object.fromEntries(Object.entries(problems()[0]).filter(([k]) => k === 'env' && !isChange() && data.env)));
      // keyboard users keep their place: re-focus the control they used (or the new step's heading)
      if (fk) { const n = v.querySelector(`[data-fk="${fk}"]`) || (fk === 'next' || fk === 'back' ? $('h3', body) : null); if (n) n.focus(); }
    };
    render(); v.append(hero, stepper, body, pvTitle, preview); crumb();
    // (a wizard that continues another keeps the keyboard where it was, or on the step's heading)
    if (keep) { const n = v.querySelector(`[data-fk="${CSS.escape(keep)}"]`) || (opts.carry ? $('h3', body) : null); if (n) n.focus(); }
  };

  // ---------------------------------------------------------------- platform
  // one status request per environment at a time; failures are not cached (↻ or the next visit retries)
  function platformStatus(id) {
    const c = PLATFORM_STATUS[id];
    if (c) return c;
    const pr = api(`/api/platform/status?env=${encodeURIComponent(id)}`).then((s) => s || {}, (err) => ({ error: err.message }));
    PLATFORM_STATUS[id] = pr;
    pr.then((s) => { if (PLATFORM_STATUS[id] === pr) { if (s.error) delete PLATFORM_STATUS[id]; else PLATFORM_STATUS[id] = s; } });
    return pr;
  }
  // A catalog item's release on the cluster: installed / built-in count as installed; a failed release (an install that
  // broke: Install again repairs it) or a pending one (an interrupted install/upgrade) is shown, but is not installed.
  const relState = (st) => (st && /^failed/i.test(st.state || '') ? 'failed' : st && /^pending/i.test(st.state || '') ? 'pending' : '');
  const isInstalled = (st) => !!st && !relState(st);
  const releaseFix = (st) => (st && (st.fix || st.remedy || st.hint)) || '';
  const releaseChip = (name, st, rs) => el('span', { class: 'chip ' + (rs === 'failed' ? 'rose' : 'seed'), title: releaseFix(st) || (rs === 'failed' ? `the last install of ${name} failed: Install repairs it` : `an install or upgrade of ${name} was interrupted: Details says how to unblock it`) }, rs === 'failed' ? 'failed' : 'pending');
  // FIPS mode: controllers are FIPS-ok; the TLS terminators only pin their ciphers (their proxy crypto is not a validated
  // module); stacks with their own crypto are skipped in a FIPS environment unless forced
  // crypto-restricted items (cert-manager, sealed-secrets, velero, cloudnative-pg) do cryptography themselves with a
  // non-validated module: they install in a FIPS environment (the platform needs them), and the scan flags them
  const fipsChip = (i, e) => (i.fips === 'compatible' ? el('span', { class: 'chip sky', title: 'runs on FIPS kernels and terminates no user TLS with its own crypto' }, 'FIPS-ok')
    : i.fips === 'tls-restricted' ? el('span', { class: 'chip seed', title: 'TLS pinned to 1.2+/FIPS suites, but the proxy crypto (Envoy BoringSSL / OpenSSL) is not a FIPS-validated module (cs scan fips reports it)' }, 'FIPS: TLS-pinned')
      : i.fips === 'crypto-restricted' ? el('span', { class: 'chip seed', title: 'installs in a FIPS environment, but its own key generation / encryption (upstream Go crypto or OpenSSL) is not a FIPS-validated module (cs scan fips reports it; a FIPS build of its image is needed for strict compliance)' }, 'FIPS: crypto not validated')
        : e && e.fips ? el('span', { class: 'chip rose', title: `ships its own, non-validated crypto: installing it into the FIPS environment ${e.id} skips it unless forced (force=true / --force; cs scan fips flags it)` }, 'not FIPS') : null);
  // an item whose images exist only for some CPU architectures (amd64): skipped on a cluster whose nodes are all of another
  // one (Apple silicon VMware guests, Graviton) unless Karpenter can add a node that fits, or it is forced
  const archChip = (i) => ((i.arch || []).length ? el('span', { class: 'chip', title: `its images are published for ${i.arch.join('/')} only: on a cluster whose nodes are all of another architecture (Apple silicon VMware guests, Graviton) the install skips it unless Karpenter can add a ${i.arch.join('/')} node, or it is forced (force=true / --force; its pods would not start)` }, `${i.arch.join('/')} only`) : null);
  // what an item needs besides itself: the same everywhere, plus per target (velero on VMware: local-path-provisioner and
  // minio); with an environment chosen only its target's extra needs are listed
  const needsText = (i, target) => {
    const byT = i.needs_by_target || {}, base = (i.needs || []).join(', ');
    if (target) { const extra = (byT[target] || []).filter((x) => !(i.needs || []).includes(x)); return [base, extra.length ? `${extra.join(', ')} (on ${target})` : ''].filter(Boolean).join(', ') || '—'; }
    const per = Object.entries(byT).filter(([, v]) => (v || []).length).map(([t, v]) => `${v.join(', ')} (on ${t})`);
    return [base, ...per].filter(Boolean).join('; ') || '—';
  };
  // group titles in words (the CLI name, which the filters and commands use, stays beside them); `code` in descriptions
  const GROUP_TITLES = { basek8s: 'Base Kubernetes', scaling: 'Scaling', data: 'Data', ai: 'AI / ML', agentic: 'Agentic', finops: 'FinOps', devsecops: 'DevSecOps', security: 'Security', resilience: 'Resilience', chaos: 'Chaos' };
  const withCode = (s) => String(s || '').split(/`([^`]+)`/).map((t, k) => (k % 2 ? el('code', {}, t) : t));
  views.platform = async () => {
    const seq = RENDER.platform = (RENDER.platform || 0) + 1;
    const v = $('#view-platform');
    const e = currentEnv(); const p = STATE.platform; const target = e ? e.cloud : null;
    const hasCluster = !!(e && e.kubernetes); const ea = e ? { cloud: e.cloud, env: e.env } : {};
    let status = {};
    if (hasCluster) {
      status = platformStatus(e.id);
      if (status instanceof Promise) {
        v.innerHTML = ''; v.append(el('div', { class: 'hero' }, el('h2', {}, `Platform on ${e.id}`), el('p', {}, 'Reading what is installed on the cluster…')));
        status = await status;
        if (seq !== RENDER.platform) return;   // a newer render (navigation, env switch, refresh) owns the view now
      }
    }
    v.innerHTML = '';
    const inst = status.items || {};
    const vals = Object.values(inst);
    // counts are over the items made for this target (an aws-only item is never "missing" on a VMware cluster); a
    // failed or pending release is counted wherever it is: it needs attention
    const applicable = p.items.filter((i) => !target || !i.only.length || i.only.includes(target));
    const nBuiltin = applicable.filter((i) => inst[i.name] && inst[i.name].state === 'built-in').length, nFailed = vals.filter((x) => relState(x) === 'failed').length, nPending = vals.filter((x) => relState(x) === 'pending').length;
    const nInstalled = applicable.filter((i) => isInstalled(inst[i.name]) && inst[i.name].state !== 'built-in').length;
    const needCluster = hasCluster ? {} : { disabled: true, title: 'select an environment with a Kubernetes cluster (top right)' };
    const retry = () => { delete PLATFORM_STATUS[e.id]; const r = views.platform(); if (r && r.catch) r.catch(viewError); };
    const broken = [nFailed ? `${nFailed} failed` : '', nPending ? `${nPending} pending` : ''].filter(Boolean).join(', ');
    const heroText = !hasCluster ? 'Select an environment with a Kubernetes cluster (top right) to install. Without one you can still browse and plan.'
      : status.error ? `Could not read what is installed on ${e.id}, so nothing below is marked installed.`
        : `${nInstalled} of ${applicable.length} items installed on ${status.distro || 'the cluster'}${nBuiltin ? ` (+${nBuiltin} built into ${status.distro || 'the distribution'})` : ''}${broken ? `; ${broken} (see the marked items)` : ''}. Install whole groups or single items: dependencies are ordered, cloud prerequisites (buckets, identities, tags) are applied through Terraform first, duplicates and conflicts are skipped.`;
    v.append(el('div', { class: 'hero' }, el('h2', {}, hasCluster ? `Platform on ${e.id}` : 'Platform catalog'), el('p', {}, heroText),
      el('div', { class: 'row' }, el('button', { class: 'btn ghost', ...needCluster, onclick: () => quick('cloudseed_platform', { action: 'status' }, 'platform status', ea) }, 'Status'), el('button', { class: 'btn ghost', ...needCluster, onclick: () => quick('cloudseed_platform', { action: 'ui' }, 'expose UIs', ea) }, 'Expose UIs'), el('button', { class: 'btn ghost', ...needCluster, onclick: () => quick('cloudseed_node', { action: 'list' }, 'nodes', ea) }, 'Nodes'), el('button', { class: 'btn ghost', ...needCluster, onclick: () => openAction('cloudseed_node', { action: 'add', count: 1, ...ea }) }, 'Add nodes…'), el('button', { class: 'btn ghost', ...needCluster, onclick: () => openAction('cloudseed_kubectl', { args: 'get pods -A', ...ea }) }, 'kubectl…'), el('button', { class: 'btn ghost', ...needCluster, onclick: () => openAction('cloudseed_helm', { args: 'list -A', ...ea }) }, 'helm…'), hasCluster ? el('button', { class: 'btn ghost', html: icon('refresh'), title: 'Read the install status from the cluster again', onclick: retry }, el('span', {}, 'Refresh status')) : null)));
    // an unreachable cluster (tunnel closed, VPN down, expired login, no kubeconfig yet) is an error, never "0 installed"
    if (hasCluster && status.error) {
      v.append(el('div', { class: 'callout warn', role: 'alert' }, el('b', {}, `Install status of ${e.id} unknown`),
        el('p', { class: 'small mono', style: 'margin:6px 0 8px' }, status.error),
        el('div', { class: 'row' }, el('button', { class: 'btn small primary', html: icon('refresh'), onclick: retry }, el('span', {}, 'Retry')),
          el('span', { class: 'muted small' }, 'Plan and Install still work: the command reads the cluster itself and says what is wrong.'))));
    }
    const groups = el('div', { class: 'grid cols-3' });
    // Plan works without a cluster; Install/Uninstall need one, and never apply to items made for another target (na: why)
    const btns = (items, label, na, inModal) => { const off = !hasCluster ? needCluster : na ? { disabled: true, title: na } : {}; return el('div', { class: 'row' }, el('button', { class: 'btn small ghost', onclick: () => { if (inModal) closeModal(); quick('cloudseed_platform', { action: 'plan', items }, 'plan ' + label, ea); } }, 'Plan'), el('button', { class: 'btn small primary', ...off, onclick: () => quick('cloudseed_platform', { action: 'install', items }, 'install ' + label, ea) }, '▶ Install'), el('button', { class: 'btn small ghost', ...off, onclick: () => quick('cloudseed_platform', { action: 'uninstall', items }, 'uninstall ' + label, ea) }, 'Uninstall')); };
    const known = hasCluster && !status.error;
    if (PLAT_FILTER.i === 'attention' && !(nFailed + nPending)) PLAT_FILTER.i = '';   // that filter chip is only offered while something needs attention
    // a group tile: its title (the CLI name beside it), what it holds, progress when the cluster could be read, and a
    // flag when a member release failed or is pending (it opens the list filtered to them)
    for (const [g, desc] of Object.entries(p.groups)) {
      const members = p.items.filter((i) => i.group === g && (!target || !i.only.length || i.only.includes(target)));
      const core = members.filter((i) => i.tier === 'core'), n = core.length, noun = n === 1 ? 'core item' : 'core items';
      const done = core.filter((i) => isInstalled(inst[i.name])).length;
      const rs = known ? p.items.filter((i) => i.group === g).map((i) => relState(inst[i.name])) : [];
      const nf = rs.filter((x) => x === 'failed').length, np = rs.filter((x) => x === 'pending').length;
      const flag = nf + np ? el('button', { type: 'button', class: 'tile-flag', title: 'Show the releases of this group that need attention', 'data-fk': 'flag:' + g,
        onclick: () => { PLAT_FILTER.g = g; PLAT_FILTER.i = 'attention'; syncChips(); renderItems(); filters.scrollIntoView({ block: 'start' }); } }, el('i', { class: nf ? 'bad' : 'warn', 'aria-hidden': 'true' }), [nf ? `${nf} failed` : '', np ? `${np} pending` : ''].filter(Boolean).join(' · ')) : null;
      groups.append(el('div', { class: 'group-tile g-' + g }, el('h3', {}, GROUP_TITLES[g] || g, GROUP_TITLES[g] && GROUP_TITLES[g].toLowerCase() !== g ? el('span', { class: 'gid' }, g) : null, explainBtn(`group ${g}`, `the ${GROUP_TITLES[g] || g} group`, { fk: 'xq:group:' + g }), flag), el('p', {}, withCode(desc)),
        el('div', { class: 'prog' }, known ? `${done}/${n} ${noun} installed` : `${n} ${noun}` + (hasCluster ? ' · install status unknown' : '')),
        known ? el('div', { class: 'bar', style: 'margin-top:6px;background:rgba(255,255,255,.25)' }, el('i', { class: 'p', style: `width:${n ? Math.round(100 * done / n) : 0}%;background:#fff` })) : null, btns([g], g)));
    }
    v.append(el('div', { class: 'section-title' }, 'Groups'), groups);
    const filters = el('div', { class: 'filters' }); const search = el('input', { placeholder: 'filter items…', style: 'max-width:280px', 'data-nodirty': '', 'data-fk': 'plat-search', 'aria-label': 'Filter catalog items', value: PLAT_FILTER.q });
    const list = el('div', { class: 'item-grid' });
    const renderItems = () => {
      list.innerHTML = ''; const q = PLAT_FILTER.q.toLowerCase();
      for (const i of p.items) {
        if (PLAT_FILTER.g && i.group !== PLAT_FILTER.g) continue;
        const st = inst[i.name], ok = isInstalled(st), rs = relState(st);
        if (known && PLAT_FILTER.i === 'installed' && !ok) continue; if (known && PLAT_FILTER.i === 'available' && ok) continue; if (known && PLAT_FILTER.i === 'attention' && !rs) continue;
        if (q && !(i.name + ' ' + i.desc + ' ' + i.group).toLowerCase().includes(q)) continue;
        const na = !!target && i.only.length > 0 && !i.only.includes(target), naWhy = na ? `${i.name} is for ${i.only.join('/')} only` : '';
        list.append(el('div', { class: 'item' + (ok ? ' installed' : '') + (rs ? ' ' + rs : '') + (na ? ' na' : '') }, el('div', { class: 'name' }, i.name, explainBtn(`item ${i.name}`, i.name, { fk: 'xq:item:' + i.name }), ok ? el('span', { class: 'chip leaf' }, st.state === 'built-in' ? 'built-in' : 'installed') : rs ? releaseChip(i.name, st, rs) : null, el('span', { class: 'chip' }, i.group), i.tier === 'extra' ? el('span', { class: 'chip outline', title: 'opt-in: not part of the group install; install it by name' }, 'extra') : null, fipsChip(i, e), archChip(i), i.cloud_prereqs.length ? el('span', { class: 'chip brand' }, 'cloud prereqs') : null, i.ui ? el('span', { class: 'chip' }, 'UI') : null, i.only.length ? el('span', { class: 'chip' + (na ? ' rose' : '') }, i.only.join('/') + ' only') : null),
          el('div', { class: 'desc' }, i.desc), el('div', { class: 'row' }, btns([i.name], i.name, naWhy), el('button', { class: 'btn small ghost', onclick: () => modal(i.name, el('div', {}, el('div', { class: 'kv' }, el('span', { class: 'k' }, 'group'), el('span', {}, i.group), el('span', { class: 'k' }, 'source'), el('span', { class: 'mono' }, i.source), el('span', { class: 'k' }, 'needs'), el('span', {}, needsText(i, target)), el('span', { class: 'k' }, 'targets'), el('span', {}, i.only.join(', ') || 'all'), (i.arch || []).length ? [el('span', { class: 'k' }, 'architectures'), el('span', {}, i.arch.join(', ') + ' only')] : null, el('span', { class: 'k' }, 'installed'), el('span', {}, known ? (st ? `${st.state} ${st.chart || ''} ${st.status || ''}` : 'no') : 'unknown')), rs && releaseFix(st) ? el('p', { class: 'small', style: 'margin-top:12px' }, releaseFix(st)) : null, i.notes ? el('p', { style: 'margin-top:12px' }, i.notes) : null, el('div', { class: 'row', style: 'margin-top:12px' }, btns([i.name], i.name, naWhy, true), el('button', { class: 'btn small ghost', onclick: () => { closeModal(); quick('cloudseed_platform', { action: 'info', items: [i.name] }, 'info ' + i.name, ea); } }, 'Full info'))), { narrow: true, explain: `item ${i.name}` }) }, 'Details'))));
      }
      if (!list.children.length) list.append(el('p', { class: 'muted' }, 'no items match'));
    };
    const syncChips = () => $$('.chip', filters).forEach((c) => { const on = (c.dataset.k === 'g' && c.dataset.v === PLAT_FILTER.g) || (c.dataset.k === 'i' && c.dataset.v === PLAT_FILTER.i); c.classList.toggle('on', on); c.setAttribute('aria-pressed', String(on)); });
    const chip = (label, val, kind) => el('span', { class: 'chip', onclick: () => { if (kind === 'g') PLAT_FILTER.g = PLAT_FILTER.g === val ? '' : val; else PLAT_FILTER.i = PLAT_FILTER.i === val ? '' : val; syncChips(); renderItems(); }, 'data-k': kind, 'data-v': val, 'data-fk': `chip:${kind}:${val}` }, label);
    // installed / available only mean something when the cluster could be read
    filters.append(search, ...(known ? [chip('installed', 'installed', 'i'), chip('available', 'available', 'i'), nFailed + nPending ? chip('failed / pending', 'attention', 'i') : null, el('span', { class: 'muted small', 'aria-hidden': 'true' }, '·')].filter(Boolean) : []), ...Object.keys(p.groups).map((g) => chip(g, g, 'g')));
    syncChips();
    search.oninput = () => { PLAT_FILTER.q = search.value; renderItems(); }; renderItems();
    v.append(el('div', { class: 'section-title' }, `Every item (${p.items.length})`), filters, list);
  };

  const SUITE_LABEL = { basic: 'Basic', network: 'Network', stress: 'Stress', full: 'Full suite' };
  views.resilience = () => {
    const v = $('#view-resilience'); v.innerHTML = '';
    const e = currentEnv(); const ea = envArgs(); const vd = e ? e.verdicts : {};
    // every button acts on the environment named here (ea is bound now); nothing runs against an implicit CLI default
    const needEnv = e ? {} : { disabled: true, title: 'select an environment (top right)' };
    const needCluster = e && e.kubernetes ? {} : { disabled: true, title: e ? `${e.id} has no Kubernetes cluster` : 'select an environment with a Kubernetes cluster (top right)' };
    // scans that cannot apply: a local VMware environment has no cloud account for prowler; host scans need a host the
    // scan can reach over SSH (the bastion, the VPN host, and - locally only - the Kubernetes node VMs)
    const local = !!(e && ((STATE.clouds || {})[e.cloud] || {}).local), o = (e && e.outputs) || {};
    const hasHosts = !!(e && (e.bastion_ip || e.vpn || (local && ((o.kubernetes_control_plane_ips || []).length || (o.kubernetes_worker_ips || []).length))));
    const needCloud = !e ? needEnv : local ? { disabled: true, title: `Not applicable to ${e.id}: a local VMware environment has no cloud account for prowler to scan (Host CIS scans its VMs)` } : {};
    const needHosts = !e ? needEnv : hasHosts ? {} : { disabled: true, title: `${e.id} has no host the scan can reach over SSH yet (bastion, VPN host or local Kubernetes nodes): apply it first` };
    const card = (title, verdict, desc, ...rows) => el('div', { class: 'card' }, el('h3', {}, title, verdict ? verdictChip('last', verdict) : null), el('p', { class: 'muted small' }, desc), ...rows);
    const fkr = (k) => 'res:' + k;
    v.append(el('div', { class: 'hero' }, el('h2', {}, 'Resilience, chaos and compliance'), el('p', {}, (e ? `Acting on ${e.id}.` : STATE.envs.length ? 'Pick an environment (top right).' : 'Create an environment first.') + ' DR drills prove backups restore; chaos suites prove workloads survive faults; scans assess architecture, CIS, STIG, vulnerabilities, cloud posture and FIPS.'),
      STATE.envs.length ? null : el('div', { class: 'row' }, el('button', { class: 'btn ghost', html: icon('create'), onclick: () => go('create', { env: null }) }, el('span', {}, 'Create environment')))));
    const suites = STATE.platform.chaos.suites, exps = STATE.platform.chaos.experiments;
    v.append(el('div', { class: 'grid cols-2' },
      card(['Disaster recovery · Velero', explainBtn('dr', 'disaster recovery')], vd.dr, 'Backups to a bucket + identity the stack creates for you (MinIO locally). The drill: create a workload → back it up → delete it → restore → verify contents and volume.',
        el('div', { class: 'row' }, el('button', { class: 'btn leaf', 'data-fk': fkr('dr-test'), ...needCluster, onclick: () => quick('cloudseed_dr', { action: 'test' }, 'DR drill', ea) }, '▶ Run DR drill'), el('button', { class: 'btn ghost', 'data-fk': fkr('dr-backup'), ...needCluster, onclick: () => quick('cloudseed_dr', { action: 'backup' }, 'backup', ea) }, 'Backup now'), el('button', { class: 'btn ghost', 'data-fk': fkr('dr-status'), ...needCluster, onclick: () => quick('cloudseed_dr', { action: 'status' }, 'dr status', ea) }, 'Status'), el('button', { class: 'btn ghost', 'data-fk': fkr('dr-backups'), ...needCluster, onclick: () => quick('cloudseed_dr', { action: 'backups' }, 'backups', ea) }, 'Backups'), el('button', { class: 'btn ghost', ...needCluster, onclick: () => openAction('cloudseed_dr', { action: 'restore', ...ea }) }, 'Restore…'), el('button', { class: 'btn ghost', ...needCluster, onclick: () => openAction('cloudseed_dr', { action: 'schedule', name: 'nightly', cron: '0 2 * * *', ...ea }) }, 'Schedule…'), el('button', { class: 'btn ghost', 'data-fk': fkr('dr-install'), ...needCluster, onclick: () => quick('cloudseed_platform', { action: 'install', items: ['resilience'] }, 'install resilience', ea) }, 'Install resilience group'))),
      card(['Chaos engineering · Chaos Mesh', explainBtn('chaos', 'chaos engineering')], vd.chaos, 'Automated experiments with a steady-state hypothesis and a PASS/FAIL verdict. A canary is created and removed for you; target your own Deployment when you are ready.',
        el('div', { class: 'row' }, ...Object.keys(suites).map((s) => el('button', { class: 'btn ' + (s === 'full' ? 'leaf' : 'ghost'), 'data-fk': fkr('chaos-' + s), title: (suites[s] || []).join(', '), ...needCluster, onclick: () => quick('cloudseed_chaos', { action: 'run', items: [s] }, 'chaos ' + s, ea) }, (s === 'full' ? '▶ ' : '') + (SUITE_LABEL[s] || s))),
          el('button', { class: 'btn ghost', ...needCluster, onclick: () => openAction('cloudseed_chaos', { action: 'run', ...ea }, { target: 'namespace/deployment[:port], e.g. shop/api:8080' }) }, 'My workload…'), el('button', { class: 'btn ghost', 'data-fk': fkr('chaos-status'), ...needCluster, onclick: () => quick('cloudseed_chaos', { action: 'status' }, 'chaos status', ea) }, 'Status'), el('button', { class: 'btn ghost', 'data-fk': fkr('chaos-stop'), ...needCluster, onclick: () => quick('cloudseed_chaos', { action: 'stop' }, 'chaos stop', ea) }, 'Stop all')),
        el('h4', {}, `Experiments (${Object.keys(exps).length})`), el('dl', { class: 'defs small' }, Object.entries(exps).map(([k, d]) => [el('dt', {}, k), el('dd', {}, d)]))),
      card(['Security & compliance scans', explainBtn('scan', 'security and compliance scans')], vd.cis || vd.kube, 'CIS (kube-bench), NSA/MITRE (kubescape), vulnerabilities (trivy), host CIS/STIG (OpenSCAP), cloud CIS (prowler), FIPS verification. Reports land in Reports.',
        el('div', { class: 'row' }, ...[['all', '▶ All security scans', 'leaf'], ['cis', 'CIS', ''], ['kube', 'NSA / MITRE', ''], ['images', 'Vulnerabilities', ''], ['host', 'Host CIS', ''], ['stig', 'STIG', ''], ['cloud', 'Cloud CIS', ''], ['fips', 'FIPS', '']].map(([k, l, c]) => { const gate = { cis: needCluster, kube: needCluster, images: needCluster, host: needHosts, stig: needHosts, cloud: needCloud }[k] || needEnv; return el('button', { class: 'btn ' + (c || 'ghost'), 'data-fk': fkr('scan-' + k), ...gate, title: [SCAN_WHAT[k], gate.title].filter(Boolean).join('\n'), onclick: () => run('cloudseed_scan', { kind: k, ...ea }, 'scan ' + k) }, l); }), el('button', { class: 'btn ghost', ...needEnv, onclick: () => openAction('cloudseed_scan', { kind: 'host', profile: 'stig', ...ea }) }, 'Options…')),
        // (every disabled scan says why, in words: a local environment without hosts has both reasons)
        local ? el('p', { class: 'muted small', style: 'margin:10px 0 0' }, 'Cloud CIS does not apply to a local VMware environment: there is no cloud account to scan.') : null,
        e && !hasHosts ? el('p', { class: 'muted small', style: 'margin:10px 0 0' }, `Host CIS and STIG need a host reachable over SSH: ${e.id} has none yet.`) : null),
      card(['Well-Architected assessment', explainBtn('scan', 'architecture assessments')], vd.architecture, 'Screen AWS, Azure or GCP configuration and saved evidence against provider pillars; VMware uses common architectural guidance. Missing or stale evidence stays unknown. This saves a report without contacting cloud services or changing infrastructure.',
        el('div', { class: 'row' }, el('button', { class: 'btn primary', 'data-fk': fkr('architecture'), ...needEnv, title: SCAN_WHAT.architecture, onclick: () => run('cloudseed_scan', { kind: 'architecture', profile: 'production', max_age_days: 30, ...ea }, 'Well-Architected assessment') }, '▶ Assess production'),
          el('button', { class: 'btn ghost', ...needEnv, onclick: () => openAction('cloudseed_scan', { kind: 'architecture', profile: 'production', max_age_days: 30, ...ea }) }, 'Profile & evidence…'),
          el('button', { class: 'btn ghost', ...needEnv, onclick: () => go('reports') }, 'Reports'))),
      card(['FIPS 140', explainBtn('fips', 'FIPS 140 mode')], vd.fips, e ? (e.fips ? `${e.id} was created in FIPS mode.` : `${e.id} is not a FIPS environment; FIPS is chosen at creation (fips_mode=true).`) : 'Create an environment with fips_mode=true for FIPS endpoints, images, kernels, SSH/TLS algorithms and FIPS-gated platform items.',
        el('div', { class: 'row' }, el('button', { class: 'btn primary', 'data-fk': fkr('fips'), ...needEnv, onclick: () => run('cloudseed_scan', { kind: 'fips', ...ea }, 'scan fips') }, 'Verify FIPS'), el('button', { class: 'btn ghost', onclick: () => showHelp('fips') }, 'How it works')))));
  };

  views.actions = () => {
    const v = $('#view-actions'); v.innerHTML = '';
    v.append(el('p', { class: 'muted' }, 'Every cloudseed capability as a form — the same registry the MCP server exposes. Blank fields use CLI defaults; the selected environment fills cloud/env.'));
    const search = el('input', { placeholder: 'find an action…', style: 'max-width:320px;margin-bottom:12px', 'data-nodirty': '', 'aria-label': 'Find an action' });
    const acc = el('div', { class: 'accordion' });
    const render = () => { acc.innerHTML = ''; const q = search.value.toLowerCase(); for (const g of [...new Set(ACTIONS.map((a) => a.group))]) { const items = ACTIONS.filter((a) => a.group === g && (!q || (a.name + a.description).toLowerCase().includes(q))); if (!items.length) continue; const d = el('details', { open: !!q || g === 'Discover' }, el('summary', {}, g, el('span', { class: 'chip' }, items.length))); const b = el('div', { class: 'body grid cols-2' }); for (const a of items) b.append(actionForm(a)); d.append(b); acc.append(d); } };
    search.oninput = render; render(); v.append(search, acc);
  };

  // scan chip: the stored verdict when the report has one, else its counters; a file without any counters is not "clean"
  const num = (x) => (typeof x === 'number' ? x : typeof x === 'string' && /^\d+(\.\d+)?$/.test(x.trim()) ? Number(x) : null);
  function scanResult(it) {
    const s = it.summary || {};
    let p = num(s.pass ?? s.passed ?? s['controls passed']), f = num(s.fail ?? s.failed ?? s['controls failed'] ?? s.critical);
    const w = (num(s.warn) || 0) + (num(s.unknown) || 0), errors = num(s.errors) || 0;
    if (f === null) {   // OpenSCAP host/STIG reports written before totals were stored: "score 61.2%  pass 180  fail 95" per host
      let pp = 0, ff = 0, seen = false;
      for (const val of Object.values(s)) { if (typeof val !== 'string') continue; const mf = /\bfail (\d+)/.exec(val), mp = /\bpass (\d+)/.exec(val); if (mf) { ff += Number(mf[1]); seen = true; } if (mp) pp += Number(mp[1]); }
      if (seen) { f = ff; if (p === null) p = pp; }
    }
    if (f === null && (it.findings || []).length) f = it.findings.filter((x) => /^(FAIL|FAILED|CRITICAL|HIGH)$/i.test(String(x.status || x.severity || ''))).length;
    return { p: p || 0, f, w, errors };
  }
  // The scan's own verdict decides the chip (the CLI's rule: e.g. kube fails only on CRITICAL/HIGH findings, so failed
  // low-severity controls still PASS); the counters go in the tooltip. Only a report without a stored verdict falls back
  // to its counters, and one without any counters is 'no totals', never 'clean'.
  function scanChip(it) {
    const { p, f, w, errors } = scanResult(it);
    const architecture = it.kind === 'architecture' || /^architecture-/.test(it.name || '');
    const counts = [p ? `${p} passed` : '', f ? `${f} failed` : '', w ? `${w} ${architecture ? 'unknown' : 'warnings'}` : '', errors ? `${errors} host(s) not scanned` : ''].filter(Boolean).join(', ');
    const verdict = String(it.verdict || '').trim().toUpperCase().split(/\s/)[0];
    const failed = () => [f ? `${f} failed` : 'failed', errors ? `${errors} host(s) not scanned` : ''].filter(Boolean).join(', ');
    let label, cls, title;
    if (verdict) {
      cls = verdictClass(verdict);
      label = cls === 'rose' ? (verdict === 'FAIL' ? failed() : verdict.toLowerCase()) : verdict === 'PASS' ? (architecture || f || errors ? 'passed' : 'clean') : verdict.toLowerCase();
      title = [`verdict ${verdict}`, counts, verdict === 'N/A' ? 'nothing to check here (no scanned host has content for this profile, or not a FIPS environment)'
        : verdict === 'INCOMPLETE' ? 'required evidence is missing, stale or could not be verified; see the report'
          : verdict === 'INCONCLUSIVE' ? 'the scan could not decide: see the report' : ''].filter(Boolean).join(' · ');
    } else if (f === null) { cls = ''; label = 'no totals'; title = 'this file carries no pass/fail summary'; }
    else { const bad = f + errors > 0; cls = bad ? 'rose' : 'leaf'; label = bad ? failed() : 'clean'; title = counts || undefined; }
    return { p, f, w, label, cls, title };
  }
  const stampOf = (name) => (/(\d{8}-\d{6})$/.exec(name) || [null, ''])[1];
  let reportsSig = '';   // what the Reports page shows now: a refresh that brings nothing new leaves it (and its scroll) alone
  views.reports = async () => {
    const seq = RENDER.reports = (RENDER.reports || 0) + 1;
    const v = $('#view-reports');
    const e = currentEnv();
    if (!e) {
      v.innerHTML = ''; delete v.dataset.env; reportsSig = '';
      v.append(STATE.envs.length ? emptyState('Pick an environment', 'Reports belong to an environment. Show the reports of:', ...STATE.envs.map((x) => el('button', { class: 'btn ghost', onclick: () => selectEnv(x.id).then(() => go('reports')) }, x.id)))
        : emptyState('No reports yet', 'Architecture assessments, DR drills, chaos runs and compliance scans save their reports here. Create an environment to get started.', el('button', { class: 'btn primary', onclick: () => go('create', { env: null }) }, 'Create environment')));
      return;
    }
    const hero = () => el('div', { class: 'hero' }, el('h2', {}, `Reports of ${e.id}`), el('p', {}, 'Architecture assessments, DR drills, chaos runs and compliance scans saved for this environment, and the logs of its setup, apply and destroy runs.'));
    // the reports of this environment already on screen stay there while the new answer is fetched (no flash of "Loading…")
    const shown = v.dataset.env === e.id && v.children.length > 0;
    if (!shown) { v.innerHTML = ''; reportsSig = ''; v.dataset.env = e.id; v.append(hero(), el('p', { class: 'muted' }, `Loading the reports of ${e.id}…`)); }
    let r;
    try { r = await api(`/api/reports?env=${encodeURIComponent(e.id)}`); }
    catch (err) {
      if (seq !== RENDER.reports) return;
      v.innerHTML = ''; delete v.dataset.env; reportsSig = '';
      v.append(hero(), el('div', { class: 'callout warn', role: 'alert' }, el('b', {}, `Could not load the reports of ${e.id}`), el('p', { class: 'small mono', style: 'margin:6px 0 8px' }, err.message),
        el('div', { class: 'row' }, el('button', { class: 'btn small primary', html: icon('refresh'), onclick: () => { const p = views.reports(); if (p && p.catch) p.catch(viewError); } }, el('span', {}, 'Retry')))));
      return;
    }
    if (seq !== RENDER.reports) return;   // a newer render owns the view
    const sig = JSON.stringify([e.id, r]);
    if (shown && sig === reportsSig) return;
    reportsSig = sig; v.innerHTML = ''; v.dataset.env = e.id;
    v.append(hero());
    const bar = (p, f, w) => { const t = p + f + (w || 0) || 1; return el('div', { class: 'bar', style: 'width:140px', 'aria-hidden': 'true' }, el('i', { class: 'p', style: `width:${100 * p / t}%` }), el('i', { class: 'f', style: `width:${100 * f / t}%` }), el('i', { class: 'w', style: `width:${100 * (w || 0) / t}%` })); };
    // every section uses the same fixed column widths, rows are labelled by run time (the file name is in the tooltip)
    const section = (title, items, row, xqb) => {
      const c = el('div', { class: 'card' }, el('h3', {}, title, xqb || null, el('span', { class: 'chip' }, items.length)));
      if (!items.length) { c.append(el('p', { class: 'muted small' }, 'None yet. Run one from ', el('a', { href: '#', onclick: (ev) => { ev.preventDefault(); go('resilience'); } }, 'Resilience'), '.')); return c; }
      const t = el('table', { class: 'reports' }, el('tr', {}, el('th', {}, 'run'), el('th', {}, 'result'), el('th', {}, 'summary'), el('th', {}, el('span', { class: 'sr-only' }, 'open'))));
      for (const it of items) {
        const kind = runKind(it.name), sm = reportSummary(it);
        t.append(el('tr', {}, el('td', { title: it.name }, el('span', { class: 'rep-when' }, runLabel(it.name)), kind && !REPORT_KIND[kind] ? el('span', { class: 'chip', title: kind }, SCAN_SHORT[kind] || scanTitle(kind)) : null), el('td', {}, row(it)),
          el('td', { class: 'small muted' }, Object.entries(sm).slice(0, 4).map(([k, val]) => `${colLabel(k)}: ${String(val).slice(0, 30)}`).join(' · ')), el('td', {}, el('button', { class: 'btn small ghost', 'aria-label': `Open ${title} report of ${runLabel(it.name)}`, onclick: () => showReport(it) }, 'Open'))));
      }
      c.append(el('div', { class: 'table-wrap' }, t)); return c;
    };
    const scans = [...(r.scans || [])].sort((a, b) => stampOf(b.name).localeCompare(stampOf(a.name)) || a.name.localeCompare(b.name));   // newest first, whatever the kind
    // log files are named <run stamp>-<command>.log: shown as a local time and the command (the file name in the tooltip)
    const logLabel = (p) => { const f = p.split('/').pop(), m = /^(\d{8}-\d{6})-(.+)\.log$/.exec(f); return m ? `${runLabel(m[1])} · ${m[2]}` : f.slice(0, 40); };
    v.append(el('div', { class: 'grid' },
      section('Chaos runs', r.chaos || [], (it) => el('div', { class: 'row' }, reportChip(it), bar(it.summary.PASS || 0, it.summary.FAIL || 0), el('span', { class: 'small' }, `${it.summary.PASS || 0} pass / ${it.summary.FAIL || 0} fail`)), explainBtn('chaos', 'chaos runs')),
      section('DR drills', r.dr || [], (it) => reportChip(it), explainBtn('dr', 'DR drills')),
      section('Scans', scans, (it) => { const c = scanChip(it); return el('div', { class: 'row' }, bar(c.p, c.f || 0, c.w), reportChip(it)); }, explainBtn('scan', 'scans')),
      el('div', { class: 'card' }, el('h3', {}, 'Logs', explainBtn('audit', 'logs and the audit trail'), el('span', { class: 'chip' }, (r.logs || []).length)), (r.logs || []).length ? null : el('p', { class: 'muted small' }, 'None yet. Every setup, apply and destroy writes one.'),
        el('div', { class: 'row' }, ...(r.logs || []).slice(0, 20).map((p) => el('button', { class: 'btn small ghost', title: p.split('/').pop(), onclick: async () => { try { const f = await api(`/api/file?path=${encodeURIComponent(p)}`); modal(`Log · ${logLabel(p)}`, [el('p', { class: 'muted small mono', style: 'margin:0 0 10px' }, p), el('pre', { class: 'help' }, f.text)], { explain: 'audit' }); } catch (err) { fail(err); } } }, logLabel(p)))))));
  };
  // report file names end in the UTC run stamp YYYYMMDD-HHMMSS; show it as a local date and keep the prefix as the kind
  const runKind = (name) => String(name || '').replace(/-?\d{8}-\d{6}$/, '');
  const runLabel = (name) => { const m = /(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})$/.exec(name || ''); const d = m ? new Date(Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6])) : null; return d && !isNaN(d) ? d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : String(name || ''); };
  const REPORT_KIND = { report: 'Chaos run', drill: 'DR drill' };
  // the scans the CLI saves, in words (the list chip uses the short name, the report dialog the full one)
  const SCAN_TITLES = { architecture: 'Well-Architected assessment', cis: 'CIS Kubernetes benchmark', 'stig-k8s': 'Kubernetes STIG', kube: 'Kubernetes posture (NSA/MITRE)', images: 'Vulnerability scan', 'stig-host': 'Host STIG (OpenSCAP)', cloud: 'Cloud CIS (prowler)', fips: 'FIPS verification' };
  const SCAN_SHORT = { architecture: 'Architecture', cis: 'CIS', 'stig-k8s': 'K8s STIG', kube: 'NSA/MITRE', images: 'Vulnerabilities', 'stig-host': 'Host STIG', cloud: 'Cloud CIS', fips: 'FIPS' };
  const scanTitle = (kind) => SCAN_TITLES[kind] || (/^host-(.+)$/.test(kind) ? `Host ${kind.slice(5).toUpperCase()} (OpenSCAP)` : kind ? kind + ' scan' : 'Report');
  // one wording for a report's verdict, in the list and in its dialog: lower-case words, counts for scans
  const reportChip = (it) => {
    if (!REPORT_KIND[runKind(it.name)]) { const c = scanChip(it); return el('span', { class: 'chip ' + c.cls, title: c.title }, c.label); }
    const v = it.verdict || '?';
    return el('span', { class: 'chip ' + verdictClass(v), title: v === 'INCONCLUSIVE' ? 'no experiment ran to a verdict (empty or all skipped)' : undefined }, String(v).toLowerCase());
  };
  // report columns in words (a trailing _s is seconds)
  const COL_LABEL = { min_availability: 'min availability', recovery_s: 'recovery (s)', recovery_bound_s: 'recovery bound (s)', seconds: 'seconds', rto_s: 'RTO (s)', total_s: 'total (s)' };
  const colLabel = (k) => COL_LABEL[k] || String(k).replace(/_s$/, ' (s)').replace(/_/g, ' ');
  // DR drill reports carry no summary block: the server sends the one `cs dr` shows (RTO, total, steps). For a server
  // that does not, it is derived here: RTO (restore + verify), total and the steps that passed. Only a drill that
  // recovered its workload (PASS) measured an RTO: a failed or interrupted one has none (its restore time is not a
  // recovery time), and neither has a file without a verdict (cs dr says "RTO not measured" too). The 'interrupted'
  // row is a note, not a step of the drill.
  const reportSummary = (it) => {
    if (Object.keys(it.summary || {}).length || runKind(it.name) !== 'drill') return it.summary || {};
    const steps = (it.results || []).filter((x) => x && x.step !== 'interrupted'), secs = (f) => Math.round(10 * steps.filter(f).reduce((a, x) => a + (Number(x.seconds) || 0), 0)) / 10;
    const verdict = it.verdict === undefined || it.verdict === null || it.verdict === '' ? null : String(it.verdict).trim().toUpperCase().split(/[\s:,]/)[0];
    const rto = verdict === 'PASS' ? `${typeof it.rto_s === 'number' ? it.rto_s : secs((x) => /^[45]\./.test(x.step || ''))}s` : '—';
    return steps.length ? { RTO: rto, total: `${it.total_s ?? secs(() => true)}s`, steps: `${steps.filter((x) => x.ok).length}/${steps.length} ok` } : {};
  };
  const cellChip = (v) => { const t = String(v); return el('span', { class: 'chip ' + verdictClass(t) }, t); };
  const REPORT_COLS = ['experiment', 'step', 'verdict', 'status', 'ok', 'availability', 'min_availability', 'recovered', 'recovery_s', 'recovery_bound_s', 'seconds', 'detail', 'reason'];
  const reportCell = (k, v) => v === undefined || v === null || v === '' ? '' : (k === 'verdict' || k === 'status') ? cellChip(v) : typeof v === 'boolean' ? el('span', { class: 'chip ' + (v ? 'leaf' : 'rose') }, v ? '✔ yes' : '✖ no')
    : /availability$/.test(k) && typeof v === 'number' && v >= 0 && v <= 1 ? Math.round(100 * v) + '%' : typeof v === 'object' ? JSON.stringify(v) : String(v);
  function showReport(it) {
    const body = el('div', {}), kind = runKind(it.name), sm = reportSummary(it);
    body.append(el('div', { class: 'row', style: 'margin-bottom:10px' }, it.verdict || !REPORT_KIND[kind] ? reportChip(it) : null, el('span', { class: 'muted small mono' }, it.name)));
    if (kind === 'architecture') {
      body.append(el('p', { class: 'muted small' }, `Profile: ${it.profile || 'unspecified'}. Assesses saved configuration and evidence; it does not verify live infrastructure. Missing evidence stays unknown.${it.max_age_days ? ` Evidence freshness: ${it.max_age_days} days.` : ''}`));
      if ((it.coverage_limits || []).length) body.append(el('details', {}, el('summary', {}, 'Assessment coverage and limits'), el('ul', {}, ...it.coverage_limits.map((limit) => el('li', { class: 'small' }, limit)))));
    }
    if (Object.keys(sm).length) body.append(kv(...Object.entries(sm).map(([k, val]) => [colLabel(k), String(val)])));
    // columns: the union over all rows, the meaningful ones first (verdict and reason are never cut off); description as a row tooltip
    const table = (rows) => {
      const keys = [...new Set(rows.flatMap((r) => Object.keys(r)))].filter((k) => !['kind', 'desc', 'started', 'probes'].includes(k));
      const cols = [...REPORT_COLS.filter((k) => keys.includes(k)), ...keys.filter((k) => !REPORT_COLS.includes(k))].slice(0, 8);
      const t = el('table', {}, el('tr', {}, ...cols.map((c) => el('th', {}, colLabel(c)))));
      for (const r of rows) t.append(el('tr', { title: r.desc || null }, ...cols.map((c) => el('td', { class: 'small' }, reportCell(c, r[c])))));
      return el('div', { class: 'table-wrap' }, t);
    };
    if ((it.results || []).length) body.append(el('h4', {}, kind === 'drill' ? 'Steps' : 'Results'), table(it.results));
    if (kind === 'architecture' && (it.findings || []).length) {
      body.append(el('h4', {}, `Checks (${it.findings.length})`));
      const t = el('table', {}, el('tr', {}, ...['status', 'pillar / check', 'evidence', 'remediation'].map((title) => el('th', {}, title))));
      const evidenceText = (value) => {
        if (!value || typeof value !== 'object') return String(value);
        const type = { declared_configuration: 'Declared configuration', saved_report: 'Saved report', manual_review: 'Manual review required' }[value.type] || colLabel(value.type || 'evidence');
        const fields = Array.isArray(value.fields) ? value.fields.join(', ') : '';
        const extra = Object.entries(value).filter(([key]) => !['type', 'source', 'fields', 'reason', 'live_verified'].includes(key)).map(([key, detail]) => `${colLabel(key)}: ${String(detail)}`);
        return [type, value.source, fields, value.reason, ...extra, value.live_verified === false ? 'Not checked live' : ''].filter(Boolean).join(' · ');
      };
      const guidance = (ref) => {
        const url = typeof ref === 'string' ? ref : ref && ref.url;
        return el('p', { class: 'muted small' }, typeof url === 'string' && /^https:\/\//i.test(url) ? el('a', { href: url, target: '_blank', rel: 'noopener noreferrer', title: url }, 'Provider guidance') : url || '',
          ref && typeof ref === 'object' && ref.scope ? ` · ${ref.scope}` : '');
      };
      for (const f of it.findings) {
        const evidence = Array.isArray(f.evidence) ? f.evidence : f.evidence ? [f.evidence] : [];
        const refs = Array.isArray(f.references) ? f.references : [];
        t.append(el('tr', {}, el('td', {}, cellChip(f.status || 'UNKNOWN')), el('td', { class: 'small' }, el('b', {}, f.title), el('p', { class: 'muted small' }, colLabel(f.pillar))),
          el('td', { class: 'small' }, f.detail, ...evidence.map((item) => el('p', { class: 'muted small' }, evidenceText(item)))),
          el('td', { class: 'small' }, f.remediation || '—', ...refs.map(guidance))));
      }
      body.append(el('div', { class: 'table-wrap' }, t));
    } else if (it.findings && it.findings.length && !(it.checks && it.checks.length)) { body.append(el('h4', {}, `Findings (${it.findings.length})`)); const t = el('table', {}, el('tr', {}, el('th', {}, 'severity'), el('th', {}, 'finding'), el('th', {}, 'detail'))); for (const f of it.findings) t.append(el('tr', {}, el('td', {}, el('span', { class: 'chip ' + ({ CRITICAL: 'rose', HIGH: 'rose', MEDIUM: 'seed', LOW: '', INFO: '' }[f.severity] || '') }, f.severity || f.status)), el('td', { class: 'small' }, f.title), el('td', { class: 'small muted' }, f.detail))); body.append(el('div', { class: 'table-wrap' }, t)); }
    if (it.checks && it.checks.length) { body.append(el('h4', {}, 'Checks')); const t = el('table', {}, el('tr', {}, el('th', {}, 'status'), el('th', {}, 'area'), el('th', {}, 'check'), el('th', {}, 'detail'))); for (const c of it.checks) t.append(el('tr', {}, el('td', {}, cellChip(c.status || 'INFO')), el('td', {}, c.area), el('td', { class: 'small' }, c.check), el('td', { class: 'small muted' }, c.detail))); body.append(el('div', { class: 'table-wrap' }, t)); }
    body.append(el('p', { class: 'muted small mono', style: 'margin-top:12px' }, it.path));
    const e = currentEnv();
    modal(`${REPORT_KIND[kind] || scanTitle(kind)} · ${runLabel(it.name)}${e ? ' · ' + e.id : ''}`, body, { explain: XQ_REPORT[REPORT_KIND[kind] ? kind : 'scan'] });
  }

  // Agents & MCP. Switches and the MCP enable button read the state when clicked (never a value captured when the page
  // was drawn), and views.agents.patch keeps them, the chips and the clients table in step with the state while a form
  // here holds unsent input (the page itself is then redrawn later).
  const featureOn = (k) => (k === 'agentic' ? !!STATE.settings.agentic : k === 'headliner' ? STATE.settings.headliner !== false : !!STATE.mcp.enabled);
  const toggleFeature = (k) => { const on = featureOn(k); run('cloudseed_' + (on ? 'disable' : 'enable'), { feature: k }, (on ? 'disable ' : 'enable ') + k); };
  const LIVE_CHIPS = {
    'agentic-chip': () => [STATE.settings.agentic ? 'leaf' : '', STATE.settings.agentic ? 'on' : 'off'],
    'agent-chip': () => ['', 'agent: ' + (STATE.settings.agent || 'none')],
    'mcp-chip': () => [STATE.mcp.enabled ? 'leaf' : '', STATE.mcp.enabled ? 'enabled' : 'disabled'],
    'mcp-run-chip': () => (STATE.mcp.url ? [STATE.mcp.running ? 'leaf' : 'rose', (STATE.mcp.running ? 'running · ' : 'down · ') + STATE.mcp.url] : ['', 'stdio only']),
  };
  const liveChip = (k) => { const [cls, text] = LIVE_CHIPS[k](); return el('span', { class: 'chip ' + cls, 'data-live': k }, text); };
  const mcpToggleText = () => (STATE.mcp.enabled ? 'Disable' : 'Enable (stdio)');
  // the MCP clients on this machine: connected (and over which transport), out of date (wired to a server that is not
  // there any more: Reconnect fixes it), installed but not connected, or not detected.
  // Reconnect keeps the transport the client uses (a client put on stdio on purpose - shell-exported credentials - stays
  // there): it rewrites the address and token. Only an HTTP client whose server is gone moves to stdio. A new connection
  // uses the deployed server (HTTP when there is one).
  const reconnectTransport = (c) => (c.connected === 'http' && !STATE.mcp.url ? 'stdio' : c.connected === 'http' || c.connected === 'stdio' ? c.connected : '');
  function clientsTable() {
    const t = el('table', { class: 'clients' }, el('tr', {}, el('th', {}, 'client'), el('th', {}, 'state'), el('th', {}, el('span', { class: 'sr-only' }, 'actions'))));
    for (const [k, c] of Object.entries(STATE.mcp.clients)) {
      const connect = (primary, text, title, transport) => el('button', { class: 'btn small ' + (primary ? 'primary' : 'ghost'), 'data-fk': `client:${k}:connect`, title,
        onclick: () => run('cloudseed_mcp', { action: 'connect', clients: [k], ...(transport ? { transport } : {}) }, (text === 'Reconnect' ? 'reconnect ' : 'connect ') + k) }, text);
      const tr = reconnectTransport(c);
      const reTitle = tr === 'stdio' && c.connected === 'http' ? `No HTTP MCP server is deployed any more: rewrites ${c.display}'s config to start cloudseed over stdio`
        : tr ? `Rewrite ${c.display}'s config with the current ${tr === 'http' ? 'server address and token' : 'command'}, keeping its ${tr} connection${tr === 'stdio' && STATE.mcp.url && (c.transports ? c.transports.includes('http') : k !== 'claude-desktop') ? ' (to use the HTTP server instead: Disconnect, then Connect)' : ''}` : `Rewrite ${c.display}'s config`;
      const acts = c.connected ? [connect(!!c.stale, 'Reconnect', reTitle, tr), el('button', { class: 'btn small ghost', 'data-fk': `client:${k}:disconnect`, onclick: () => run('cloudseed_mcp', { action: 'disconnect', clients: [k] }, 'disconnect ' + k) }, 'Disconnect')]
        : c.present ? [connect(true, 'Connect')] : [connect(false, 'Connect', `${c.display} was not detected: this pre-writes its config`)];
      const state = c.connected && c.stale ? el('span', { class: 'chip seed', title: 'Its config points at an MCP server that is not there any more (another port or an old token): Reconnect rewrites it' }, 'out of date · ' + c.connected)
        : c.connected ? el('span', { class: 'chip leaf' }, 'connected · ' + c.connected) : c.present ? el('span', { class: 'chip' }, 'installed · not connected') : el('span', { class: 'chip', style: 'opacity:.8' }, 'not detected');
      t.append(el('tr', {}, el('td', {}, el('b', {}, c.display)), el('td', {}, state), el('td', {}, el('div', { class: 'row' }, ...acts))));
    }
    return t;
  }
  // 'Connect all detected': the detected clients that are not connected, plus the out-of-date ones (read when clicked).
  // A client already connected stays as it is: `connect all` would move one deliberately on stdio over to HTTP.
  const connectAll = () => {
    const names = Object.entries(STATE.mcp.clients).filter(([, c]) => c.present && (!c.connected || c.stale)).map(([k]) => k);
    if (!names.length) return toast(Object.values(STATE.mcp.clients).some((c) => c.present) ? 'Every detected client is connected already (Reconnect rewrites one)' : 'No MCP client was detected on this machine (Connect in the table pre-writes the config of one)');
    run('cloudseed_mcp', { action: 'connect', clients: names }, 'connect ' + (names.length > 2 ? `${names.length} clients` : names.join(', ')));
  };
  views.agents = () => {
    const v = $('#view-agents'); v.innerHTML = '';
    const s = STATE.settings, m = STATE.mcp;
    const sw = (k, label) => el('label', { class: 'check', style: 'gap:12px' }, el('button', { type: 'button', role: 'switch', 'aria-checked': String(featureOn(k)), class: 'switch ' + (featureOn(k) ? 'on' : ''), 'data-live': k, 'data-fk': 'switch:' + k, onclick: () => toggleFeature(k) }), el('span', {}, label));
    const agentCard = el('div', { class: 'card' }, el('h3', {}, 'Agentic mode', explainBtn('agentic', 'agentic mode'), liveChip('agentic-chip'), liveChip('agent-chip')),
      el('p', { class: 'muted small' }, 'Let an agent drive cloudseed from plain English: the built-in agent (Claude API) or the Claude Code, Codex, Gemini and Grok CLIs. Credentials are stripped from the agent process; every output is redacted.'),
      sw('agentic', 'Agentic mode'), sw('headliner', 'Headliner research brief before each task'),
      el('div', { class: 'row', style: 'margin:8px 0 4px' }, el('button', { class: 'btn ghost small', 'data-fk': 'agents:status', onclick: () => run('cloudseed_agents', {}, 'agents') }, 'Agent status'), el('button', { class: 'btn ghost small', 'data-fk': 'agents:models', title: s.agent ? `models of ${s.agent}` : 'no agent chosen yet: shows the built-in agent\'s models', onclick: () => run('cloudseed_model', STATE.settings.agent ? {} : { agent: 'builtin' }, 'models') }, 'Models')),
      el('h4', {}, 'Choose the agent', explainBtn('use', 'choosing the agent')), actionForm(action('cloudseed_use'), { agent: s.agent || 'builtin' }, true),
      el('h4', {}, 'Run a task', explainBtn('command agentic', 'running a task')), actionForm(action('cloudseed_agentic'), {}, true, { task: 'e.g. list my environments and tell me which have a bastion running' }),
      el('h4', {}, 'Skills', explainBtn('skill', 'agent skills')), actionForm(action('cloudseed_skill'), { action: 'install' }, true));
    // one filled button (deploy); the rest are quiet, and what stops or removes the server sits apart at the end
    const b = (text, act, label, extra = {}) => el('button', { class: 'btn ghost', 'data-fk': 'mcp:' + act, onclick: () => run('cloudseed_mcp', { action: act }, label), ...extra }, text);
    const mcpCard = el('div', { class: 'card' }, el('h3', {}, 'MCP server', explainBtn('mcp', 'the MCP server'), liveChip('mcp-chip'), liveChip('mcp-run-chip')),
      el('p', { class: 'muted small' }, 'Every cloudseed feature as MCP tools for Claude Code, Claude Desktop, Codex, Cursor, Windsurf, Gemini CLI, VS Code and any other client.'),
      el('div', { class: 'row' }, el('button', { class: 'btn leaf', 'data-fk': 'mcp:setup', onclick: () => run('cloudseed_mcp', { action: 'setup', clients: [] }, 'deploy MCP server') }, '▶ Deploy local server'),
        el('button', { class: 'btn ghost', 'data-fk': 'mcp:connect-all', title: 'Connect every detected client that is not connected yet, and rewrite the out-of-date ones (clients already connected keep their transport)', onclick: connectAll }, 'Connect all detected'),
        b('Status', 'status', 'mcp status'), b('Self-test', 'test', 'mcp test'), b('Tools', 'tools', 'mcp tools'), b('Restart', 'restart', 'mcp restart'),
        el('button', { class: 'btn ghost', 'data-fk': 'mcp:guide', onclick: async () => { let g; try { g = await api('/api/mcp/guide'); } catch (err) { return fail(err); } showMcpGuide(g); } }, 'Connection guide')),
      el('div', { class: 'row danger-row' }, el('button', { class: 'btn ghost', 'data-live': 'mcp-toggle', 'data-fk': 'mcp:toggle', onclick: () => toggleFeature('mcp') }, mcpToggleText()), b('Stop', 'stop', 'mcp stop'), el('span', { class: 'spacer' }),
        el('button', { class: 'btn rose', 'data-fk': 'mcp:uninstall', onclick: () => run('cloudseed_mcp', { action: 'uninstall' }, 'remove MCP', { message: 'Stops the MCP server and removes its service, its token and the cloudseed entry from every client config it wrote.' }) }, 'Remove everything')),
      el('h4', {}, 'Clients on this machine', explainBtn('command mcp', 'connecting MCP clients')), el('div', { class: 'table-wrap' }, clientsTable()));
    v.append(el('div', { class: 'grid cols-2' }, agentCard, mcpCard));
  };
  views.agents.patch = () => {
    const v = $('#view-agents');
    for (const n of $$('[data-live]', v)) {
      const k = n.dataset.live;
      if (LIVE_CHIPS[k]) { const [cls, text] = LIVE_CHIPS[k](); n.className = 'chip ' + cls; n.textContent = text; }
      else if (k === 'mcp-toggle') n.textContent = mcpToggleText();
      else { const on = featureOn(k); n.setAttribute('aria-checked', String(on)); n.classList.toggle('on', on); }
    }
    const old = $('table.clients', v); if (old) { const mark = focusMark(v); old.replaceWith(clientsTable()); focusBack(v, mark); }
  };
  // The MCP connection guide: each section's rows as a label/value grid with commands and paths in code, and one
  // copy-paste snippet per client and transport - a client uses exactly one of them - each with its own Copy button.
  function showMcpGuide(g) {
    const cmdish = (x) => /^(cs|claude|codex|gemini|cloudseed)\s|^\//.test(x);
    const item = (x) => { const m = /^(cloudseed_\w+)(.*)$/.exec(x); return x.includes('`') ? withCode(x) : cmdish(x) ? el('code', {}, x) : m ? [el('code', {}, m[1]), m[2]] : x; };
    // a value is several parts set apart by runs of spaces (a state, then its command); a list of commands is joined by " · "
    const value = (text) => String(text).split(/\s{3,}/).filter(Boolean).map((p) => el('span', { class: 'part' }, p.split(' · ').map((x, i) => [i ? ' · ' : '', item(x)])));
    const b = el('div', { class: 'guide' });
    for (const sec of g.sections || []) {
      b.append(el('h4', { class: 'guide-title' }, sec.title));   // (titles hold commands: not upper-cased)
      const pairs = (sec.rows || []).filter((r) => Array.isArray(r)), lines = (sec.rows || []).filter((r) => !Array.isArray(r) && r);
      if (pairs.length) b.append(el('div', { class: 'kv guide-kv' }, pairs.map(([k, val]) => [el('span', { class: 'k' }, k), el('span', {}, value(val))])));
      for (const l of lines) b.append(el('p', { class: 'small' }, withCode(l)));
    }
    b.append(el('h4', {}, 'Copy-paste configuration'), el('p', { class: 'muted small' }, 'Use one variant per client: the shared HTTP server or stdio.'));
    const blocks = g.variants || Object.entries(g.configs || {}).map(([k, snip]) => ({ display: k, path: '', variants: [['', snip]] }));
    for (const blk of blocks) {
      b.append(el('div', { class: 'snip-head' }, el('b', {}, blk.display), blk.path ? el('span', { class: 'muted small mono' }, blk.path) : null));
      for (const [label, snip] of blk.variants || []) {
        // (an older server joins a client's variants into one text: that is shown, but not offered as one config to copy)
        const one = !!label || !/\n\n/.test(snip);
        b.append(el('div', { class: 'snip' }, label ? el('div', { class: 'small muted' }, withCode(label)) : null, el('pre', { class: 'help' }, snip),
          one ? el('button', { class: 'btn small ghost snip-copy', onclick: () => copyText(snip, `${blk.display} config`) }, 'Copy') : null));
      }
    }
    modal('How to connect an MCP client', b, { explain: 'mcp' });
  }

  views.creds = () => {
    const v = $('#view-creds'); v.innerHTML = '';
    v.append(el('div', { class: 'hero' }, el('h2', {}, 'Credentials vault'), el('p', {}, `Stored locally in ${STATE.home ? tildePath(STATE.home.replace(/\/$/, '')) + '/credentials.json' : '~/.cloudseed/credentials.json'} (0600), injected only into cloudseed commands, never displayed again once saved, never sent anywhere. Variables already exported in your shell win. Undo restores what you change.`)));
    // Every vault call reports what happened (or why not) and redraws from the server's answer. What was typed but not
    // saved in the other fields is carried over the redraw (the saved or cleared values are not: they are stored now).
    const credsCall = async (body, okMsg, srcForm) => {
      let r; try { r = await api('/api/creds', body); } catch (e) { fail(e); return false; }
      toast(okMsg, 'ok');
      // saved, but worth a look: a stored path that does not point at a file (yet)
      for (const w of (r && r.warnings) || []) toast('▲ ' + w, 'warn', 9000);
      try { await loadState(); } catch { /* the next poll catches up */ }
      if (VIEW !== 'creds') return true;
      const done = new Set([...(body.unset || []), ...Object.keys(body.set || {})]);
      const keep = $$('input, textarea', v).filter((i) => i.name && i.value !== '' && !done.has(i.name) && !(srcForm && srcForm.contains(i))).map((i) => [i.name, i.value]);
      const a = document.activeElement, at = a && v.contains(a) && a.name && !done.has(a.name) ? [a.name, typeof a.selectionStart === 'number' ? [a.selectionStart, a.selectionEnd] : null] : null;
      views.creds();
      for (const [name, value] of keep) { const i = $(`[name="${CSS.escape(name)}"]`, v); if (i) { i.value = value; const f = i.closest('form'); if (f) f.dataset.dirty = '1'; } }
      if (at) { const i = $(`[name="${CSS.escape(at[0])}"]`, v); if (i) { i.focus(); if (at[1]) try { i.setSelectionRange(at[1][0], at[1][1]); } catch { /* not a text field */ } } }
      return true;
    };
    const byGroup = {}; for (const c of STATE.creds) (byGroup[c.group] = byGroup[c.group] || []).push(c);
    const grid = el('div', { class: 'grid cols-2' });
    for (const [g, rows] of Object.entries(byGroup)) {
      const form = el('form', { class: 'card' }, el('h3', {}, STATE.creds_groups[g] || (g === 'custom' ? 'Custom variables' : humanKey(g)), explainBtn(XQ_CREDS[g] || 'creds', STATE.creds_groups[g] || g), el('span', { class: 'chip ' + (rows.some((r) => r.set) ? 'leaf' : '') }, `${rows.filter((r) => r.set).length} stored`)));
      for (const c of rows) {
        // a stored value is never shown again: its masked form (or, for plain settings, the value) is written next to the
        // chip. A stored JSON key says only whether it parses: one that does not is a warning (enter it again)
        const badJson = c.kind === 'json' && c.set && !!c.hint && !/^stored JSON key$/i.test(c.hint);
        const shownHint = c.set && c.hint && !/^stored\b/i.test(c.hint) ? c.hint : '';
        const inp = c.kind === 'json' ? el('textarea', { name: c.key, placeholder: !c.set ? '{"type": "service_account", ...}' : badJson ? 'paste the JSON key again' : 'paste a new JSON key to replace it' })
          : el('input', { name: c.key, type: c.kind === 'secret' ? 'password' : 'text', placeholder: c.set ? 'type a new value to replace it' : c.from_env ? 'set in your shell (it wins over the vault)' : '', autocomplete: c.kind === 'secret' ? 'new-password' : 'off' });
        const warn = c.ignored ? '' : badJson ? c.hint.charAt(0).toUpperCase() + c.hint.slice(1) : c.warning || '';
        const lab = el('label', {}, el('span', { class: 'lbl' }, c.key, ' ', c.ignored ? el('span', { class: 'chip seed', title: c.hint }, 'ignored') : c.set ? el('span', { class: 'chip leaf' }, 'stored') : c.from_env ? el('span', { class: 'chip' }, 'from shell') : null, shownHint && !c.ignored ? el('span', { class: 'stored-hint mono' }, shownHint) : null),
          el('div', { class: 'row', style: 'flex-wrap:nowrap' }, inp, c.set ? el('button', { type: 'button', class: 'btn small ghost', onclick: () => credsCall({ unset: [c.key] }, 'Removed ' + c.key) }, 'clear') : null), el('span', { class: 'hint' }, c.label),
          warn ? el('span', { class: 'field-warn', role: 'note' }, '▲ ' + warn) : null);
        form.append(lab);
      }
      form.append(el('button', { type: 'submit', class: 'btn primary' }, 'Save'));
      form.onsubmit = async (ev) => { ev.preventDefault(); const set = {}; for (const inp of $$('input,textarea', form)) if (inp.value.trim() !== '') set[inp.name] = inp.value.trim(); if (!Object.keys(set).length) return toast('Nothing to save: fill in a field first'); await credsCall({ set }, 'Saved ' + Object.keys(set).join(', '), form); };
      grid.append(form);
    }
    // a custom variable's value is typed blind (it is a secret as far as the vault is concerned)
    const custom = el('form', { class: 'card' }, el('h3', {}, 'Add a custom variable', explainBtn('creds', 'the credentials vault')), el('div', { class: 'form-grid' }, field('KEY', { type: 'string', label: 'Name', description: 'a variable name, e.g. MY_TOKEN', autocomplete: 'off' }, true, ''), field('VALUE', { type: 'string', label: 'Value', secret: true }, true, '')), el('button', { type: 'submit', class: 'btn primary' }, 'Save'));
    custom.onsubmit = async (ev) => {
      ev.preventDefault();
      const key = ($('[name="KEY"]', custom).value || '').trim().toUpperCase(), val = ($('[name="VALUE"]', custom).value || '').trim();
      if (!/^[A-Z_][A-Z0-9_]*$/.test(key)) return toast('✖ The name must be a variable name like MY_TOKEN: letters, digits and _, not starting with a digit', 'bad', 6000);
      if (key === 'PATH' || key === 'HOME') return toast(`✖ ${key} always comes from the console server's own environment; storing it would have no effect`, 'bad', 6000);
      if (!val) return toast('✖ A value is required (to remove a stored variable use its "clear" button)', 'bad', 6000);
      await credsCall({ set: { [key]: val } }, 'Saved ' + key, custom);
    };
    grid.append(custom);
    v.append(grid, el('div', { class: 'row', style: 'margin-top:12px' }, el('button', { class: 'btn ghost', 'data-fk': 'creds:doctor', onclick: () => run('cloudseed_doctor', {}, 'doctor') }, 'Check credentials (doctor)')));
  };

  // ---------------------------------------------------------------- help
  const HELP_TOPICS = ['quickstart', 'setup', 'security', 'state', 'deps', 'agentic', 'agents', 'mcp', 'ui', 'creds', 'undo', 'envs', 'services', 'vmware', 'platform', 'dr', 'chaos', 'scan', 'fips', 'destroy', 'troubleshooting', 'examples', 'variables aws', 'variables gcp', 'variables azure', 'variables vmware', 'outputs aws', 'outputs gcp', 'outputs azure', 'outputs vmware'];
  let helpSeq = 0, helpNext = null;
  // only the newest request may write the page: a slow earlier answer (e.g. the default page) never replaces the one asked for
  async function loadHelp(topic) {
    const seq = ++helpSeq; const pre = $('#help-text'); if (!pre) return;
    const art = $('#help-explain'); if (art) art.hidden = true; pre.hidden = false;   // (it replaces an explain page shown here)
    $$('#help-topics a').forEach((a) => a.classList.toggle('active', a.textContent === topic));
    pre.textContent = `loading ${topic || 'help'}…`;
    let r;
    try { r = await api(`/api/help?topic=${encodeURIComponent(topic)}`); }
    catch (e) { if (seq === helpSeq) { pre.textContent = `help for "${topic}" failed: ${e.message}`; fail(e, 'help: '); } return; }
    if (seq === helpSeq) pre.textContent = r.text;
  }
  function showHelp(topic) { helpNext = topic; go('help'); }
  views.help = () => {
    const v = $('#view-help');
    if (!v.dataset.built) {
      v.dataset.built = '1';
      const topics = el('div', { class: 'tabs', id: 'help-topics' }, ...HELP_TOPICS.map((t) => el('a', { onclick: () => showHelp(t) }, t)));
      const custom = el('form', { class: 'row', style: 'margin-bottom:12px' }, el('input', { placeholder: 'help <command|topic>  ·  explain <anything>', style: 'max-width:420px', 'data-nodirty': '', 'aria-label': 'Help topic or explain query' }), el('button', { type: 'submit', class: 'btn ghost' }, 'Show'));
      // `explain X` opens the Explain panel (no job: the page is documentation); `help X` loads the help page below
      custom.onsubmit = (ev) => { ev.preventDefault(); const inp = $('input', custom), q = inp.value.trim(); if (/^explain\b/i.test(q)) openExplain(q.replace(/^explain\s*/i, ''), { from: inp }); else showHelp(q.replace(/^help\s*/, '') || 'quickstart'); };
      v.append(explainSearch(), topics, custom, el('pre', { class: 'help', id: 'help-text' }, 'pick a topic'), el('article', { class: 'card xp-article', id: 'help-explain', hidden: true, 'aria-labelledby': 'help-explain-title' }), shortcutsCard());
    }
    const t = helpNext || (v.dataset.loaded ? null : 'quickstart'); helpNext = null;
    if (t && typeof t === 'object') { v.dataset.loaded = '1'; loadHelpExplain(t.explain, t.focus); }
    else if (t) { v.dataset.loaded = '1'; loadHelp(t); }
  };

  // An explain page in the Help view, full width (the panel's "Open in Help"); its links stay in the Help view
  async function loadHelpExplain(q, focus) {
    const seq = ++helpSeq, art = $('#help-explain'), pre = $('#help-text'); if (!art || !pre) return;
    $$('#help-topics a').forEach((a) => a.classList.remove('active'));
    pre.hidden = true; art.hidden = false;
    if (!XCACHE.has(xqNorm(q))) { art.innerHTML = ''; art.append(el('p', { class: 'muted', style: 'margin:0' }, `loading cs explain ${q}…`.replace('  ', ' '))); }
    let r;
    try { [r] = await Promise.all([xpFetch(q), loadNames().catch(() => null)]); }
    catch (e) { if (seq === helpSeq) { art.innerHTML = ''; art.append(el('p', { class: 'text-danger', style: 'margin:0' }, `cs explain ${q} failed: ${e.message}`)); fail(e, 'explain: '); } return; }
    if (seq !== helpSeq) return;
    const h = xpHead(r), nav = (x) => loadHelpExplain(x, true);
    art.innerHTML = '';
    art.append(el('header', { class: 'xp-a-head' }, el('div', { class: 'xp-kind' }, h.kind.filter(Boolean)), el('h2', { class: 'xp-title', id: 'help-explain-title', tabindex: '-1' }, h.title), h.summary ? el('p', { class: 'xp-summary' }, h.summary) : null),
      xpPage(r, nav, { palette: openPalette }),
      el('footer', { class: 'xp-foot' }, el('span', { class: 'xp-cli-l' }, 'CLI'), el('code', { class: 'xp-cli', title: r.cli }, r.cli), xpCopy(r.cli, `Copy the command ${r.cli}`), el('span', { class: 'spacer' }),
        el('button', { type: 'button', class: 'btn ghost small', onclick: (ev) => openExplain(r.query, { from: ev.currentTarget }) }, 'Open as a panel')));
    if (focus) $('#help-explain-title').focus({ preventScroll: false });
  }
  // The Help page's search over everything explainable: a few best matches as you type (Enter opens the first)
  const xRank = (n, q) => {
    const nm = n.name.toLowerCase(), words = nm.split(/[\s_-]+/);
    if (nm === q || n.query === q) return 0; if (nm.startsWith(q)) return 1; if (words.some((w) => w.startsWith(q))) return 2;
    if (nm.includes(q) || q.split(' ').every((w) => nm.includes(w))) return 3;
    return (n.summary || '').toLowerCase().includes(q) ? 4 : -1;
  };
  const xSearch = (q, limit = 8) => { q = xqNorm(q); if (!q || !XNAMES) return []; return XNAMES.map((n, i) => [xRank(n, q), i, n]).filter(([rk]) => rk >= 0).sort((a, b) => a[0] - b[0] || a[1] - b[1]).slice(0, limit).map(([, , n]) => n); };
  function explainSearch() {
    const input = el('input', { type: 'search', placeholder: 'vpn, aws, velero, single_nat_gateway…', 'data-nodirty': '', 'aria-label': 'Search everything cloudseed can explain', autocomplete: 'off', 'aria-describedby': 'xs-status', style: 'flex:1 1 240px' });
    const list = el('div', { class: 'xres' }), status = el('span', { class: 'sr-only', id: 'xs-status', 'aria-live': 'polite' });
    const popular = el('div', { class: 'xp-pills xs-popular' }, el('span', { class: 'muted small' }, 'Popular:'), XQ_POPULAR.map((q) => xpPill('', q, q, (x, ev) => openExplain(x, { from: ev && ev.currentTarget }))));
    const draw = () => {
      const q = input.value.trim(), found = xSearch(q); list.innerHTML = ''; popular.hidden = !!q;
      for (const n of found) list.append(el('button', { type: 'button', class: 'xres-row', onclick: (ev) => openExplain(n.query, { from: ev.currentTarget }) },
        el('span', { class: 'chip brand' }, XKIND[n.kind] || n.kind), el('b', {}, n.kind === 'variable' ? n.name.replace(/^(\S+) (.*)$/, '$2 ($1)') : n.name), el('span', { class: 'muted' }, n.summary)));
      if (q && !found.length) list.append(el('p', { class: 'muted small', style: 'margin:6px 2px 0' }, XNAMES ? `Nothing matches “${q}”. Enter asks cs explain anyway.` : 'Loading the list…'));
      status.textContent = q ? `${found.length} match${found.length === 1 ? '' : 'es'}` : '';
    };
    input.oninput = draw;
    input.onkeydown = (e) => {
      if (e.key === 'Enter') { e.preventDefault(); const q = input.value.trim(); if (!q) return; const f = xSearch(q, 1)[0]; openExplain(f ? f.query : q, { from: input }); }
      else if (e.key === 'ArrowDown') { const b = $('.xres-row', list); if (b) { e.preventDefault(); b.focus(); } }
    };
    list.onkeydown = (e) => {
      const rows = $$('.xres-row', list), i = rows.indexOf(document.activeElement); if (i < 0) return;
      if (e.key === 'ArrowDown' && i < rows.length - 1) { e.preventDefault(); rows[i + 1].focus(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); (i ? rows[i - 1] : input).focus(); }
    };
    loadNames().then(() => { if (input.value.trim()) draw(); }).catch(() => null);
    return el('section', { class: 'card xsearch', 'aria-labelledby': 'xs-title' }, el('h3', { id: 'xs-title' }, 'Explain anything'),
      el('p', { class: 'muted small' }, 'Every feature, target, command, topic, platform group and item, and setup variable: the page ', el('code', {}, 'cs explain'), ' prints, as a page. Look for the ', el('span', { class: 'xq-inline', html: icon('xq') }), ' beside things across the console, or press ', el('kbd', {}, '?'), ' on any page.'),
      el('div', { class: 'row' }, input, el('button', { type: 'button', class: 'btn ghost', onclick: (ev) => openExplain('', { from: ev.currentTarget }) }, 'Browse everything')), popular, list, status);
  }
  // the console's keyboard shortcuts (the ? key included)
  const shortcutsCard = () => el('section', { class: 'card keys-card', 'aria-labelledby': 'keys-title' }, el('h3', { id: 'keys-title' }, 'Keyboard shortcuts'),
    el('dl', { class: 'keys' }, [[[MOD + 'K'], 'Search actions, environments, the catalog and explanations'], [['?'], 'Explain the page you are on'], [['1', '0'], 'Go to a view, in the order of the sidebar'],
      [['`'], 'Show or hide Activity'], [[MOD + 'B'], 'Collapse the sidebar (the menu on a small screen)'], [['Esc'], 'Close the explanation, a dialog or the palette'], [['Alt', '←'], 'Back, in the explanation']]
      .map(([ks, what]) => [el('dt', {}, ks.map((k, i) => [i ? (ks[0] === '1' ? '–' : '+') : '', el('kbd', {}, k)])), el('dd', {}, what)])));

  // ---------------------------------------------------------------- undo
  // The arguments that make `cloudseed undo` act on exactly this row. A row of an environment names it (cloud + env); the
  // entry id is passed when the server's undo action understands it (then a stale page cannot undo something else).
  // A global row needs a way to name the global scope: without one a bare `cloudseed undo` takes the newest entry of ANY
  // scope, so the button is only offered when this row is that newest entry.
  const undoProps = () => ((action('cloudseed_undo') || {}).schema || {}).properties || {};
  function undoTarget(e, list) {
    const props = undoProps();
    const a = {};
    if (e.scope !== 'global') { const i = e.scope.indexOf('-'); a.cloud = e.scope.slice(0, i); a.env = e.scope.slice(i + 1); }
    if (props.id && e.id) a.id = e.id;
    if (e.scope === 'global') { if (props.scope) a.scope = 'global'; else if (props.global) a.global = true; }
    const exact = e.scope !== 'global' || a.id || a.scope || a.global;
    return exact || list[0] === e ? a : null;
  }
  // Discard drops an entry whose undo cannot succeed (or no longer applies) without changing anything; it needs the
  // entry's id, so a stale page can never drop a different one.
  const canDiscard = (e) => !!(undoProps().drop && undoProps().id && e.id);
  function openUndo() {
    const list = (STATE && STATE.undo) || []; const body = el('div', {});
    if (!list.length) {
      body.append(el('p', {}, 'Nothing to undo yet.'), el('p', { class: 'muted small' }, 'Changes made here, in the CLI or by an agent appear in this list; up to fifteen are kept per environment (at most five of one kind, and fifteen for global settings). In a terminal: cs undo --list.'));
      modal('Undo history', body, { narrow: true }); modalExplain('undo'); return;
    }
    const panel = el('div', {});
    // the table scrolls sideways on a phone instead of squeezing its columns to a letter each
    const seen = new Set(); const t = el('table', { class: 'undo' }, el('tr', {}, el('th', {}, 'when'), el('th', {}, 'scope'), el('th', {}, 'action'), el('th', {}, 'undo would'), el('th', {}, el('span', { class: 'sr-only' }, 'actions'))));
    for (const e of list) {
      const first = !seen.has(e.scope); seen.add(e.scope);
      const target = first ? undoTarget(e, list) : null;
      const cell = !first ? el('span', { class: 'muted small' }, 'after the newer one')
        : el('div', { class: 'row', style: 'flex-wrap:nowrap' },
          target ? el('button', { class: 'btn small rose', onclick: () => askUndo(e, panel) }, '↶ Undo')
            : el('span', { class: 'muted small', title: 'This console cannot single out the global scope: undo the newer entries first (or run cloudseed undo in a terminal).' }, 'undo newer entries first'),
          canDiscard(e) ? el('button', { class: 'btn small ghost', title: 'Remove this entry from the history without undoing it (for a step whose undo keeps failing or no longer applies)', onclick: () => askUndo(e, panel, true) }, 'Discard') : null);
      t.append(el('tr', {}, el('td', { class: 'small muted' }, fmtTime(e.at)), el('td', {}, el('span', { class: 'chip' }, e.scope)), el('td', { class: 'small' }, e.summary), el('td', { class: 'small muted' }, e.inverse), el('td', { class: 'act' }, cell)));
    }
    body.append(el('div', { class: 'table-wrap' }, t), panel, el('p', { class: 'muted small', style: 'margin-top:12px' }, 'Up to fifteen changes are kept per environment (at most five of one kind, and fifteen for global settings); reports and scans have five slots of their own. Older changes can no longer be undone here.'));
    modal('Undo history', body, { explain: 'undo' });
  }
  // second step: say exactly what will happen, then run it for this entry only
  function askUndo(e, panel, drop = false) {
    panel.innerHTML = '';
    const risky = !drop && /destroy|re-apply|setup again|uninstall|delete|revoke|restore/i.test(e.inverse || '');
    const ok = el('button', { class: 'btn ' + (drop ? 'primary' : 'rose'), onclick: () => doUndo(e, drop) }, drop ? 'Discard entry' : '↶ Confirm undo');
    panel.append(el('div', { class: 'card flat', style: 'margin-top:14px' },
      el('h3', {}, (drop ? 'Discard “' : 'Undo “') + e.summary + '”', el('span', { class: 'chip' }, e.scope)),
      drop ? el('p', {}, 'Removes this entry from the undo history. Nothing is changed or reverted, and this step can no longer be undone; the entries before it become undoable.')
        : el('p', { class: risky ? 'text-danger' : null }, 'Undo would: ' + e.inverse + '.'),
      el('p', { class: 'muted small' }, drop ? 'Use it for a step whose undo keeps failing or no longer applies.' : 'Only this entry is undone (auto-approved); the rest of the history stays.'),
      el('div', { class: 'row' }, ok, el('button', { class: 'btn ghost', onclick: () => { panel.innerHTML = ''; } }, 'Cancel'))));
    ok.focus();
  }
  async function doUndo(e, drop = false) {
    try { await loadState(); } catch (err) { return fail(err); }
    const list = STATE.undo || [];
    const cur = list.find((x) => (e.id && x.id ? x.id === e.id : x.scope === e.scope && x.at === e.at && x.summary === e.summary));
    const a = cur && list.find((x) => x.scope === cur.scope) === cur ? undoTarget(cur, list) : null;
    if (!a || (drop && !(a.id && canDiscard(cur)))) { toast('The undo history changed meanwhile: review it again.', 'bad', 6000); return openUndo(); }
    // without a way to name the global scope, `cloudseed undo` takes the newest entry of any scope: a job that finishes
    // meanwhile (a setup records 'created') would make that another environment's entry - wait until nothing runs
    const inexact = cur.scope === 'global' && !a.id && !a.scope && !a.global;
    if (inexact && (STATE.jobs || []).some((j) => j.running)) return toast('A job is still running and may add a newer undo entry: undo this global entry once it has finished.', 'bad', 7000);
    closeModal();
    run('cloudseed_undo', { ...a, ...(drop ? { drop: true } : {}), confirm: true }, (drop ? 'discard undo ' : 'undo ') + cur.summary.slice(0, 40));
  }
  // (the history is read fresh on every click: entries made in the CLI or by an agent show up at once)
  $('#undo-btn').onclick = async () => { try { await loadState(); } catch (err) { fail(err); } openUndo(); };

  // ---------------------------------------------------------------- palette, keyboard, navigation
  const palette = $('#palette'); const pinput = $('#palette-input'); const plist = $('#palette-list'); let pIdx = 0, pItems = [];
  function paletteItems() {
    const items = [];
    for (const [id, label] of NAV) items.push({ kind: 'view', label, sub: '', go: () => go(id) });
    if (!STATE) return items;
    // an environment: select it on this page and show its card (the terminal's current environment is not changed)
    for (const e of STATE.envs) items.push({ kind: 'env', label: e.id, sub: [e.name, e.region].filter(Boolean).join(' · '), go: () => selectEnv(e.id).then(() => showEnvCard(e.id)) });
    for (const a of ACTIONS) items.push({ kind: 'action', label: a.name.replace('cloudseed_', '').replace(/_/g, ' '), sub: a.description, go: () => openAction(a.name) });
    // catalog entries open the install form (with its confirmation): Enter in a search box never installs anything by itself
    for (const i of STATE.platform.items) items.push({ kind: 'catalog', label: i.name, sub: 'install… · ' + i.desc, go: () => openAction('cloudseed_platform', { action: 'install', items: [i.name] }) });
    for (const g of Object.keys(STATE.platform.groups)) items.push({ kind: 'group', label: 'install ' + g, sub: String(STATE.platform.groups[g]).replace(/`/g, ''), go: () => openAction('cloudseed_platform', { action: 'install', items: [g] }) });
    for (const t of HELP_TOPICS) items.push({ kind: 'help', label: 'help ' + t, sub: '', go: () => showHelp(t) });
    // each entry says what it is (a word can name several things: vpn the feature and the command)
    const xpLabel = (n) => { const m = /^(\S+) (.*)$/.exec(n.name); return n.kind === 'variable' && m ? `${m[2]} (${XCLOUD[m[1]] || m[1]} variable)` : `${n.name} (${(XKIND[n.kind] || n.kind).toLowerCase()})`; };
    for (const n of XNAMES || []) items.push({ kind: 'explain', label: 'Explain: ' + xpLabel(n), xname: n.kind === 'variable' ? n.name.replace(/^\S+ /, '') : n.name, sub: n.summary, go: () => openExplain(n.query) });
    return items;
  }
  function openPalette() {
    if (!STATE) return;
    if (xpOpen()) closeExplain({ instant: true });
    if (!XNAMES) loadNames().then(() => { if (!palette.classList.contains('hidden')) renderPalette(); }).catch(() => null);
    palette.classList.remove('hidden'); pinput.setAttribute('aria-expanded', 'true'); pinput.value = ''; renderPalette(); pinput.focus(); }
  const closePalette = () => { palette.classList.add('hidden'); pinput.setAttribute('aria-expanded', 'false'); };
  const markActive = () => { $$('.pi', plist).forEach((n, i) => { n.classList.toggle('active', i === pIdx); n.setAttribute('aria-selected', String(i === pIdx)); }); if (pItems.length) pinput.setAttribute('aria-activedescendant', 'pi-' + pIdx); else pinput.removeAttribute('aria-activedescendant'); };
  // Matches are ranked - the exact name, then names starting with the query, then a word of the name, then anywhere in
  // the name, then only in the description or kind - and keep their kind order within a rank (views, environments,
  // actions, catalog items, groups, help). So Enter on a typed catalog name opens that item, not a form mentioning it.
  const paletteRank = (i, q) => {
    const l = i.label.toLowerCase();
    if (l === q) return 0; if (l.startsWith(q)) return 1; if (l.split(/[\s/-]+/).some((w) => w.startsWith(q))) return 2; if (l.includes(q)) return 3;
    return (l + ' ' + i.sub + ' ' + i.kind).toLowerCase().includes(q) ? 4 : -1;
  };
  // (an Explain entry named exactly what was typed comes first among the Explain entries of its rank, still after the rest)
  const paletteScore = (i, q) => { const r = paletteRank(i, q); return r > 0 && i.xname !== undefined && i.xname !== q ? r + 0.5 : r; };
  function renderPalette() {
    const q = pinput.value.toLowerCase().trim(); const all = paletteItems();
    pItems = (q ? all.map((i, n) => [paletteScore(i, q), n, i]).filter(([rk]) => rk >= 0).sort((a, b) => a[0] - b[0] || a[1] - b[1]).map(([, , i]) => i) : all.slice(0, 40)).slice(0, 60); pIdx = 0;
    plist.innerHTML = ''; plist.scrollTop = 0; pItems.forEach((i, n) => plist.append(el('div', { class: 'pi' + (n === pIdx ? ' active' : ''), id: 'pi-' + n, role: 'option', tabindex: '-1', 'aria-selected': String(n === pIdx), onmousemove: () => { if (pIdx !== n) { pIdx = n; markActive(); } }, onclick: () => { closePalette(); i.go(); } }, el('span', { class: 'kind' }, i.kind), el('span', {}, i.label), el('span', { class: 'sub' }, i.sub))));
    if (pItems.length) pinput.setAttribute('aria-activedescendant', 'pi-' + pIdx); else pinput.removeAttribute('aria-activedescendant');
    if (!pItems.length) plist.append(el('div', { class: 'pi muted' }, 'no matches'));
  }
  pinput.oninput = renderPalette;
  // the keys work wherever focus is inside the palette; the input is its only control, so Tab stays on it, and a click
  // in the list (an option, the padding, the scrollbar) never takes focus away from it
  $('.palette-card').addEventListener('keydown', (e) => {
    if (e.key === 'Tab') { e.preventDefault(); pinput.focus(); return; }
    if (e.key === 'ArrowDown') { pIdx = Math.min(pIdx + 1, pItems.length - 1); } else if (e.key === 'ArrowUp') { pIdx = Math.max(pIdx - 1, 0); } else if (e.key === 'Enter') { e.preventDefault(); if (pItems[pIdx]) { closePalette(); pItems[pIdx].go(); } return; }   /* (no default: the Enter must not also submit the form it opens) */ else if (e.key === 'Escape') { closePalette(); return; } else return;
    e.preventDefault(); markActive(); const n = $$('.pi', plist)[pIdx]; if (n) n.scrollIntoView({ block: 'nearest' });
  });
  plist.addEventListener('mousedown', (e) => e.preventDefault());
  plist.addEventListener('focusin', () => pinput.focus());
  $('#palette-btn').onclick = openPalette; palette.addEventListener('click', (e) => { if (e.target === palette) closePalette(); });
  document.addEventListener('keydown', (e) => {
    if (!STATE) return;   // shortcuts wait for the first state load
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); return; }
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'b') { e.preventDefault(); toggleRail(); return; }
    if (e.key === 'Escape') { if (xpOpen()) { closeExplain(); return; } closePalette(); closeModal(); if ($('#app').classList.contains('nav-open')) setNav(false); return; }
    if (modalOpen() || !palette.classList.contains('hidden') || xpOpen()) return;   // shortcuts never act behind a dialog
    if (e.target.matches('input,textarea,select') || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === '?') { e.preventDefault(); openExplain(XQ_VIEW[VIEW] ?? ''); return; }   // explain this page
    const nav = NAV.find(([, , k]) => k === e.key); if (nav) { go(nav[0]); focusMain(); }
    if (e.key === '`') setDrawer(!drawer.classList.contains('open'));
  });
  addEventListener('unhandledrejection', (ev) => { const m = ev.reason && ev.reason.message ? ev.reason.message : String(ev.reason || ''); if (m) toast('✖ ' + m, 'bad', 6000); });
  function go(view, opts) {
    if (!views[view]) return;
    VIEW = view; if ($('#app').classList.contains('nav-open')) setNav(false);
    $$('#nav a').forEach((a) => { a.classList.toggle('active', a.dataset.view === view); if (a.dataset.view === view) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); }); $$('.view').forEach((s) => s.classList.toggle('active', s.id === 'view-' + view)); $('#crumb-view').textContent = NAV.find((n) => n[0] === view)[1]; xqCrumb(view);
    if (!STATE) return;   // still loading: the view picked now is drawn once the state is there
    const sec = $('#view-' + view); if (sec) { delete sec.dataset.dirty; delete sec.dataset.stale; }
    try { const r = views[view](opts); if (r && r.catch) r.catch(viewError); } catch (err) { viewError(err); }
    $('#main').scrollTop = 0;
  }
  // The selector is this page's choice (kept per tab). Choosing an environment here never changes the CLI's current
  // environment - the one terminal cluster commands act on (cs env use): that takes 'Use in terminal' on its card.
  async function selectEnv(id) { const sel = $('#current-env'); if (sel.value !== id) sel.value = id; sel.title = id || ''; ssSet('cs-env', id); }
  async function useInTerminal(id) {
    let r; try { r = await api('/api/env/use', { id }); } catch (err) { return fail(err); }
    if (STATE) STATE.current_env = r.current_env || null; lastServerCurrent = STATE ? STATE.current_env : undefined;
    toast(`Terminal cluster commands (kubectl, helm, node, platform …) now act on ${id} (cs env use ${id})`, 'ok', 6000);
    try { await loadState(); } catch { /* the next poll catches up */ }
    refreshView();
    // the button is gone now (the card says 'CLI default'): keep the keyboard on that card
    const h = $(`#view-${VIEW} [data-env="${CSS.escape(id)}"] h3`); if (h && (!document.activeElement || document.activeElement === document.body)) h.focus({ preventScroll: true });
  }
  $('#current-env').onchange = async () => {
    const id = $('#current-env').value; ssSet('cs-env', id); $('#current-env').title = id || '';
    // env-specific pages redraw for the new environment; forms elsewhere keep what was typed
    if (['overview', 'envs', 'platform', 'resilience', 'reports'].includes(VIEW)) { const r = views[VIEW](); if (r && r.catch) r.catch(viewError); }
    else if (VIEW === 'actions' && !editing($('#view-actions'))) views.actions();
  };

  let lastServerCurrent, stateSig = '';
  // a path under the user's home directory, the way a shell shows it (~/.cloudseed)
  const tildePath = (p) => String(p || '').replace(/^\/(?:Users|home)\/[^/]+(?=\/|$)|^\/root(?=\/|$)/, '~');
  async function loadState() {
    const s = await api('/api/state');
    if (!ACTIONS.length) ACTIONS = await api('/api/actions');
    STATE = s; tokenBack();
    $('#main').removeAttribute('aria-busy'); const boot = $('#boot'); if (boot) boot.remove();   // the loading placeholder
    $('#version').textContent = 'v' + STATE.version;
    const sel = $('#current-env'); const first = !sel.dataset.ready; const prev = sel.value;
    sel.innerHTML = ''; sel.append(el('option', { value: '' }, '— none —'));
    for (const e of STATE.envs) sel.append(el('option', { value: e.id }, `${e.id}${e.kubernetes ? ' ☸' : ''}`));
    const exists = (id) => !!id && STATE.envs.some((e) => e.id === id);
    let want;
    if (!first) want = prev === '' || exists(prev) ? prev : exists(STATE.current_env) ? STATE.current_env : '';   // keep the page's choice ('— none —' included) unless its env is gone
    else { const stored = ssGet('cs-env'); want = stored !== null && (stored === '' || exists(stored)) ? stored : exists(STATE.current_env) ? STATE.current_env : (STATE.envs.find((e) => e.kubernetes) || STATE.envs[0] || { id: '' }).id; }
    sel.value = want; sel.title = want || ''; sel.dataset.ready = '1';   // (the title shows a name the narrow selector cuts off)
    if (!first && lastServerCurrent !== undefined && STATE.current_env !== lastServerCurrent && STATE.current_env && STATE.current_env !== sel.value) toast(`The CLI's current environment is now ${STATE.current_env}; this page stays on ${sel.value || 'none'} (switch top right to follow).`, '', 7000);
    lastServerCurrent = STATE.current_env;
    $('#rail-status').innerHTML = '';
    $('#rail-status').append(el('div', { class: 'row-s' }, el('span', { class: 'dot', 'aria-hidden': 'true', style: `background:${STATE.mcp.running || (STATE.mcp.enabled && !STATE.mcp.url) ? '#4ade80' : '#64748b'}` }), 'MCP ' + (STATE.mcp.url ? (STATE.mcp.running ? 'running' : 'down') : STATE.mcp.enabled ? 'stdio' : 'off')),
      el('div', { class: 'row-s' }, el('span', { class: 'dot', 'aria-hidden': 'true', style: `background:${STATE.settings.agentic ? '#4ade80' : '#64748b'}` }), 'agent ' + (STATE.settings.agentic ? STATE.settings.agent || 'builtin' : 'off')),
      // CLOUDSEED_HOME as a shell shows it (~/.cloudseed); a long one keeps its meaningful end visible (leading
      // ellipsis); the whole path is in the tooltip
      el('div', { class: 'row-s rail-home', title: 'CLOUDSEED_HOME: ' + STATE.home }, el('span', {}, '‎' + tildePath(STATE.home) + '‎')));
    $('#undo-btn').title = (STATE.undo || []).length ? `Undo history (${STATE.undo.length} ${STATE.undo.length === 1 ? 'entry' : 'entries'})` : 'Undo history: nothing recorded yet';
    // jobs: the server's status wins (a job whose stream this page is not following still ends here)
    const listed = new Set(); const finished = [];
    for (const j of STATE.jobs) { listed.add(j.id); const was = (jobs.get(j.id) || {}).running; const m = trackJob(j.id, j); if (was && !m.running) finished.push(m); }
    for (const [id, j] of jobs) if (j.running && !listed.has(id) && !(id === activeJob && es)) checkJob(id, false);   // restarted server, or older than the list
    for (const j of finished) { if (j.id === activeJob && !es) $('#job-status').textContent = jobStatusText(j); announce(j); }
    renderTabs();
    const sig = JSON.stringify([STATE.envs, STATE.settings, STATE.mcp, STATE.creds, STATE.undo, STATE.jobs.map((j) => [j.id, j.running, j.rc])]);
    const changed = sig !== stateSig; stateSig = sig;
    return { changed: changed || finished.length > 0, selChanged: !first && prev !== sel.value };
  }
  // The first load: the view picked meanwhile (or the Overview) is drawn once the state is there. When it fails, the
  // page says why - the server is not running, it refused this tab's token, or it hit an error - and offers a retry.
  function startupFailed(e) {
    const st = e && e.status;
    const [title, text, cmd] = st === 401 ? ['This console link is no longer valid', 'The console’s access token changed since this tab was opened. Open the console again with its current link:', 'cs ui']
      : st === 0 ? ['Cannot reach the cloudseed console', 'Is it running? Check it, and read its log:', 'cs ui status\ncs ui logs'] : st >= 500 ? ['The console server hit an error', (e && e.message) || 'unknown error', 'cs ui logs']
        : ['The console could not start', (e && e.message) || 'unknown error', 'cs ui logs'];
    const logo = el('img', { src: document.documentElement.dataset.theme === 'dark' ? '/assets/logo-dark.svg' : '/assets/logo.svg', alt: 'cloudseed', width: '280', height: '62' });
    const retry = el('button', { class: 'btn primary', type: 'button', onclick: () => location.reload() }, 'Retry');
    document.body.innerHTML = '';
    document.body.append(el('div', { class: 'locked' }, el('main', { class: 'lock-card', role: 'alert' }, logo, el('h1', {}, title), el('p', {}, text), el('pre', {}, cmd), st !== 401 && e && e.message && text !== e.message ? el('p', { class: 'muted small' }, e.message) : null, el('div', { class: 'row', style: 'justify-content:center;margin-top:14px' }, retry))));
    retry.focus();
  }
  loadState().then(() => { go(VIEW); loadNames().catch(() => null); }).catch(startupFailed);
  // background refresh: every 30 s, or every 6 s while a job runs that no open stream is following
  let lastPoll = Date.now();
  setInterval(async () => {
    if (document.hidden || !STATE) return;
    const unwatched = Array.from(jobs.values()).some((j) => j.running && !(j.id === activeJob && es));
    if (Date.now() - lastPoll < (unwatched ? 6000 : 30000)) return;
    lastPoll = Date.now();
    try {
      const r = await loadState(); const sec = $('#view-' + VIEW);
      if (r.changed || r.selChanged || (sec && sec.dataset.stale)) refreshView();
    } catch (err) { /* a refused token is announced by request(); otherwise offline for a moment: the next tick retries */ }
  }, 2000);
})();

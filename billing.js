/* ============================================================
 * BCL Billing Portal — owner-only billing analytics & uploads.
 *
 * Pattern: PBKDF2 vault.json gates login; secrets (GitHub PAT,
 * optional Anthropic key) decrypt to a sessionStorage blob.
 * All persistent state lives in this repo under /billing/.
 *
 *   billing/vault.json         encrypted login secrets
 *   billing/data.json          crunched analytics (loop writes this)
 *   billing/uploads/<cat>/...  raw billing files dropped by owner
 *   billing/comments/*.json    AI + user comment thread
 *
 * A scheduled loop watches /billing/uploads/*, processes new files,
 * and rewrites data.json with refreshed KPIs + insights[].
 * ============================================================ */

(function () {
'use strict';

// ---------- constants ----------
const SESSION_KEY = 'dnzBillingSession.v3';   // bumped: forces re-login so cached sessions pick up the kdfInput needed for data decryption
const SECTIONS = [
  { key: 'inbox',       label: 'Inbox',        hint: 'newly uploaded — awaiting classification' },
  { key: 'ar-aging',    label: 'AR Aging',     hint: 'aging buckets, open invoices' },
  { key: 'wip',         label: 'WIP',          hint: 'unbilled time + costs' },
  { key: 'billings',    label: 'Billings',     hint: 'invoices issued' },
  { key: 'collections', label: 'Collections',  hint: 'payments received' },
  { key: 'time',        label: 'Time',         hint: 'timekeeper productivity' },
  { key: 'other',       label: 'Other',        hint: 'anything else' },
];

// ---------- DOM helpers ----------
const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  if (props) Object.entries(props).forEach(([k, v]) => {
    if (k === 'class') n.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(n.style, v);
    else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
    else if (k === 'html') n.innerHTML = v;
    else if (v != null) n.setAttribute(k, v);
  });
  kids.flat().forEach((k) => {
    if (k == null || k === false) return;
    n.appendChild(typeof k === 'string' ? document.createTextNode(k) : k);
  });
  return n;
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}
function fmtMoney(n) {
  const num = Number(n) || 0, sign = num < 0 ? '−$' : '$', a = Math.abs(num);
  if (a >= 1000000) return sign + (a / 1000000).toFixed(1) + 'M';
  if (a >= 10000) return sign + Math.round(a / 1000) + 'K';
  return sign + a.toLocaleString('en-US', { maximumFractionDigits: 0 });
}
function fmtMoneyFull(n) {
  const num = Number(n) || 0;
  return (num < 0 ? '−$' : '$') + Math.abs(num).toLocaleString('en-US', { maximumFractionDigits: 0 });
}
function fmtNum(n) { return (Number(n) || 0).toLocaleString('en-US'); }
function fmtPct(n) { return (Number(n) || 0).toFixed(1) + '%'; }
function fmtDate(iso) {
  if (!iso) return '—';
  try {
    // Parse YYYY-MM-DD as a LOCAL date (avoid the UTC-midnight → prior-day shift).
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(iso));
    const d = m ? new Date(+m[1], +m[2] - 1, +m[3]) : new Date(iso);
    if (isNaN(d)) return String(iso);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  } catch { return String(iso); }
}
// Whole days between two YYYY-MM-DD dates (parsed as local, like fmtDate). Used
// to annualize YTD figures and compute days-sales-outstanding in the brief.
function daysBetween(a, b) {
  const pa = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(a || ''));
  const pb = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(b || ''));
  if (!pa || !pb) return 0;
  const da = new Date(+pa[1], +pa[2] - 1, +pa[3]), db = new Date(+pb[1], +pb[2] - 1, +pb[3]);
  return Math.max(1, Math.round((db - da) / 86400000));
}
function fmtRelative(iso) {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.round(s / 60) + 'm ago';
  if (s < 86400) return Math.round(s / 3600) + 'h ago';
  if (s < 86400 * 7) return Math.round(s / 86400) + 'd ago';
  return fmtDate(iso);
}
function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(1) + ' MB';
}
function slugify(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
}
// GL category labels come through as "6180 Marketing" or bare codes like "6330".
function cleanCat(lbl) {
  return /^\d+(\.\d+)?$/.test(String(lbl).trim()) ? 'Account ' + lbl : String(lbl).replace(/^\d+(\.\w+)?\s+/, '');
}
function genId() {
  return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
}

// ---------- toast ----------
function ensureToastHost() {
  let h = $('#toastHost');
  if (!h) { h = el('div', { id: 'toastHost', class: 'toast-host' }); document.body.appendChild(h); }
  return h;
}
function toast(msg, type) {
  const t = el('div', { class: 'toast toast-' + (type || 'info') }, msg);
  ensureToastHost().appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 400); }, 3200);
}

// ---------- session ----------
// Secrets (PAT, API key) and kdfInput (contains the password) live ONLY in the
// in-memory State.session. Web storage gets just the username so the login
// form can prefill after a reload — a reload always re-prompts for the password.
function saveSession(s) { try { sessionStorage.setItem(SESSION_KEY, JSON.stringify({ username: s.username })); } catch {} }
function loadSession() { try { return JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null'); } catch { return null; } }
function clearSession() { try { sessionStorage.removeItem(SESSION_KEY); } catch {} }

// ---------- vault ----------
async function loadVault() {
  const r = await fetch('vault.json', { cache: 'no-store' });
  if (!r.ok) throw new Error('vault.json missing — run setup.html first.');
  return r.json();
}
async function tryDecrypt(username, password) {
  const vault = await loadVault();
  const u = vault.users && vault.users[username];
  if (!u) return null;
  const kdfInput = username + ':' + password;
  const secrets = await AsaCrypto.decryptJSON(
    { salt: u.salt, iv: u.iv, ct: u.ct, iter: u.iter },
    kdfInput
  );
  if (!secrets) return null;
  return {
    username,
    name: u.name || username,
    role: u.role || 'owner',
    owner: vault.owner,
    repo: vault.repo,
    secrets,
    kdfInput,   // in-memory only — saveSession() never persists it (it contains the password)
  };
}

// Detect the {salt, iv, ct, iter} encrypted-file shape used for data.json etc.
function isPwBlob(o) {
  return o && typeof o === 'object' && o.salt && o.iv && o.ct && o.iter && Object.keys(o).length === 4;
}

// ---------- GitHub API ----------
async function gh(path, opts = {}) {
  const s = State.session;
  if (!s) throw new Error('No session');
  const url = 'https://api.github.com/repos/' + s.owner + '/' + s.repo + path;
  const r = await fetch(url, {
    ...opts,
    headers: {
      'Authorization': 'Bearer ' + s.secrets.githubToken,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(opts.headers || {}),
    },
  });
  if (!r.ok) {
    const text = await r.text();
    throw new Error('GH ' + r.status + ': ' + text.slice(0, 200));
  }
  if (r.status === 204) return null;
  return r.json();
}
async function ghGetFile(path) {
  try {
    const j = await gh('/contents/' + encodeURI(path) + '?ref=main');
    return { sha: j.sha, content: atob(j.content.replace(/\n/g, '')) };
  } catch (e) {
    if (String(e).includes('404')) return null;
    throw e;
  }
}
async function ghListDir(path) {
  try {
    const j = await gh('/contents/' + encodeURI(path) + '?ref=main');
    if (!Array.isArray(j)) return [];
    return j;
  } catch (e) {
    if (String(e).includes('404')) return [];
    throw e;
  }
}
async function ghPutFile(path, base64Content, message, sha) {
  const body = { message, content: base64Content, branch: 'main' };
  if (sha) body.sha = sha;
  return gh('/contents/' + encodeURI(path), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}
async function ghPutText(path, text, message) {
  let existing = await ghGetFile(path).catch(() => null);
  const b64 = btoa(unescape(encodeURIComponent(text)));
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await ghPutFile(path, b64, message, existing ? existing.sha : undefined);
    } catch (e) {
      const msg = String(e);
      if (msg.includes('422') || msg.includes('409')) {
        await new Promise((r) => setTimeout(r, 400 + attempt * 400));
        // refetch handles both races: file created since our null read, and
        // file changed since our stale sha
        existing = await ghGetFile(path).catch(() => existing);
        continue;
      }
      throw e;
    }
  }
  throw new Error('ghPutText: gave up after retries');
}
// Binary/base64 PUT with the same conflict resilience ghPutText has. Bulk
// uploads commit many files to `main` in quick succession; GitHub's Contents
// API then returns 409 (branch head moved since our PUT was built), 422 (path
// already exists, a sha is required), 429, secondary-rate-limit 403s, or 5xx.
// Retry those with backoff instead of failing the whole batch on the first one.
async function ghPutBlob(path, base64Content, message) {
  let sha; // undefined => create; set if we discover the path already exists
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      return await ghPutFile(path, base64Content, message, sha);
    } catch (e) {
      const msg = String(e);
      const code = +((/GH (\d{3})/.exec(msg) || [])[1] || 0);
      const rateLimited = code === 403 && /rate limit|secondary|abuse/i.test(msg);
      const retriable = code === 409 || code === 422 || code === 429 || code >= 500 || rateLimited;
      if (!retriable || attempt === 5) throw e;
      // 422 generally means the path already exists and a sha is required —
      // fetch it and retry as an update so the file still lands.
      if (code === 422) {
        const existing = await ghGetFile(path).catch(() => null);
        if (existing) sha = existing.sha;
      }
      await new Promise((r) => setTimeout(r, 500 + attempt * 700));
    }
  }
  throw new Error('ghPutBlob: gave up after retries');
}
async function ghDelete(path, sha, message) {
  return gh('/contents/' + encodeURI(path), {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, sha, branch: 'main' }),
  });
}

// ---------- app state ----------
const State = {
  session: null,
  view: 'overview',
  data: null,
  uploads: null,
  comments: null,
};

// ============================================================
// LOGIN
// ============================================================
async function handleLogin(e) {
  if (e) e.preventDefault();
  const form = $('#loginForm');
  const username = form.username.value.trim();
  const password = form.password.value;
  hideLoginError();

  // DEMO MODE — accept any username/password and sign in as the firm owner.
  // No vault, no decryption: the portal reads the bundled plaintext data.json.
  const s = {
    username: username || 'demo',
    name: 'Demo Owner',
    role: 'owner',
    owner: 'demo',
    repo: 'demoportallaw',
    secrets: { githubToken: '' },
    kdfInput: null,
  };
  State.session = s;
  saveSession(s);
  await bootApp();
}
function showLoginError(msg) {
  const e = $('#loginError');
  e.hidden = false; e.textContent = msg;
}
function hideLoginError() { $('#loginError').hidden = true; }

// ============================================================
// APP BOOT
// ============================================================
async function bootApp() {
  $('#loginView').hidden = true;
  $('#appView').hidden = false;

  const s = State.session;
  $('#userName').textContent = s.name;
  $('#userRole').textContent = s.role;
  $('#userAvatar').textContent = s.name.split(/\s+/).map((w) => w[0]).join('').slice(0, 2).toUpperCase();

  buildSidebar();
  await navigate('overview');
}

function buildSidebar() {
  const nav = $('#sidebarNav');
  nav.innerHTML = '';
  const items = [
    { view: 'overview',     label: 'Overview' },
    null,
    { view: 'ar',           label: 'A/R · Aging Summary' },
    { view: 'invoices',     label: 'Invoices' },
    { view: 'collections',  label: 'A/R · 90+ Days · Top 25' },
    { view: 'originators',  label: 'A/R · by Originating Attorney' },
    null,
    { view: 'pl',           label: 'Profit & Loss' },
    { view: 'distributions',label: 'Partner Distributions' },
    { view: 'cash',         label: 'Cash & Balance Sheet' },
    { view: 'ap',           label: 'Accounts Payable' },
    null,
    { view: 'wip',          label: 'Work in Progress' },
    { view: 'clients',      label: 'Top Clients' },
    null,
    { view: 'billscorner',  label: "Bill's Corner" },
    null,
    { view: 'upload',       label: 'Upload Reports' },
    { view: 'documents',    label: 'Documents' },
    { view: 'comments',     label: 'Comments' },
    { view: 'insights',     label: 'AI Insights' },
    { view: 'settings',     label: 'Settings' },
  ];
  items.forEach((it) => {
    if (it === null) { nav.appendChild(el('div', { class: 'sidebar-divider' })); return; }
    const b = el('button', { 'data-view': it.view, onclick: () => navigate(it.view) }, it.label);
    nav.appendChild(b);
  });
  $('#logoutBtn').onclick = () => {
    clearSession();
    State.session = null;
    location.reload();
  };
}

async function navigate(view, opts) {
  State.view = view;
  State.navOpts = opts || null;   // optional drill-down context (e.g. {q:'Client'} for invoices)
  $$('#sidebarNav button').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  const root = $('#content');
  root.innerHTML = '<div class="loading">Loading…</div>';
  try {
    if (view === 'overview')         await renderOverview(root);
    else if (view === 'brief')       await renderBrief(root);
    else if (view === 'ar')          await renderAR(root);
    else if (view === 'invoices')    await renderInvoices(root);
    else if (view === 'collections') await renderCollectibles(root);
    else if (view === 'originators') await renderOriginators(root);
    else if (view === 'pl')          await renderPL(root);
    else if (view === 'distributions') await renderDistributions(root);
    else if (view === 'cash')        await renderCash(root);
    else if (view === 'ap')          await renderAP(root);
    else if (view === 'wip')         await renderWIP(root);
    else if (view === 'clients')     await renderTopClients(root);
    else if (view === 'billscorner') await renderBillsCorner(root);
    else if (view === 'upload')      await renderUpload(root);
    else if (view === 'documents')   await renderDocuments(root);
    else if (view === 'comments')    await renderComments(root);
    else if (view === 'insights')    await renderInsights(root);
    else if (view === 'settings')    await renderSettings(root);
    else root.innerHTML = '<p>Unknown view.</p>';
  } catch (e) {
    root.innerHTML = '';
    root.appendChild(el('div', { class: 'error-card' },
      el('h3', null, 'Something went wrong'),
      el('p', null, String(e.message || e))
    ));
  }
}

// ============================================================
// DATA loader
// ============================================================
async function loadData(force) {
  if (!force && State.data) return State.data;
  try {
    const r = await fetch('data.json?_=' + Date.now(), { cache: 'no-store' });
    if (!r.ok) throw new Error('data.json fetch failed: ' + r.status);
    const raw = await r.json();
    if (isPwBlob(raw)) {
      const kdf = State.session && State.session.kdfInput;
      if (!kdf) throw new Error('No password in session — sign in again');
      State.data = await AsaCrypto.decryptJSON(raw, kdf);
      if (State.data === null) throw new Error('Decryption failed — wrong password');
    } else {
      State.data = raw;
    }
  } catch (e) {
    console.warn('loadData:', e);
    State.data = null;
  }
  return State.data;
}

// ============================================================
// VIEWS
// ============================================================
function pageHead(eyebrow, title, sub) {
  return el('div', { class: 'page-head' },
    el('div', null,
      el('p', { class: 'eyebrow' }, eyebrow),
      el('h1', null, title),
      sub ? el('p', null, sub) : null,
    )
  );
}
function kpiCard(label, value, sublabel, tone, navTo) {
  const props = { class: 'kpi-card ' + (tone || '') + (navTo ? ' clickable' : '') };
  if (navTo) {
    props.onclick = () => navigate(navTo);
    props.title = 'View details →';
  }
  return el('div', props,
    el('div', { class: 'kpi-label' }, label),
    el('div', { class: 'kpi-value' }, value),
    sublabel ? el('div', { class: 'kpi-sublabel' }, sublabel) : null,
    navTo ? el('div', { class: 'kpi-drill' }, 'View details →') : null,
  );
}

// ---- Interactive charts (vanilla inline SVG + hover tooltip + click-through) ----
const SVGNS = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs, ...kids) {
  const e = document.createElementNS(SVGNS, tag);
  for (const k in (attrs || {})) e.setAttribute(k, attrs[k]);
  for (const kid of kids) if (kid != null) e.appendChild(typeof kid === 'string' ? document.createTextNode(kid) : kid);
  return e;
}
function fmtCompact(n) {
  const a = Math.abs(Number(n) || 0), sign = n < 0 ? '-' : '';
  if (a >= 1e6) return sign + '$' + (a / 1e6).toFixed(a >= 1e7 ? 0 : 1) + 'M';
  if (a >= 1e3) return sign + '$' + Math.round(a / 1e3) + 'K';
  return sign + '$' + Math.round(a);
}
// bars: [{ label, value, color, note, navTo }]
function barChartPanel(title, subtitle, bars, footNote) {
  const W = 660, H = 280, pad = { t: 22, r: 18, b: 52, l: 16 };
  const iW = W - pad.l - pad.r, iH = H - pad.t - pad.b;
  const max = Math.max(0, ...bars.map((b) => b.value));
  const min = Math.min(0, ...bars.map((b) => b.value));
  const range = (max - min) || 1;
  const y = (v) => pad.t + iH * (1 - (v - min) / range);
  const zeroY = y(0);
  const slot = iW / bars.length;
  const bw = Math.min(slot * 0.6, 92);
  const svg = svgEl('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'bar-chart', preserveAspectRatio: 'xMidYMid meet', role: 'img' });
  svg.appendChild(svgEl('line', { x1: pad.l, x2: W - pad.r, y1: zeroY, y2: zeroY, class: 'bar-axis' }));
  const tip = el('div', { class: 'chart-tip' });
  bars.forEach((b, i) => {
    const cx = pad.l + slot * (i + 0.5);
    const top = b.value >= 0 ? y(b.value) : zeroY;
    const hgt = Math.max(2, Math.abs(zeroY - y(b.value)));
    const rect = svgEl('rect', { x: cx - bw / 2, y: top, width: bw, height: hgt, rx: 5,
      fill: b.color || '#14263d', class: 'bar' + (b.navTo ? ' bar-click' : '') });
    const show = (e) => {
      const r = svg.getBoundingClientRect();
      tip.style.left = (e.clientX - r.left) + 'px';
      tip.style.top = (y(b.value) / H * r.height - 8) + 'px';
      tip.innerHTML = '<strong>' + escapeHtml(b.label) + '</strong>' + fmtMoneyFull(b.value) + (b.note ? '<span>' + escapeHtml(b.note) + '</span>' : '');
      tip.classList.add('show');
    };
    rect.addEventListener('mouseenter', show);
    rect.addEventListener('mousemove', show);
    rect.addEventListener('mouseleave', () => tip.classList.remove('show'));
    if (b.navTo) rect.addEventListener('click', () => navigate(b.navTo));
    svg.appendChild(rect);
    svg.appendChild(svgEl('text', { x: cx, y: (b.value >= 0 ? top - 7 : top + hgt + 15), 'text-anchor': 'middle', class: 'bar-val' }, fmtCompact(b.value)));
    svg.appendChild(svgEl('text', { x: cx, y: H - pad.b + 20, 'text-anchor': 'middle', class: 'bar-lbl' }, b.label));
  });
  return el('div', { class: 'panel chart-panel' },
    el('div', { class: 'panel-head' }, el('h3', null, title),
      subtitle ? el('span', { class: 'muted', style: { fontSize: '12px' } }, subtitle) : null),
    el('div', { class: 'chart-wrap' }, svg, tip),
    footNote ? el('p', { class: 'muted chart-foot' }, footNote) : null,
  );
}

// "$BCL" stock ticker — weekly pre-draw income via Chart.js, mirroring the $ASA chart in
// the All Sportz Apparel admin. Returns a wrapper; the Chart inits next frame once the
// canvas is in the DOM. pd = data.preDrawWeekly.
let _dnzChart = null;
function appendDnzStock(root, pd) {
  const pts = (pd && pd.points) || [];
  if (pts.length < 2) return;
  const wrap = el('div');
  const wkLabel = (iso) => new Date(iso + 'T00:00:00').toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  const labels = pts.map((p) => p.label || wkLabel(p.w));
  const data = pts.map((p) => Math.round(p.value));
  const avg = Math.round(data.reduce((a, b) => a + b, 0) / data.length);
  const latest = data[data.length - 1] || 0;
  const prev = data.length > 1 ? data[data.length - 2] : latest;
  const chg = prev ? ((latest - prev) / prev * 100) : 0;
  const up = latest >= prev;
  const hi = Math.max(...data), lo = Math.min(...data);
  const hiWk = pts[data.indexOf(hi)], loWk = pts[data.indexOf(lo)];
  const total = data.reduce((a, b) => a + b, 0);
  const first = data[0] || 0;
  const periodChg = first ? ((latest - first) / first * 100) : 0;
  const lineColor = latest >= first ? '#16a34a' : '#dc2626';
  const money = (n) => '$' + Math.round(n).toLocaleString('en-US');
  const chip = (v) => `<span style="color:${v >= 0 ? '#22c55e' : '#f87171'};font-weight:700">${v >= 0 ? '▲' : '▼'} ${Math.abs(v).toFixed(1)}%</span>`;
  wrap.innerHTML = `
    <div class="panel" style="background:linear-gradient(135deg,#0b1020 0%,#14223b 100%);color:#e8eef6;padding:22px 26px;border:1px solid #1e2a44">
      <div style="display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:14px">
        <div>
          <div style="display:flex;align-items:center;gap:10px">
            <span style="font-family:'Bebas Neue',Impact,sans-serif;font-size:32px;letter-spacing:2px;color:#fff">$BCL</span>
            <span style="display:inline-flex;align-items:center;gap:5px;font-size:11px;color:#86efac"><span style="width:7px;height:7px;border-radius:50%;background:#22c55e;display:inline-block;animation:asapulse 1.6s infinite"></span>WEEKLY CLOSE</span>
          </div>
          <div style="font-size:13px;color:#8595ad;margin-top:2px">Brightwell Carter &amp; Lane · pre-draw income / wk</div>
        </div>
        <div style="text-align:right">
          <div style="font-size:36px;font-weight:800;font-variant-numeric:tabular-nums;color:#fff">${money(latest)}</div>
          <div style="font-size:13px">${chip(chg)} <span style="color:#8595ad">wk / wk</span></div>
        </div>
      </div>
      <div style="height:300px;margin-top:16px"><canvas id="dnzStockChart"></canvas></div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px;margin-top:16px;font-variant-numeric:tabular-nums">
        ${[['Latest close', money(latest), wkLabel(pts[pts.length - 1].w)],
           ['Avg / wk', money(avg), 'dashed line'],
           ['Period high', money(hi), wkLabel(hiWk.w)],
           ['Period low', money(lo), wkLabel(loWk.w)],
           ['Since start', (periodChg >= 0 ? '+' : '') + periodChg.toFixed(1) + '%', wkLabel(pts[0].w)],
           ['YTD total', money(pd.ytdTotal || total), pts.length + ' wks']
          ].map(([l, v, s]) => `<div style="background:rgba(255,255,255,.04);border:1px solid #1e2a44;border-radius:10px;padding:10px 12px">
            <div style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:#8595ad">${l}</div>
            <div style="font-size:18px;font-weight:700;color:#e8eef6">${v}</div>
            <div style="font-size:10px;color:#6b7a93">${s}</div></div>`).join('')}
      </div>
    </div>
    <style>@keyframes asapulse{0%{box-shadow:0 0 0 0 rgba(34,197,94,.6)}70%{box-shadow:0 0 0 7px rgba(34,197,94,0)}100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}}</style>
    <p style="font-size:11px;color:var(--ink-dim);margin-top:8px">Weekly pre-draw income (operating profit before partner draws), scaled so the year sums to the actual YTD figure. Hover the line for any week. Dashed line = ${money(avg)}/wk average.</p>
  `;
  root.appendChild(wrap);
  const cv = wrap.querySelector('#dnzStockChart');
  if (cv && window.Chart) {
    if (_dnzChart) { try { _dnzChart.destroy(); } catch (e) {} _dnzChart = null; }
    const ctx = cv.getContext('2d');
    const grad = ctx.createLinearGradient(0, 0, 0, 300);
    grad.addColorStop(0, up ? 'rgba(34,197,94,.35)' : 'rgba(220,38,38,.32)');
    grad.addColorStop(1, 'rgba(20,34,59,0)');
    _dnzChart = new Chart(cv, {
      type: 'line',
      data: { labels, datasets: [
        { label: 'Pre-draw income', data, borderColor: lineColor, backgroundColor: grad, fill: true, tension: .25, borderWidth: 2, pointRadius: 0, pointHoverRadius: 5, pointHoverBackgroundColor: '#fff', pointHoverBorderColor: lineColor },
        { label: `Avg ${money(avg)}/wk`, data: data.map(() => avg), borderColor: '#9aa6b1', borderDash: [6, 6], borderWidth: 1.5, fill: false, pointRadius: 0, pointHoverRadius: 0 },
      ] },
      options: {
        responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0b1020', borderColor: '#1e2a44', borderWidth: 1, titleColor: '#fff', bodyColor: '#cfe0f5', padding: 10,
            callbacks: {
              title: (items) => { const w = pts[items[0].dataIndex]; return w ? 'Week of ' + new Date(w.w + 'T00:00:00').toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : items[0].label; },
              label: (item) => item.datasetIndex === 0 ? `  ${money(item.parsed.y)} pre-draw income` : `  avg ${money(avg)}`,
            },
          },
        },
        scales: {
          y: { grid: { color: 'rgba(255,255,255,.06)' }, ticks: { color: '#8595ad', font: { size: 10 }, callback: (v) => '$' + (v / 1000).toFixed(0) + 'k' } },
          x: { grid: { display: false }, ticks: { color: '#8595ad', font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 12 } },
        },
      },
    });
  }
  return wrap;
}

// Horizontal stacked-bar chart of outstanding A/R by originating attorney (Chart.js),
// segmented by aging bucket. Appended then initialised synchronously.
let _origChart = null;
function appendOriginatorsChart(root, oa) {
  const atts = (oa && oa.attorneys) || [];
  if (atts.length < 2) return;
  const top = atts.slice().sort((a, b) => (b.total || 0) - (a.total || 0)).slice(0, 15);
  const labels = top.map((a) => a.attorney);
  const H = Math.max(300, top.length * 30 + 80);
  const money = (n) => '$' + Math.round(n || 0).toLocaleString('en-US');
  const wrap = el('div', { class: 'panel' });
  wrap.innerHTML =
    '<div class="panel-head"><h3>Outstanding A/R by originating attorney</h3>' +
    '<span class="muted" style="font-size:12px">Top ' + top.length + ' by total · stacked by aging bucket · as of ' + fmtDate(oa.asOf) + '</span></div>' +
    '<div style="height:' + H + 'px"><canvas id="origArChart"></canvas></div>';
  root.appendChild(wrap);
  const cv = wrap.querySelector('#origArChart');
  if (!cv || !window.Chart) return;
  if (_origChart) { try { _origChart.destroy(); } catch (e) {} _origChart = null; }
  const buckets = [
    { label: '1–30 days', key: 'b30', color: '#2bb673' },
    { label: '31–60 days', key: 'b60', color: '#cdab6b' },
    { label: '61–90 days', key: 'b90', color: '#d98c2b' },
    { label: '90+ days', key: 'b91', color: '#8a1d24' },
  ];
  _origChart = new Chart(cv, {
    type: 'bar',
    data: { labels, datasets: buckets.map((b) => ({ label: b.label, data: top.map((a) => Math.round(a[b.key] || 0)), backgroundColor: b.color, borderWidth: 0, borderRadius: 2 })) },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { position: 'top', labels: { boxWidth: 12, font: { size: 11 } } },
        tooltip: {
          callbacks: {
            label: (it) => '  ' + it.dataset.label + ': ' + money(it.parsed.x),
            footer: (items) => 'Total: ' + money(items.reduce((s, i) => s + (i.parsed.x || 0), 0)),
          },
        },
      },
      scales: {
        x: { stacked: true, ticks: { callback: (v) => '$' + (v / 1000).toFixed(0) + 'k', font: { size: 10 }, color: '#5a6b85' }, grid: { color: 'rgba(13,27,42,.06)' } },
        y: { stacked: true, ticks: { font: { size: 11 }, color: '#324158' }, grid: { display: false } },
      },
    },
  });
}
function emptyState(msg) {
  return el('div', { class: 'empty-state' },
    el('div', { class: 'empty-state-icon' }, '○'),
    el('p', null, msg),
    el('p', { class: 'empty-state-sub' }, 'Drop a file in the Upload tab to get started.'),
  );
}

// NOTE: the server-generated-SVG chart pipeline (chartSlot/chartGrid/chartFull
// and billing/charts/*.svg) was removed 2026-06-10: no view ever embedded the
// files, and the stored charts had gone stale/incorrect vs data.json. All
// visible charts are built client-side from decrypted data (barChartPanel,
// appendDnzStock, Chart.js panels), which can't drift from the data they show.

// ============================================================
// SHARED HELPERS for the new owner-focused views
// ============================================================
function execHero({ eyebrow, title, big, sub, chips }) {
  return el('div', { class: 'hero' },
    el('div', { class: 'hero-l' },
      el('div', { class: 'eyebrow' }, eyebrow || ''),
      el('h1', { class: 'hero-title' }, title || ''),
      el('div', { class: 'hero-number' }, big || ''),
      el('div', { class: 'hero-sub' },
        ...((chips || []).map((c) => el('span', { class: 'hero-chip' + (c.tone ? ' ' + c.tone : '') }, c.text))),
        (chips && chips.length) ? ' · ' : '',
        sub || '',
      ),
    ),
  );
}

function executiveKPIs(data) {
  const h = (data && data.headline) || {};
  // Net income before partner draws = Net Operating Income (income − operating
  // expenses, BEFORE the partner-comp "Other Expenses" section). Reads straight
  // from the P&L so it auto-updates each loop; falls back to net income + the
  // partner-draw "other expenses" if NOI isn't present.
  const pl = data.pl || {};
  const beforeDraws = (pl.netOperatingIncome != null)
    ? pl.netOperatingIncome
    : ((h.ytdNetIncome || 0) + (pl.otherExpenses || 0));
  const grid = el('div', { class: 'kpi-grid kpi-grid-5' });
  grid.appendChild(kpiCard('Cash on hand',  fmtMoneyFull(h.cashOnHand || 0),
    'across all bank accounts', (h.cashOnHand || 0) < 500000 ? 'warn' : '', 'cash'));
  grid.appendChild(kpiCard('Total A/R',     fmtMoneyFull(h.totalAR || 0),
    fmtPct((data.ar && data.ar.over90Pct) || 0) + ' over 90 days',
    ((data.ar && data.ar.over90Pct) || 0) >= 30 ? 'danger' : 'warn', 'ar'));
  grid.appendChild(kpiCard('YTD revenue',   fmtMoneyFull(h.ytdRevenue || 0),
    'cash basis · Jan 1 – ' + fmtDate(data.asOf), '', 'pl'));
  grid.appendChild(kpiCard('Net income (pre-draws)', fmtMoneyFull(beforeDraws),
    'operating profit before partner draws', beforeDraws < 0 ? 'danger' : 'ok', 'pl'));
  grid.appendChild(kpiCard('YTD net income',fmtMoneyFull(h.ytdNetIncome || 0),
    'after partner draws',
    (h.ytdNetIncome || 0) < 0 ? 'danger' : '', 'pl'));
  return grid;
}

// Table builder helper for clean owner-style tables.
// onRowClick(row) — optional; makes rows clickable (drill-down).
function ownerTable({ title, columns, rows, foot, onRowClick }) {
  const thead = el('thead', null,
    el('tr', null, ...columns.map((c) =>
      el('th', { class: c.num ? 'num' : '' }, c.label)))
  );
  const tbody = el('tbody', null, ...rows.map((r) => {
    const tr = el('tr', onRowClick ? { class: 'row-clickable', onclick: () => onRowClick(r), title: 'View invoices →' } : null,
      ...columns.map((c) => {
        const v = c.value(r);
        return el('td', { class: (c.num ? 'num ' : '') + (c.bold ? 'bold ' : '') + (c.tone ? c.tone : '') },
          v == null ? '—' : v);
      }));
    return tr;
  }));
  const tbl = el('table', { class: 'data-table' }, thead, tbody);
  const panel = el('div', { class: 'panel' },
    title ? el('h3', null, title) : null,
    tbl);
  if (foot) panel.appendChild(el('p', { class: 'muted', style: { marginTop: '12px', fontSize: '12px' } }, foot));
  return panel;
}

// ============================================================
// OVERVIEW — executive summary for the firm's owner
// ============================================================
async function renderOverview(root) {
  const data = await loadData();
  root.innerHTML = '';

  if (!data || !data.headline) {
    root.appendChild(pageHead('Owner Dashboard', 'Overview', 'No data yet'));
    root.appendChild(emptyState('No billing data crunched yet. Upload reports to begin.'));
    return;
  }
  const h = data.headline;
  const ar = data.ar || {};
  const pl = data.pl || {};
  const cf = data.cashFlow || {};
  const wip = data.wip || {};
  const bs = data.balanceSheet || {};

  // ---- HERO: cash position front and center ----
  root.appendChild(execHero({
    eyebrow: 'Brightwell Carter & Lane LLP · Owner Dashboard · as of ' + fmtDate(data.asOf),
    title: 'Cash on hand',
    big: fmtMoneyFull(h.cashOnHand || 0),
    sub: 'Net change YTD ' + (cf.netChange < 0 ? '−' : '+') + fmtMoneyFull(Math.abs(cf.netChange || 0)) + ' · refreshed ' + fmtRelative(data.lastUpdated),
    chips: [
      { text: 'A/R ' + fmtMoneyFull(h.totalAR || 0), tone: 'warn' },
      { text: 'Revenue ' + fmtMoneyFull(h.ytdRevenue || 0) },
      { text: (h.ytdNetIncome < 0 ? '▼ ' : '▲ ') + fmtMoneyFull(Math.abs(h.ytdNetIncome || 0)) + ' net', tone: h.ytdNetIncome < 0 ? 'danger' : '' },
    ],
  }));

  // ---- "OVERVIEW BRIEF" CTA → printable, colorful one-page financial summary ----
  root.appendChild(el('div', { class: 'brief-cta no-print' },
    el('button', { class: 'btn btn-primary', onclick: () => navigate('brief') },
      '📄  Overview Brief'),
    el('span', { class: 'muted', style: { fontSize: '12px' } },
      'A colorful, print-ready summary of the firm\'s finances — including A/R by attorney — for printing or saving as a PDF.'),
  ));

  // ---- EXECUTIVE KPIs ----
  root.appendChild(executiveKPIs(data));

  // ---- "$BCL" stock ticker (Chart.js, mirrors the $ASA chart): weekly pre-draw income ----
  if (data.preDrawWeekly && data.preDrawWeekly.points && data.preDrawWeekly.points.length > 1) {
    appendDnzStock(root, data.preDrawWeekly);
  }

  // ---- INTERACTIVE YTD CHARTS (hover for exact $, click a bar to drill in) ----
  const NAVY = '#14263d', GREEN = '#2bb673', GOLD = '#b08a3a', GOLD2 = '#cdab6b', RED = '#8a1d24', SLATE = '#5a6b85';
  const bc = (ar.bucketCounts) || {};
  const cnt = (n) => n ? ' · ' + fmtNum(n) + ' invoices' : '';
  const charts = el('div', { class: 'chart-grid' });
  charts.appendChild(barChartPanel(
    'YTD profitability', 'Cash basis · Jan 1 – ' + fmtDate(pl.periodEnd),
    [
      { label: 'Revenue',        value: pl.totalIncome || 0,        color: NAVY,  navTo: 'pl' },
      { label: 'Pre-draw income',value: pl.netOperatingIncome || 0, color: GREEN, navTo: 'pl', note: 'operating profit before partner draws' },
      { label: 'Partner draws',  value: -Math.abs(pl.otherExpenses || 0), color: GOLD, navTo: 'distributions' },
      { label: 'Net income',     value: pl.netIncome || 0,          color: (pl.netIncome || 0) < 0 ? RED : GREEN, navTo: 'pl', note: 'after partner draws' },
    ],
    'Hover any bar for the exact figure · click to drill into the detail.'));
  charts.appendChild(barChartPanel(
    'A/R aging', 'Total A/R ' + fmtMoneyFull(ar.total || 0) + ' · as of ' + fmtDate(ar.asOf),
    [
      { label: 'Current', value: (ar.buckets && ar.buckets['current']) || 0, color: GREEN,  navTo: 'invoices', note: cnt(bc['current']).slice(3) },
      { label: '1–30',    value: (ar.buckets && ar.buckets['1-30']) || 0,    color: '#7fbf8f', navTo: 'invoices', note: cnt(bc['1-30']).slice(3) },
      { label: '31–60',   value: (ar.buckets && ar.buckets['31-60']) || 0,   color: GOLD2,  navTo: 'invoices', note: cnt(bc['31-60']).slice(3) },
      { label: '61–90',   value: (ar.buckets && ar.buckets['61-90']) || 0,   color: GOLD,   navTo: 'invoices', note: cnt(bc['61-90']).slice(3) },
      { label: 'Over 90', value: (ar.buckets && ar.buckets['90+']) || 0,     color: RED,    navTo: 'collections', note: fmtNum(over90Count(ar)) + ' invoices' },
    ],
    fmtPct(ar.over90Pct || 0) + ' of A/R is over 90 days · click a bucket for source invoices.'));
  charts.appendChild(barChartPanel(
    'YTD cash flow', 'Statement of cash flows · Jan 1 – ' + fmtDate(cf.periodEnd),
    [
      { label: 'Beginning', value: cf.cashBeginning || 0, color: SLATE },
      { label: 'Operating', value: cf.operating || 0,     color: (cf.operating || 0) < 0 ? RED : GREEN, navTo: 'cash' },
      { label: 'Investing', value: cf.investing || 0,     color: (cf.investing || 0) < 0 ? RED : GREEN, navTo: 'cash' },
      { label: 'Financing', value: cf.financing || 0,     color: (cf.financing || 0) < 0 ? RED : GREEN, navTo: 'cash' },
      { label: 'Ending',    value: cf.cashEnding || 0,    color: NAVY, navTo: 'cash' },
    ],
    'Net change ' + fmtMoneyFull(cf.netChange || 0) + ' YTD.'));
  root.appendChild(charts);

  // ---- A/R AGING SNAPSHOT (the most important number for a law firm owner) ----
  const arPanel = el('div', { class: 'panel' },
    el('div', { class: 'panel-head' },
      el('h3', null, 'Accounts receivable — aging'),
      el('span', { class: 'muted', style: { fontSize: '12px' } },
        fmtNum(ar.invoiceCount || 0) + ' open invoices · ' + fmtNum(ar.clientCount || 0) + ' clients · as of ' + fmtDate(ar.asOf)),
      el('a', { href: '#', class: 'panel-link', onclick: (e) => { e.preventDefault(); navigate('invoices'); } }, 'View source invoices →'),
    ),
    el('div', { class: 'aging-strip' },
      // 'Current' (not yet due) is shown only when nonzero so the blocks always sum to the total
      ((ar.buckets && ar.buckets['current']) || 0) > 0
        ? agingBlock('Current', ar.buckets['current'], ar.bucketCounts && ar.bucketCounts['current'], '', 'invoices') : null,
      agingBlock('1–30 days',    ar.buckets && ar.buckets['1-30'],  ar.bucketCounts && ar.bucketCounts['1-30'], '', 'invoices'),
      agingBlock('31–60 days',   ar.buckets && ar.buckets['31-60'], ar.bucketCounts && ar.bucketCounts['31-60'], 'warn', 'invoices'),
      agingBlock('61–90 days',   ar.buckets && ar.buckets['61-90'], ar.bucketCounts && ar.bucketCounts['61-90'], 'warn', 'invoices'),
      agingBlock('Over 90 days', ar.buckets && ar.buckets['90+'],   over90Count(ar),   'danger', 'collections'),
    ),
  );
  root.appendChild(arPanel);

  // ---- TOP 10 90+ COLLECTIBLES (chase list) ----
  if (ar.top90Plus && ar.top90Plus.length) {
    const c2o = data.clientToOriginator || {};
    root.appendChild(ownerTable({
      title: 'Largest collectibles over 90 days — the chase list',
      columns: [
        { label: 'Client', value: (r) => shortenClient(r.client) },
        { label: 'Originator', value: (r) => c2o[shortenClient(r.client)] || '—' },
        { label: '90+ balance',  num: true, bold: true, tone: 'warn', value: (r) => fmtMoneyFull(r.b91) },
        { label: 'Total open',   num: true, value: (r) => fmtMoneyFull(r.total) },
      ],
      rows: ar.top90Plus.slice(0, 10),
      onRowClick: (r) => navigate('invoices', { q: shortenClient(r.client) }),
      foot: 'These 10 accounts represent ' +
        fmtPct(100 * ar.top90Plus.slice(0, 10).reduce((s, c) => s + c.b91, 0) / ((ar.buckets && ar.buckets['90+']) || 1)) +
        ' of all 90+ A/R. Click any row to see that client\'s invoices.',
    }));
  }

  // ---- P&L + CASH FLOW snapshot side-by-side ----
  // Operating expenses row is expandable → reveals the category breakdown (comment: tiih).
  const plBody = el('tbody', null);
  plBody.appendChild(plLineRow('Total revenue', pl.totalIncome, true));
  const cats = (pl.topExpenseCategories || []).slice();
  const catSum = cats.reduce((s, c) => s + Math.abs(c.amount || 0), 0);
  const opexAbs = Math.abs(pl.operatingExpenses || 0);
  const subRows = [];
  cats.forEach((c) => subRows.push(el('tr', { class: 'pl-subrow', style: { display: 'none' } },
    el('td', null, el('span', { class: 'pl-subcat' }, cleanCat(c.label))),
    el('td', { class: 'num subtle' }, fmtMoneyFull(-Math.abs(c.amount || 0))))));
  if (opexAbs - catSum > 1000) subRows.push(el('tr', { class: 'pl-subrow', style: { display: 'none' } },
    el('td', null, el('span', { class: 'pl-subcat' }, 'All other operating expenses')),
    el('td', { class: 'num subtle' }, fmtMoneyFull(-(opexAbs - catSum)))));
  const opexRow = el('tr', { class: 'subtle pl-expandable', title: 'Click to expand' },
    el('td', null, el('span', { class: 'pl-caret' }, '▸ '), 'Operating expenses'),
    el('td', { class: 'num subtle' }, fmtMoneyFull(-opexAbs)));
  let expanded = false;
  opexRow.onclick = () => {
    expanded = !expanded;
    opexRow.querySelector('.pl-caret').textContent = expanded ? '▾ ' : '▸ ';
    subRows.forEach((r) => { r.style.display = expanded ? '' : 'none'; });
  };
  plBody.appendChild(opexRow);
  subRows.forEach((r) => plBody.appendChild(r));
  plBody.appendChild(plLineRow('Net operating income', pl.netOperatingIncome, true));
  plBody.appendChild(plLineRow('Partner distributions & other', -Math.abs(pl.otherExpenses), false, 'subtle'));
  plBody.appendChild(plLineRow('Net income', pl.netIncome, true, pl.netIncome < 0 ? 'warn' : ''));
  root.appendChild(el('div', { class: 'grid-2' },
    el('div', { class: 'panel' },
      el('div', { class: 'panel-head' }, el('h3', null, 'Profit & loss · YTD'),
        el('span', { class: 'muted', style: { fontSize: '11px' } }, 'click Operating expenses to expand')),
      el('table', { class: 'data-table compact-pl' }, plBody),
      el('p', { class: 'muted', style: { marginTop: '10px', fontSize: '12px' } },
        'Cash basis · Jan 1 – ' + fmtDate(pl.periodEnd) + ' · margin ' + fmtPct(pl.margin || 0)),
    ),
    el('div', { class: 'panel' },
      el('h3', null, 'Cash flow · YTD'),
      el('table', { class: 'data-table compact-pl' },
        el('tbody', null,
          plLineRow('Beginning cash',           cf.cashBeginning, false, 'subtle'),
          plLineRow('Operating activities',     cf.operating),
          plLineRow('Investing activities',     cf.investing),
          plLineRow('Financing activities',     cf.financing),
          plLineRow('Net change',               cf.netChange,     true, cf.netChange < 0 ? 'warn' : ''),
          plLineRow('Ending cash',              cf.cashEnding,    true),
        ),
      ),
      el('p', { class: 'muted', style: { marginTop: '10px', fontSize: '12px' } },
        'From the Statement of Cash Flows · Jan 1 – ' + fmtDate(cf.periodEnd)),
    ),
  ));

  // ---- WIP + AP snapshot side-by-side ----
  root.appendChild(el('div', { class: 'grid-2' },
    el('div', { class: 'panel' },
      el('h3', null, 'Work in progress · unbilled'),
      el('div', { class: 'wip-box' },
        el('div', { class: 'wip-big' }, fmtMoneyFull(wip.value || 0)),
        el('div', { class: 'wip-sub' },
          el('span', null, fmtNum(wip.hours || 0) + ' hours'),
          el('span', { class: 'sep' }, '·'),
          el('span', null, '$' + fmtNum(Math.round(wip.avgRate || 0)) + '/hr avg'),
        ),
      ),
      el('p', { class: 'muted', style: { marginTop: '10px', fontSize: '12px' } },
        'Unbilled time and costs, ' + fmtDate(wip.periodStart) + ' through ' + fmtDate(wip.periodEnd) + '.'),
    ),
    el('div', { class: 'panel' },
      el('h3', null, 'Accounts payable'),
      el('div', { class: 'wip-box' },
        el('div', { class: 'wip-big' }, fmtMoneyFull((data.ap && data.ap.total) || 0)),
        el('div', { class: 'wip-sub' },
          el('span', null, fmtMoney((data.ap && data.ap.buckets && data.ap.buckets['90+']) || 0) + ' over 90 days'),
        ),
      ),
      el('p', { class: 'muted', style: { marginTop: '10px', fontSize: '12px' } },
        'What the firm owes vendors as of ' + fmtDate((data.ap && data.ap.asOf) || data.asOf) + '.'),
    ),
  ));

  // ---- TOP CLIENTS YTD ----
  if (data.topClients && data.topClients.length) {
    root.appendChild(ownerTable({
      title: 'Top 10 clients by revenue · YTD',
      columns: [
        { label: 'Client', value: (r) => shortenClient(r.client) },
        { label: 'YTD revenue',  num: true, bold: true, value: (r) => fmtMoneyFull(r.income_ytd) },
        { label: '% of book',    num: true, value: (r) => fmtPct(100 * r.income_ytd / (pl.totalIncome || 1)) },
      ],
      rows: data.topClients.slice(0, 10),
    }));
  }
}

// ============================================================
// OVERVIEW BRIEF — a colorful, print-ready financial summary the
// owner can save as a PDF. Renders entirely from the already-
// decrypted in-browser data (loadData) — nothing is written to disk,
// so no plaintext financials ever leave the browser. Print CSS (see
// billing.css) hides the app chrome and lays this out as clean pages.
// ============================================================
async function renderBrief(root) {
  const data = await loadData();
  root.innerHTML = '';
  if (!data || !data.headline) {
    root.appendChild(pageHead('Overview Brief', 'Financial Overview Brief', 'No data yet'));
    root.appendChild(emptyState('No billing data crunched yet. Upload reports to begin.'));
    return;
  }
  const h = data.headline, ar = data.ar || {}, pl = data.pl || {}, cf = data.cashFlow || {},
        wip = data.wip || {}, ap = data.ap || {}, oa = data.originatingAttorneys || {},
        bs = data.balanceSheet || {};
  const C = { navy: '#14263d', navy2: '#22456b', green: '#2bb673', greenL: '#7fbf8f',
              gold: '#b08a3a', gold2: '#cdab6b', amber: '#d98c2b', red: '#8a1d24', slate: '#5a6b85' };

  // ---- derived "business health" metrics ----
  // These tell the real story the raw levels hide: net income is negative only
  // because partner distributions are an expense, while the firm's *operating*
  // margin (profit before those draws) is strongly positive. We annualize off
  // the YTD pace and surface collection speed + liquidity for the owner.
  const periodDays = daysBetween(data.periodStart || pl.periodStart, data.asOf || pl.periodEnd);
  const annualize  = periodDays ? 365 / periodDays : 0;
  const runRate    = (h.ytdRevenue || 0) * annualize;                                  // annualized revenue
  const opMargin   = pl.totalIncome ? 100 * (pl.netOperatingIncome || 0) / pl.totalIncome : 0;
  const dso        = (pl.totalIncome && periodDays) ? (h.totalAR || 0) / (pl.totalIncome / periodDays) : 0;
  const curRatio   = bs.currentLiab ? (bs.currentAssets || 0) / bs.currentLiab : 0;
  const earnedUncollected = (h.totalAR || 0) + (wip.value || 0);                       // future cash already earned
  const revPerAtt  = (oa.attorneys && oa.attorneys.length) ? (h.ytdRevenue || 0) / oa.attorneys.length : 0;

  // ---- toolbar (screen only — hidden on print) ----
  root.appendChild(el('div', { class: 'brief-toolbar no-print' },
    el('button', { class: 'btn btn-ghost btn-sm', onclick: () => navigate('overview') }, '← Back to dashboard'),
    el('div', { style: { flex: '1' } }),
    el('span', { class: 'muted', style: { fontSize: '12px', marginRight: '12px' } },
      'Tip: enable “Background graphics” in the print dialog for full color.'),
    el('button', { class: 'btn btn-primary', onclick: () => window.print() }, '🖨  Print / Save as PDF'),
  ));

  const page = el('div', { class: 'brief-page' });
  root.appendChild(el('div', { class: 'brief-doc' }, page));

  // ---- cover band ----
  page.appendChild(el('div', { class: 'brief-cover' },
    el('div', { class: 'brief-cover-top' },
      el('div', { class: 'brief-mark' }, 'BCL'),
      el('div', null,
        el('div', { class: 'brief-firm' }, 'Brightwell Carter & Lane LLP'),
        el('div', { class: 'brief-conf' }, 'Confidential · Owner Eyes Only'))),
    el('h1', { class: 'brief-title' }, 'Financial Overview Brief'),
    el('div', { class: 'brief-asof' },
      'As of ' + fmtDate(data.asOf) + ' · prepared ' + fmtDate(new Date().toISOString())),
  ));

  // ---- KPI grid ----
  const kpi = (label, val, sub, color) => el('div', { class: 'brief-kpi', style: { '--kc': color } },
    el('div', { class: 'brief-kpi-label' }, label),
    el('div', { class: 'brief-kpi-val' }, val),
    sub ? el('div', { class: 'brief-kpi-sub' }, sub) : null);
  page.appendChild(el('div', { class: 'brief-kpis' },
    kpi('Cash on hand', fmtMoneyFull(h.cashOnHand || 0), 'Net change YTD ' + fmtMoneyFull(cf.netChange || 0), C.navy),
    kpi('Accounts receivable', fmtMoneyFull(h.totalAR || 0),
      fmtNum(ar.invoiceCount || 0) + ' invoices · ' + fmtPct(ar.over90Pct || 0) + ' over 90d', C.amber),
    kpi('Revenue · YTD', fmtMoneyFull(h.ytdRevenue || 0), 'Operating margin ' + fmtPct(opMargin), C.green),
    kpi('Net income · YTD', fmtMoneyFull(h.ytdNetIncome || 0), 'After partner draws',
      (h.ytdNetIncome || 0) < 0 ? C.red : C.green),
    kpi('Work in progress', fmtMoneyFull(wip.value || 0), fmtNum(wip.hours || 0) + ' unbilled hours', C.slate),
    kpi('Accounts payable', fmtMoneyFull(ap.total || 0),
      fmtMoney((ap.buckets && ap.buckets['90+']) || 0) + ' over 90d', C.slate),
  ));

  const h2 = (t, sub) => el('div', { class: 'brief-h2' }, el('span', null, t), sub ? el('em', null, sub) : null);

  // ---- KEY RATIOS — business-health metrics that tell the real story ----
  page.appendChild(h2('Business health — key ratios', 'What the numbers say about the firm'));
  page.appendChild(el('div', { class: 'brief-kpis brief-kpis-ratios' },
    kpi('Operating margin', fmtPct(opMargin), 'Profit before partner draws', C.green),
    kpi('Profit before partner draws', fmtMoneyFull(pl.netOperatingIncome || 0), 'Net operating income · YTD', C.green),
    kpi('Revenue run-rate', fmtMoneyFull(runRate), 'Annualized from YTD pace', C.gold),
    kpi('Days to collect (DSO)', Math.round(dso) + ' days', 'Avg time to turn A/R into cash', C.amber),
    kpi('Current ratio', curRatio.toFixed(1) + '×', 'Liquidity · current assets vs. liabilities', C.navy2),
    kpi('Earned, not yet collected', fmtMoneyFull(earnedUncollected),
      'Open A/R + unbilled WIP' + (revPerAtt ? ' · ' + fmtMoneyFull(revPerAtt) + '/originating atty' : ''), C.slate),
  ));

  // ---- A/R aging: segmented bar + legend ----
  const buckets = [
    { label: 'Current', key: 'current', color: C.green },
    { label: '1–30',    key: '1-30',    color: C.greenL },
    { label: '31–60',   key: '31-60',   color: C.gold2 },
    { label: '61–90',   key: '61-90',   color: C.amber },
    { label: 'Over 90', key: '90+',     color: C.red },
  ];
  const arTotal = ar.total || buckets.reduce((s, b) => s + ((ar.buckets && ar.buckets[b.key]) || 0), 0) || 1;
  const seg = el('div', { class: 'brief-segbar' });
  buckets.forEach((b) => {
    const v = (ar.buckets && ar.buckets[b.key]) || 0;
    if (v <= 0) return;
    seg.appendChild(el('div', { class: 'brief-seg', style: { width: (100 * v / arTotal) + '%', background: b.color },
      title: b.label + ' ' + fmtMoneyFull(v) }));
  });
  const legend = el('div', { class: 'brief-legend' }, ...buckets.map((b) =>
    el('div', { class: 'brief-leg' },
      el('span', { class: 'brief-dot', style: { background: b.color } }),
      el('span', null, b.label),
      el('strong', null, fmtMoneyFull((ar.buckets && ar.buckets[b.key]) || 0)))));
  page.appendChild(h2('Accounts receivable — aging',
    fmtNum(ar.invoiceCount || 0) + ' invoices · ' + fmtNum(ar.clientCount || 0) + ' clients · as of ' + fmtDate(ar.asOf)));
  page.appendChild(el('div', { class: 'brief-card' }, seg, legend));

  // ---- A/R BY ORIGINATING ATTORNEY (the headline request): bars + full table ----
  if (oa.attorneys && oa.attorneys.length) {
    const atts = oa.attorneys.slice().sort((a, b) => b.total - a.total);
    const totalBook = oa.totalBook || atts.reduce((s, a) => s + a.total, 0) || 1;
    const maxT = atts[0].total || 1;
    page.appendChild(h2('A/R by originating attorney',
      'Total book ' + fmtMoneyFull(totalBook) + ' · ' + atts.length + ' attorneys · as of ' + fmtDate(oa.asOf)));
    const segColors = [['b30', C.greenL], ['b60', C.gold2], ['b90', C.amber], ['b91', C.red]];
    const bars = el('div', { class: 'brief-attbars' });
    atts.slice(0, 12).forEach((a) => {
      const track = el('div', { class: 'brief-attbar-track' });
      segColors.forEach(([k, col]) => {
        const v = a[k] || 0; if (v <= 0) return;
        track.appendChild(el('div', { class: 'brief-attbar-seg', style: { width: (100 * v / maxT) + '%', background: col },
          title: a.attorney + ' · ' + fmtMoneyFull(v) }));
      });
      bars.appendChild(el('div', { class: 'brief-attrow' },
        el('div', { class: 'brief-attname', title: a.attorney }, a.attorney),
        el('div', { class: 'brief-attbar' }, track),
        el('div', { class: 'brief-attval' }, fmtMoneyFull(a.total),
          el('span', { class: 'brief-attshare' }, fmtPct(100 * a.total / totalBook)))));
    });
    page.appendChild(el('div', { class: 'brief-card' }, bars,
      el('div', { class: 'brief-mini-legend' },
        el('span', null, el('span', { class: 'brief-dot', style: { background: C.greenL } }), '1–30'),
        el('span', null, el('span', { class: 'brief-dot', style: { background: C.gold2 } }), '31–60'),
        el('span', null, el('span', { class: 'brief-dot', style: { background: C.amber } }), '61–90'),
        el('span', null, el('span', { class: 'brief-dot', style: { background: C.red } }), '90+'))));
    if (atts.length > 12) {
      page.appendChild(el('table', { class: 'brief-table' },
        el('thead', null, el('tr', null,
          ...['Attorney', '1–30', '31–60', '61–90', '90+', 'Total', 'Share'].map((c, i) => el('th', { class: i ? 'num' : '' }, c)))),
        el('tbody', null, ...atts.map((a) => el('tr', null,
          el('td', null, a.attorney),
          el('td', { class: 'num' }, a.b30 ? fmtMoneyFull(a.b30) : '—'),
          el('td', { class: 'num' }, a.b60 ? fmtMoneyFull(a.b60) : '—'),
          el('td', { class: 'num' }, a.b90 ? fmtMoneyFull(a.b90) : '—'),
          el('td', { class: 'num', style: { color: C.red } }, a.b91 ? fmtMoneyFull(a.b91) : '—'),
          el('td', { class: 'num bold' }, fmtMoneyFull(a.total)),
          el('td', { class: 'num' }, fmtPct(100 * a.total / totalBook)))))));
    }
  }

  // ---- P&L + cash flow side by side ----
  const plRow = (l, v, bold, tone) => el('tr', { class: tone || '' },
    el('td', null, bold ? el('strong', null, l) : l),
    el('td', { class: 'num' + (bold ? ' bold' : '') }, fmtMoneyFull(v || 0)));
  page.appendChild(h2('Profit & loss · YTD',
    'Cash basis · through ' + fmtDate(pl.periodEnd) + ' · margin ' + fmtPct(pl.margin || 0)));
  page.appendChild(el('div', { class: 'brief-2col' },
    el('table', { class: 'brief-table' }, el('tbody', null,
      plRow('Total revenue', pl.totalIncome, true),
      plRow('Operating expenses', -Math.abs(pl.operatingExpenses || 0)),
      plRow('Net operating income', pl.netOperatingIncome, true),
      plRow('Partner distributions & other', -Math.abs(pl.otherExpenses || 0)),
      plRow('Net income', pl.netIncome, true, (pl.netIncome || 0) < 0 ? 'red' : ''))),
    el('table', { class: 'brief-table' }, el('tbody', null,
      plRow('Beginning cash', cf.cashBeginning),
      plRow('Operating activities', cf.operating),
      plRow('Investing activities', cf.investing),
      plRow('Financing activities', cf.financing),
      plRow('Net change', cf.netChange, true, (cf.netChange || 0) < 0 ? 'red' : ''),
      plRow('Ending cash', cf.cashEnding, true)))));

  // ---- largest expense categories (bars) ----
  if (pl.topExpenseCategories && pl.topExpenseCategories.length) {
    const cats = pl.topExpenseCategories.slice(0, 6);
    const maxC = Math.max(...cats.map((c) => Math.abs(c.amount || 0)), 1);
    page.appendChild(h2('Largest expense categories'));
    const cbars = el('div', { class: 'brief-attbars' });
    cats.forEach((c) => {
      const v = Math.abs(c.amount || 0);
      cbars.appendChild(el('div', { class: 'brief-attrow' },
        el('div', { class: 'brief-attname', title: cleanCat(c.label) }, cleanCat(c.label)),
        el('div', { class: 'brief-attbar' }, el('div', { class: 'brief-attbar-track' },
          el('div', { class: 'brief-attbar-seg', style: { width: (100 * v / maxC) + '%', background: C.navy2 } }))),
        el('div', { class: 'brief-attval' }, fmtMoneyFull(v))));
    });
    page.appendChild(el('div', { class: 'brief-card' }, cbars));
  }

  // ---- 90+ chase list ----
  if (ar.top90Plus && ar.top90Plus.length) {
    const c2o = data.clientToOriginator || {};
    page.appendChild(h2('Largest collectibles over 90 days', 'The chase list'));
    page.appendChild(el('table', { class: 'brief-table' },
      el('thead', null, el('tr', null,
        el('th', null, 'Client'), el('th', null, 'Originator'),
        el('th', { class: 'num' }, '90+ balance'), el('th', { class: 'num' }, 'Total open'))),
      el('tbody', null, ...ar.top90Plus.slice(0, 10).map((r) => el('tr', null,
        el('td', null, shortenClient(r.client)),
        el('td', null, c2o[shortenClient(r.client)] || '—'),
        el('td', { class: 'num', style: { color: C.red, fontWeight: '700' } }, fmtMoneyFull(r.b91)),
        el('td', { class: 'num' }, fmtMoneyFull(r.total)))))));
  }

  // ---- top clients by revenue (bars) ----
  if (data.topClients && data.topClients.length) {
    const tc = data.topClients.slice(0, 10);
    const maxR = Math.max(...tc.map((c) => c.income_ytd || 0), 1);
    page.appendChild(h2('Top clients by revenue · YTD'));
    const cbars = el('div', { class: 'brief-attbars' });
    tc.forEach((c) => {
      const v = c.income_ytd || 0;
      cbars.appendChild(el('div', { class: 'brief-attrow' },
        el('div', { class: 'brief-attname', title: shortenClient(c.client) }, shortenClient(c.client)),
        el('div', { class: 'brief-attbar' }, el('div', { class: 'brief-attbar-track' },
          el('div', { class: 'brief-attbar-seg', style: { width: (100 * v / maxR) + '%', background: C.green } }))),
        el('div', { class: 'brief-attval' }, fmtMoneyFull(v),
          el('span', { class: 'brief-attshare' }, fmtPct(100 * v / (pl.totalIncome || 1))))));
    });
    page.appendChild(el('div', { class: 'brief-card' }, cbars));
  }

  // ---- footer ----
  page.appendChild(el('div', { class: 'brief-foot' },
    el('span', null, 'Brightwell Carter & Lane LLP — Confidential financial summary, generated from the firm’s billing portal.'),
    el('span', null, 'As of ' + fmtDate(data.asOf))));
}

// The 90+ invoice count is stored under '90+' in some report batches and '91+' in
// others — read tolerantly so the chase-list/aging blocks never show "0 invoices".
function over90Count(ar) {
  const c = (ar && ar.bucketCounts) || {};
  return c['90+'] ?? c['91+'] ?? c['91 AND OVER'] ?? 0;
}
function agingBlock(label, amt, count, tone, navTo) {
  const props = { class: 'aging-block ' + (tone || '') + (navTo ? ' clickable' : '') };
  if (navTo) { props.onclick = () => navigate(navTo); props.title = 'View invoices →'; }
  return el('div', props,
    el('div', { class: 'aging-label' }, label),
    el('div', { class: 'aging-value' }, fmtMoneyFull(amt || 0)),
    el('div', { class: 'aging-count' }, count == null ? '' : fmtNum(count || 0) + ' invoices'),
  );
}

function plLineRow(label, amount, bold, tone) {
  return el('tr', { class: tone || '' },
    el('td', null, bold ? el('strong', null, label) : label),
    el('td', { class: 'num ' + (bold ? 'bold ' : '') + (tone || '') }, fmtMoneyFull(amount || 0)),
  );
}

function shortenClient(name) {
  if (!name) return '—';
  return String(name).replace(/\s*\(Clio\s*\d+\)\s*$/, '').replace(/\xa0/g, ' ').trim();
}

// ============================================================
// ACCOUNTS RECEIVABLE
// ============================================================
// Shared "Download Excel" button for the A/R views. Pulls the comprehensive,
// encrypted A/R workbook (Aging Summary · Largest Debtors · Over 90 · By
// Originating Attorney) generated at bills-corner/ar-sections.json — same
// decrypt-in-browser download path Bill's Corner uses. The loop regenerates
// that file from data.json on every run (see billing/AGENT.md).
function arExcelButton(label) {
  return el('div', { class: 'ar-export-bar', style: { margin: '10px 0 2px' } },
    el('button', {
      class: 'btn btn-primary btn-sm',
      onclick: () => downloadBillsSheet({
        file: 'bills-corner/ar-sections.json',
        filename: 'BCL A-R Sections.xlsx',
      }),
    }, '⬇ ' + (label || 'Download Excel (all A/R tabs)')));
}

async function renderAR(root) {
  const data = await loadData();
  root.innerHTML = '';
  if (!data || !data.ar) {
    root.appendChild(pageHead('Receivables', 'Accounts Receivable', 'No A/R report loaded'));
    root.appendChild(emptyState('Upload an A/R aging report to begin.'));
    return;
  }
  const ar = data.ar;
  const b = ar.buckets || {};
  const c = ar.bucketCounts || {};

  root.appendChild(execHero({
    eyebrow: 'Accounts Receivable · as of ' + fmtDate(ar.asOf),
    title: 'Total open A/R',
    big: fmtMoneyFull(ar.total || 0),
    sub: fmtNum(ar.invoiceCount || 0) + ' open invoices across ' + fmtNum(ar.clientCount || 0) + ' clients',
    chips: [
      { text: fmtPct(ar.over90Pct || 0) + ' over 90 days', tone: 'danger' },
      { text: fmtMoneyFull(b['90+'] || 0) + ' in 90+', tone: 'danger' },
    ],
  }));

  root.appendChild(arExcelButton());

  root.appendChild(el('div', { class: 'panel' },
    el('h3', null, 'Aging buckets'),
    el('div', { class: 'aging-strip' },
      (b['current'] || 0) > 0 ? agingBlock('Current', b['current'], c['current']) : null,
      agingBlock('1–30 days',    b['1-30'],  c['1-30']),
      agingBlock('31–60 days',   b['31-60'], c['31-60'], 'warn'),
      agingBlock('61–90 days',   b['61-90'], c['61-90'], 'warn'),
      agingBlock('Over 90 days', b['90+'],   over90Count(ar),   'danger'),
    ),
    el('p', { class: 'muted', style: { marginTop: '14px', fontSize: '12px' } },
      'Industry benchmark: a healthy law-firm A/R has under 30% in the 90+ bucket. ' +
      'BCL currently sits at ' + fmtPct(ar.over90Pct || 0) + ' — collections focus warranted.'),
  ));

  // A/R by client — the FULL client list (all open accounts), searchable.
  // Falls back to the top-25 list if the full client list isn't present yet.
  const c2o = data.clientToOriginator || {};
  const allClients = (ar.clients && ar.clients.length) ? ar.clients : (ar.topClients || []);
  if (allClients.length) {
    const full = !!(ar.clients && ar.clients.length);
    const panel = el('div', { class: 'panel' });
    const search = el('input', { class: 'tf-date', type: 'search',
      placeholder: 'Search ' + allClients.length + ' clients…', style: { minWidth: '260px' } });
    panel.appendChild(el('div', { class: 'panel-head' },
      el('h3', null, full ? 'A/R by client — all open accounts' : 'Largest debtors — top 25 by total open balance'),
      el('span', { class: 'muted', style: { fontSize: '12px' } },
        fmtNum(allClients.length) + ' clients · ' + fmtMoneyFull(ar.total || 0) + ' total open · as of ' + fmtDate(ar.asOf))));
    panel.appendChild(el('div', { style: { margin: '0 0 12px' } }, search));
    const tbody = el('tbody');
    const foot = el('p', { class: 'muted', style: { fontSize: '12px', marginTop: '10px' } });
    const cell = (v, cls) => el('td', { class: 'num' + (cls ? ' ' + cls : '') }, v ? fmtMoneyFull(v) : '—');
    function renderRows() {
      const q = search.value.trim().toLowerCase();
      const rows = q ? allClients.filter((r) => shortenClient(r.client).toLowerCase().includes(q)
        || (c2o[shortenClient(r.client)] || '').toLowerCase().includes(q)) : allClients;
      tbody.innerHTML = '';
      rows.forEach((r) => tbody.appendChild(el('tr', null,
        el('td', null, shortenClient(r.client)),
        el('td', null, c2o[shortenClient(r.client)] || '—'),
        cell(r.total, 'bold'), cell(r.current), cell(r.b30), cell(r.b60), cell(r.b90),
        cell(r.b91, 'warn'))));
      const sum = rows.reduce((s, r) => s + (r.total || 0), 0);
      foot.textContent = fmtNum(rows.length) + ' of ' + fmtNum(allClients.length) + ' clients shown · ' + fmtMoneyFull(sum) + ' total';
    }
    search.addEventListener('input', renderRows);
    renderRows();
    panel.appendChild(el('div', { class: 'ledger-wrap', style: { maxHeight: '560px', overflowY: 'auto' } },
      el('table', { class: 'data-table ledger-table' },
        el('thead', null, el('tr', null,
          el('th', null, 'Client'), el('th', null, 'Originator'),
          el('th', { class: 'num' }, 'Total'), el('th', { class: 'num' }, 'Current'),
          el('th', { class: 'num' }, '1–30'), el('th', { class: 'num' }, '31–60'),
          el('th', { class: 'num' }, '61–90'), el('th', { class: 'num' }, '90+'))),
        tbody)));
    panel.appendChild(foot);
    root.appendChild(panel);
  }
}

// ============================================================
// TOP COLLECTIBLES (chase list) — 90+ debtors
// ============================================================
async function renderCollectibles(root) {
  const data = await loadData();
  root.innerHTML = '';
  if (!data || !data.ar) {
    root.appendChild(pageHead('Accounts Receivable', 'A/R Over 90 Days · Top 25', 'No A/R loaded'));
    root.appendChild(emptyState('Upload an A/R aging report.'));
    return;
  }
  const ar = data.ar;
  const top = (ar.top90Plus || []).slice(0, 25);
  const totalOver90 = (ar.buckets && ar.buckets['90+']) || 0;
  const top10Sum = top.slice(0, 10).reduce((s, c) => s + c.b91, 0);

  const origByClient = data.clientToOriginator || {};

  root.appendChild(execHero({
    eyebrow: 'Accounts receivable · over 90 days · as of ' + fmtDate(ar.asOf),
    title: 'A/R Over 90 Days — Top 25',
    big: fmtMoneyFull(totalOver90),
    sub: 'These are the 25 clients with the largest balances aged 90+ days. ' +
         'Top 10 hold ' + fmtPct(100 * top10Sum / (totalOver90 || 1)) + ' of all 90+ A/R.',
    chips: [{ text: fmtNum(over90Count(ar)) + ' invoices', tone: 'danger' }],
  }));

  root.appendChild(arExcelButton());

  root.appendChild(ownerTable({
    title: 'Top 25 outstanding A/R · clients with the largest 90+ balances',
    columns: [
      { label: 'Client', value: (r) => shortenClient(r.client) },
      { label: 'Originator', value: (r) => origByClient[shortenClient(r.client)] || '—' },
      { label: '90+ balance', num: true, bold: true, tone: 'warn', value: (r) => fmtMoneyFull(r.b91) },
      { label: 'Total open',  num: true, value: (r) => fmtMoneyFull(r.total) },
      { label: '90+ share',   num: true, value: (r) => fmtPct(100 * r.b91 / (r.total || 1)) },
    ],
    rows: top,
    foot: 'These are the clients to chase first. The 90+ bucket includes invoices going back to 2025 — ' +
      'open the Invoices tab to see every open invoice with its issue date and balance.',
  }));
}

// ============================================================
// ORIGINATING ATTORNEYS — who brought the business in
// ============================================================
async function renderOriginators(root) {
  const data = await loadData();
  root.innerHTML = '';
  if (!data || !data.originatingAttorneys || !data.originatingAttorneys.attorneys) {
    root.appendChild(pageHead('Accounts Receivable', 'A/R by Originating Attorney', 'No originator report loaded'));
    root.appendChild(emptyState('Upload an aging-by-originating-attorney report.'));
    return;
  }
  const oa = data.originatingAttorneys;
  const atts = oa.attorneys;
  const total = oa.totalBook || 0;

  root.appendChild(execHero({
    eyebrow: 'Accounts receivable · by originating attorney · as of ' + fmtDate(oa.asOf),
    title: 'A/R by Originating Attorney',
    big: fmtMoneyFull(total),
    sub: 'Total outstanding A/R across ' + atts.length + ' originating attorneys',
  }));

  // The originator report is uploaded separately from the A/R summary; when the
  // two snapshots differ, say so instead of letting the totals quietly disagree.
  const arAsOf = data.ar && data.ar.asOf;
  if (arAsOf && oa.asOf && arAsOf !== oa.asOf) {
    root.appendChild(el('div', { class: 'ledger-note' },
      el('strong', null, 'Different snapshot: '),
      'this originator report is from ' + fmtDate(oa.asOf) + ', while the A/R Aging Summary is from ' +
      fmtDate(arAsOf) + ' — totals will not match across the two views (' + fmtMoneyFull(total) +
      ' here vs ' + fmtMoneyFull((data.ar && data.ar.total) || 0) + '). Upload a fresh ' +
      'aging-by-originating-attorney report to bring this view current.'));
  }

  root.appendChild(el('div', { class: 'ar-export-bar', style: { margin: '10px 0 2px', display: 'flex', gap: '10px', flexWrap: 'wrap' } },
    el('button', { class: 'btn btn-primary btn-sm', onclick: downloadOriginatorAR },
      '⬇ Download A/R by Originating Attorney (Excel)'),
    el('button', { class: 'btn btn-ghost btn-sm', onclick: () => downloadBillsSheet({
      file: 'bills-corner/ar-sections.json', filename: 'BCL A-R Sections.xlsx' }) },
      '⬇ All A/R tabs')));

  appendOriginatorsChart(root, oa);

  // ---- expandable attorney table: A/R book ↔ originated matters ↔ commission payouts ----
  // Click an attorney to see the matters behind their book and what the firm
  // allocation rules (the golden prompt) have paid them on those collections,
  // tied into the same data that drives Bill's Corner.
  const cols = ['Attorney', '1–30', '31–60', '61–90', '90+', 'Total', 'Book share'];
  const thead = el('thead', null, el('tr', null, ...cols.map((c, i) =>
    el('th', { class: i ? 'num' : '' }, c))));
  const tbody = el('tbody');
  const expanded = new Set();
  let web = null; // { matters, matrix } lazily fetched + decrypted once
  async function loadWeb() {
    if (web) return web;
    const kdf = State.session && State.session.kdfInput;
    const get = async (p) => {
      const r = await fetch(p + '?_=' + Date.now(), { cache: 'no-store' });
      if (!r.ok) return null;
      const raw = await r.json();
      return isPwBlob(raw) ? await AsaCrypto.decryptJSON(raw, kdf) : raw;
    };
    const [matters, matrix] = await Promise.all([
      get('bills-corner/originator-matters.json').catch(() => null),
      get('bills-corner/commission-matrix.json').catch(() => null),
    ]);
    web = { matters, matrix };
    return web;
  }
  const attKey = (name) => { // "Margery Greenberg" -> "greenberg, margery"
    const t = String(name || '').trim().split(/\s+/);
    return t.length >= 2 ? (t[t.length - 1] + ', ' + t[0]).toLowerCase() : String(name || '').toLowerCase();
  };
  function detailRow(r) {
    const td = el('td', { colspan: String(cols.length) });
    const tr = el('tr', { class: 'ledger-detail' }, td);
    td.appendChild(el('div', { class: 'loading' }, 'Loading commission web…'));
    loadWeb().then(({ matters, matrix }) => {
      td.innerHTML = '';
      const key = attKey(r.attorney);
      const om = matters && matters.attorneys && matters.attorneys[key];
      const mx = matrix && (matrix.attorneys || []).find((a) => a.key === key);
      if (mx) {
        td.appendChild(el('div', { class: 'ledger-detail-row' },
          el('span', { class: 'ledger-chip ledger-chip-user' }, 'Billing commission YTD ' + fmtMoneyFull(mx.ytdUser)),
          el('span', { class: 'ledger-chip ledger-chip-orig' }, 'Origination credit YTD ' + fmtMoneyFull(mx.ytdOrig)),
          el('span', { class: 'ledger-chip' }, 'Total paid YTD ' + fmtMoneyFull(mx.ytd))));
      }
      if (om && om.matters && om.matters.length) {
        const mt = el('table', { class: 'data-table' },
          el('thead', null, el('tr', null,
            el('th', null, 'Matter'),
            el('th', { class: 'num' }, 'Collected'),
            el('th', { class: 'num' }, 'Billing commission'),
            el('th', { class: 'num' }, 'Origination credit'))),
          el('tbody', null, ...om.matters.slice(0, 10).map((m) => el('tr', null,
            el('td', null, m.matter),
            el('td', { class: 'num' }, fmtMoneyFull(m.collected)),
            el('td', { class: 'num' }, m.user ? fmtMoneyFull(m.user) : '—'),
            el('td', { class: 'num' }, m.orig ? fmtMoneyFull(m.orig) : '—')))));
        td.appendChild(mt);
        if (om.matterCount > 10) td.appendChild(el('p', { class: 'muted', style: { fontSize: '11px', margin: '6px 2px' } },
          'Top 10 of ' + om.matterCount + ' matters with collections this year, ranked by their payout.'));
      } else {
        td.appendChild(el('p', { class: 'muted', style: { margin: '8px 2px' } },
          (mx ? 'No matter-level collections recorded for this attorney in the loaded payment-allocation reports.'
              : 'No commission activity for this attorney in the loaded payment-allocation reports — their payouts appear once a report covering their collections is uploaded.')));
      }
      td.appendChild(el('p', { class: 'muted', style: { fontSize: '12px', margin: '8px 2px 2px' } },
        'Figures follow the firm allocation rules (same engine as the commission ledger). ',
        el('a', { href: '#', class: 'panel-link', onclick: (e) => { e.preventDefault(); navigate('billscorner'); } },
          'Open Bill\'s Corner →')));
    }).catch((e) => { td.textContent = 'Could not load commission data: ' + (e.message || e); });
    return tr;
  }
  function renderRows() {
    tbody.innerHTML = '';
    atts.forEach((r) => {
      const open = expanded.has(r.attorney);
      const tr = el('tr', { class: 'ledger-row' + (open ? ' is-open' : ''), title: 'Click for matters + commissions' },
        el('td', null, el('div', { class: 'ledger-name-cell' },
          el('span', null, el('span', { class: 'ledger-caret' }, open ? '▾ ' : '▸ '), r.attorney),
          el('button', {
            class: 'ar-att-dl',
            title: 'Download ' + r.attorney + '’s A/R report (Excel)',
            onclick: (e) => { e.stopPropagation(); downloadOriginatorARForAttorney(r, oa.asOf); },
          }, '↓ A/R'))),
        el('td', { class: 'num' }, r.b30 ? fmtMoneyFull(r.b30) : '—'),
        el('td', { class: 'num' }, r.b60 ? fmtMoneyFull(r.b60) : '—'),
        el('td', { class: 'num' }, r.b90 ? fmtMoneyFull(r.b90) : '—'),
        el('td', { class: 'num warn' }, r.b91 ? fmtMoneyFull(r.b91) : '—'),
        el('td', { class: 'num bold' }, fmtMoneyFull(r.total)),
        el('td', { class: 'num' }, fmtPct(100 * r.total / (total || 1))));
      tr.addEventListener('click', () => { if (open) expanded.delete(r.attorney); else expanded.add(r.attorney); renderRows(); });
      tbody.appendChild(tr);
      if (open) tbody.appendChild(detailRow(r));
    });
  }
  renderRows();
  root.appendChild(el('div', { class: 'panel' },
    el('h3', null, 'Originating attorney — receivables, matters & commission payouts'),
    el('table', { class: 'data-table ledger-table' }, thead, tbody),
    el('p', { class: 'muted', style: { marginTop: '12px', fontSize: '12px' } },
      'Source: aging-by-originating-attorney report, ' + fmtDate(oa.asOf) + '. ' +
      'Top 5 originators account for ' + fmtPct(100 * atts.slice(0,5).reduce((s,a)=>s+a.total,0) / (total || 1)) +
      ' of the firm\'s outstanding receivables. Click any attorney to see their matters and what the allocation rules paid them.')));
}

// ============================================================
// PROFIT & LOSS
// ============================================================
async function renderPL(root) {
  const data = await loadData();
  root.innerHTML = '';
  if (!data || !data.pl) {
    root.appendChild(pageHead('Income', 'Profit & Loss', 'No P&L loaded'));
    root.appendChild(emptyState('Upload a Profit & Loss report.'));
    return;
  }
  const pl = data.pl;

  root.appendChild(execHero({
    eyebrow: 'Profit & Loss · ' + fmtDate(pl.periodStart) + ' through ' + fmtDate(pl.periodEnd) + ' · ' + (pl.basis || 'Cash') + ' basis',
    title: 'YTD net income',
    big: fmtMoneyFull(pl.netIncome || 0),
    sub: 'Revenue ' + fmtMoneyFull(pl.totalIncome) + ' · margin ' + fmtPct(pl.margin || 0),
    chips: [{
      text: (pl.netIncome >= 0 ? '▲ ' : '▼ ') + fmtPct(Math.abs(pl.margin || 0)),
      tone: pl.netIncome < 0 ? 'danger' : '',
    }],
  }));

  // P&L summary
  root.appendChild(el('div', { class: 'panel' },
    el('h3', null, 'Statement summary'),
    el('table', { class: 'data-table compact-pl' },
      el('tbody', null,
        plLineRow('Total revenue',              pl.totalIncome,       true),
        plLineRow('Gross profit',               pl.grossProfit),
        plLineRow('Operating expenses',         -Math.abs(pl.operatingExpenses), false, 'subtle'),
        plLineRow('Net operating income',       pl.netOperatingIncome, true),
        plLineRow('Partner distributions & other', -Math.abs(pl.otherExpenses),  false, 'subtle'),
        plLineRow('Net income',                 pl.netIncome,          true, pl.netIncome < 0 ? 'warn' : ''),
      ),
    ),
    el('p', { class: 'muted', style: { marginTop: '10px', fontSize: '12px' } },
      (pl.basis || 'Cash') + ' basis · all figures direct from QuickBooks export, ' + fmtDate(pl.periodEnd) + '.'),
  ));

  // Top expense categories — % is of OPERATING expenses (the categories listed
  // are operating-only; totalExpenses also contains the partner-draw block)
  if (pl.topExpenseCategories && pl.topExpenseCategories.length) {
    root.appendChild(ownerTable({
      title: 'Largest expense categories · YTD',
      columns: [
        { label: 'Category', value: (r) => cleanCat(r.label) },
        { label: 'YTD amount', num: true, bold: true, value: (r) => fmtMoneyFull(r.amount) },
        { label: '% of operating expenses', num: true, value: (r) => fmtPct(100 * Math.abs(r.amount) / (Math.abs(pl.operatingExpenses) || 1)) },
      ],
      rows: pl.topExpenseCategories,
    }));
  }
}

// ============================================================
// PARTNER DISTRIBUTIONS
// ============================================================
async function renderDistributions(root) {
  const data = await loadData();
  root.innerHTML = '';
  if (!data || !data.distributions) {
    root.appendChild(pageHead('Income', 'Partner Distributions', 'No distributions data loaded'));
    root.appendChild(emptyState('Upload a Profit & Loss report — the loop extracts partner draws + 401(k) + PTET from accounts 6051 and 6053.'));
    return;
  }
  const dist = data.distributions;
  const people = (dist.byPerson || []).filter((p) => Math.abs(p.amount || 0) >= 0.005);

  root.appendChild(execHero({
    eyebrow: 'Partner distributions · ' + fmtDate(dist.periodStart) + ' – ' + fmtDate(dist.periodEnd),
    title: 'YTD partner draws & guaranteed payments',
    big: fmtMoneyFull(dist.total),
    sub: dist.lineCount + ' line items across ' + people.length + ' partners · ' +
         fmtPct(100 * dist.total / ((data.pl && data.pl.totalIncome) || 1)) + ' of YTD revenue',
  }));

  // By-person summary (zero-amount rows are noise, not partners)
  if (people.length) {
    root.appendChild(ownerTable({
      title: 'By partner — total draws YTD',
      columns: [
        { label: 'Partner',     value: (r) => r.person },
        { label: 'YTD draws',   num: true, bold: true, value: (r) => fmtMoneyFull(r.amount) },
        { label: '% of pool',   num: true, value: (r) => fmtPct(100 * r.amount / (dist.total || 1)) },
      ],
      rows: people,
    }));
  }

  // Draws by date — transaction-level ledger from the P&L Detail report.
  // Coverage is whatever window that report was run for, stated explicitly.
  const dbd = dist.drawsByDate;
  if (dbd && dbd.transactions && dbd.transactions.length) {
    if (dbd.weekly && dbd.weekly.length > 1) {
      root.appendChild(barChartPanel(
        'Draws by week', fmtDate(dbd.coverageStart) + ' – ' + fmtDate(dbd.coverageEnd) + ' · ' + fmtMoneyFull(dbd.total) + ' total',
        dbd.weekly.map((w) => ({ label: fmtDate(w.w).replace(', 2026', ''), value: w.total, color: '#b08a3a' })),
        'Week buckets start Monday. Negative weeks are reversals/adjustments.'));
    }
    const people = [...new Set(dbd.transactions.map((t) => t.person))].sort();
    const filter = el('select', { class: 'tf-date' },
      el('option', { value: '' }, 'All partners'),
      ...people.map((p) => el('option', { value: p }, p)));
    const tbody = el('tbody');
    const foot = el('p', { class: 'muted', style: { marginTop: '10px', fontSize: '12px' } });
    function renderTxns() {
      const sel = filter.value;
      const txns = dbd.transactions.filter((t) => !sel || t.person === sel).slice().reverse();
      tbody.innerHTML = '';
      txns.forEach((t) => tbody.appendChild(el('tr', null,
        el('td', null, fmtDate(t.d)),
        el('td', null, t.person),
        el('td', null, t.type + (t.num ? ' ' + t.num : '')),
        el('td', null, t.code),
        el('td', { class: 'num bold' }, fmtMoneyFull(t.amount)))));
      const sum = txns.reduce((s, t) => s + t.amount, 0);
      foot.textContent = txns.length + ' transactions · ' + fmtMoneyFull(sum) +
        (sel ? ' drawn by ' + sel : ' total') + ' in this window. ' + (dbd.note || '');
    }
    filter.addEventListener('change', renderTxns);
    renderTxns();
    root.appendChild(el('div', { class: 'panel' },
      el('div', { class: 'panel-head' },
        el('h3', null, 'Draws by date'),
        el('span', { class: 'muted', style: { fontSize: '12px' } },
          'Source: ' + (dbd.source || 'P&L Detail report'))),
      el('div', { style: { marginBottom: '10px' } }, filter),
      el('div', { class: 'ledger-wrap', style: { maxHeight: '420px', overflowY: 'auto' } },
        el('table', { class: 'data-table' },
          el('thead', null, el('tr', null,
            el('th', null, 'Date'), el('th', null, 'Partner'),
            el('th', null, 'Type'), el('th', null, 'GL'),
            el('th', { class: 'num' }, 'Amount'))),
          tbody)),
      foot));
  }

  // Detail by line (full GL view)
  if (dist.lines && dist.lines.length) {
    root.appendChild(ownerTable({
      title: 'Line detail · every GL entry under accounts 6051 (Guaranteed Payments) and 6053 (Partner Distributions)',
      columns: [
        { label: 'GL code',  value: (r) => r.code },
        { label: 'Partner',  value: (r) => r.person },
        { label: 'Kind',     value: (r) => r.kind },
        { label: 'Amount',   num: true, bold: true, value: (r) => fmtMoneyFull(r.amount) },
      ],
      rows: dist.lines,
      foot: dist.note,
    }));
  }
}

// ============================================================
// CASH & BALANCE SHEET
// ============================================================
async function renderCash(root) {
  const data = await loadData();
  root.innerHTML = '';
  if (!data || (!data.balanceSheet && !data.cashFlow)) {
    root.appendChild(pageHead('Cash', 'Cash & Balance Sheet', 'No reports loaded'));
    root.appendChild(emptyState('Upload Balance Sheet and Statement of Cash Flows.'));
    return;
  }
  const bs = data.balanceSheet || {};
  const cf = data.cashFlow || {};
  const hasBS = !!data.balanceSheet, hasCF = !!data.cashFlow;

  root.appendChild(execHero({
    eyebrow: 'Cash position · as of ' + fmtDate(bs.asOf || data.asOf),
    title: 'Cash on hand',
    big: fmtMoneyFull(cf.cashEnding || bs.cashInBank || 0),
    sub: hasCF ? 'Net change YTD ' + (cf.netChange < 0 ? '−' : '+') + fmtMoneyFull(Math.abs(cf.netChange || 0)) : 'Statement of Cash Flows not loaded',
    chips: cf.netChange < 0 ? [{ text: 'Cash down ' + fmtMoneyFull(Math.abs(cf.netChange)) + ' YTD', tone: 'warn' }] : [],
  }));

  // Bank accounts breakdown — reconciled to the cash-flow "ending cash" figure
  if (bs.bankAccounts && bs.bankAccounts.length) {
    const undep = bs.undepositedFunds || 0;
    root.appendChild(ownerTable({
      title: 'Bank accounts · current balance',
      columns: [
        { label: 'Account', value: (r) => r.account },
        { label: 'Balance', num: true, bold: true, value: (r) => fmtMoneyFull(r.balance) },
      ],
      rows: bs.bankAccounts,
      foot: 'Total across all accounts: ' + fmtMoneyFull(bs.cashInBank || 0) +
        (undep ? ' · plus undeposited funds ' + fmtMoneyFull(undep) + ' = ' +
          fmtMoneyFull((bs.cashInBank || 0) + undep) + ' total cash (the "Cash on hand" figure above).' : '.'),
    }));
  }

  // Cash flow YTD (cash basis, from the Statement of Cash Flows)
  if (hasCF) {
    root.appendChild(el('div', { class: 'panel' },
      el('h3', null, 'Cash flow · YTD'),
      el('table', { class: 'data-table compact-pl' },
        el('tbody', null,
          plLineRow('Beginning cash (Jan 1)', cf.cashBeginning,  false, 'subtle'),
          plLineRow('Operating activities',   cf.operating),
          plLineRow('Investing activities',   cf.investing),
          plLineRow('Financing activities',   cf.financing),
          plLineRow('Net change',             cf.netChange,      true, cf.netChange < 0 ? 'warn' : ''),
          plLineRow('Ending cash',            cf.cashEnding,     true),
        ),
      ),
    ));
  } else {
    root.appendChild(el('div', { class: 'panel' },
      el('h3', null, 'Cash flow · YTD'),
      el('p', { class: 'muted' }, 'No Statement of Cash Flows on file — upload one to populate this panel.')));
  }

  // Balance sheet snapshot
  if (hasBS) {
    root.appendChild(el('div', { class: 'grid-2' },
      el('div', { class: 'panel' },
        el('h3', null, 'Assets', el('span', { class: 'muted', style: { fontSize: '12px', fontWeight: '400' } },
          ' · ' + (bs.basis || 'Accrual') + ' basis')),
        el('table', { class: 'data-table compact-pl' },
          el('tbody', null,
            plLineRow('Cash in bank',         bs.cashInBank),
            bs.undepositedFunds != null ? plLineRow('Undeposited funds', bs.undepositedFunds) : null,
            plLineRow('Accounts receivable',  (data.ar && data.ar.total) || 0),
            bs.otherCurrentAssets != null ? plLineRow('Other current assets', bs.otherCurrentAssets) : null,
            plLineRow('Total current assets', bs.currentAssets, true),
            plLineRow('Fixed assets',         bs.fixedAssets),
            bs.otherAssets != null ? plLineRow('Other assets', bs.otherAssets) : null,
            plLineRow('Total assets',         bs.totalAssets,   true),
          ),
        )),
      el('div', { class: 'panel' },
        el('h3', null, 'Liabilities & Equity', el('span', { class: 'muted', style: { fontSize: '12px', fontWeight: '400' } },
          ' · ' + (bs.basis || 'Accrual') + ' basis')),
        el('table', { class: 'data-table compact-pl' },
          el('tbody', null,
            plLineRow('Current liabilities', bs.currentLiab),
            plLineRow('Total liabilities',   bs.totalLiab,   true),
            plLineRow('Total equity',        bs.totalEquity, true),
            plLineRow('Total liabilities & equity', (bs.totalLiab || 0) + (bs.totalEquity || 0), true),
          ),
        )),
    ));
    if ((bs.basis || 'Accrual') !== (data.pl && data.pl.basis || 'Cash')) {
      root.appendChild(el('p', { class: 'muted', style: { fontSize: '12px', margin: '10px 2px' } },
        'Note: the balance sheet above is ' + (bs.basis || 'Accrual').toLowerCase() + '-basis while the P&L page is ' +
        ((data.pl && data.pl.basis) || 'Cash').toLowerCase() + '-basis — their net-income figures will differ by design.'));
    }
  } else {
    root.appendChild(el('div', { class: 'panel' },
      el('h3', null, 'Balance sheet'),
      el('p', { class: 'muted' }, 'No Balance Sheet on file — upload one to populate this panel.')));
  }
}

// ============================================================
// ACCOUNTS PAYABLE
// ============================================================
async function renderAP(root) {
  const data = await loadData();
  root.innerHTML = '';
  if (!data || !data.ap) {
    root.appendChild(pageHead('Payables', 'Accounts Payable', 'No A/P loaded'));
    root.appendChild(emptyState('Upload an A/P aging report.'));
    return;
  }
  const ap = data.ap;
  const b = ap.buckets || {};

  root.appendChild(execHero({
    eyebrow: 'Accounts Payable · as of ' + fmtDate(ap.asOf),
    title: 'Total owed to vendors',
    big: fmtMoneyFull(ap.total),
    sub: fmtMoneyFull(b['90+'] || 0) + ' over 90 days',
    chips: (b['90+'] || 0) > 50000 ? [{ text: 'Aged payables', tone: 'warn' }] : [],
  }));

  root.appendChild(el('div', { class: 'panel' },
    el('h3', null, 'Aging buckets'),
    el('div', { class: 'aging-strip' },
      agingBlock('Current',  b['current']),
      agingBlock('1–30',     b['1-30']),
      agingBlock('31–60',    b['31-60'], null, 'warn'),
      agingBlock('61–90',    b['61-90'], null, 'warn'),
      agingBlock('90+',      b['90+'],   null, 'danger'),
    ),
  ));

  if (ap.topVendors && ap.topVendors.length) {
    root.appendChild(ownerTable({
      title: 'Top vendors owed',
      columns: [
        { label: 'Vendor', value: (r) => r.vendor },
        { label: 'Current', num: true, value: (r) => r.current ? fmtMoneyFull(r.current) : '—' },
        { label: '1–30',    num: true, value: (r) => r.b30 ? fmtMoneyFull(r.b30) : '—' },
        { label: '31–60',   num: true, value: (r) => r.b60 ? fmtMoneyFull(r.b60) : '—' },
        { label: '61–90',   num: true, value: (r) => r.b90 ? fmtMoneyFull(r.b90) : '—' },
        { label: '90+',     num: true, tone: 'warn', value: (r) => r.b91 ? fmtMoneyFull(r.b91) : '—' },
        { label: 'Total',   num: true, bold: true, value: (r) => fmtMoneyFull(r.total) },
      ],
      rows: ap.topVendors,
    }));
  }
}

// ============================================================
// WORK IN PROGRESS
// ============================================================
async function renderWIP(root) {
  const data = await loadData();
  root.innerHTML = '';
  if (!data || !data.wip) {
    root.appendChild(pageHead('WIP', 'Work in Progress', 'No WIP loaded'));
    root.appendChild(emptyState('Upload a Work-in-Progress report.'));
    return;
  }
  const w = data.wip;

  root.appendChild(execHero({
    eyebrow: 'Work in progress · ' + fmtDate(w.periodStart) + ' – ' + fmtDate(w.periodEnd),
    title: 'Unbilled time and costs',
    big: fmtMoneyFull(w.value || 0),
    sub: fmtNum(w.hours || 0) + ' hours at $' + fmtNum(Math.round(w.avgRate || 0)) + '/hr blended',
  }));

  root.appendChild(el('div', { class: 'panel' },
    el('h3', null, 'WIP snapshot'),
    el('div', { class: 'aging-strip' },
      el('div', { class: 'aging-block' },
        el('div', { class: 'aging-label' }, 'Unbilled value'),
        el('div', { class: 'aging-value' }, fmtMoneyFull(w.value || 0)),
        el('div', { class: 'aging-count' }, 'work performed, not invoiced'),
      ),
      el('div', { class: 'aging-block' },
        el('div', { class: 'aging-label' }, 'Hours logged'),
        el('div', { class: 'aging-value' }, fmtNum(w.hours || 0)),
        el('div', { class: 'aging-count' }, 'across all timekeepers'),
      ),
      el('div', { class: 'aging-block' },
        el('div', { class: 'aging-label' }, 'Blended rate'),
        el('div', { class: 'aging-value' }, '$' + fmtNum(Math.round(w.avgRate || 0))),
        el('div', { class: 'aging-count' }, 'effective $/hr'),
      ),
    ),
    el('p', { class: 'muted', style: { marginTop: '14px', fontSize: '12px' } },
      w.note || 'Per the firm\'s WIP report from QuickBooks/Clio. Detailed breakdown by attorney/matter available in the source PDF.'),
  ));
}

// ============================================================
// TOP CLIENTS by revenue
// ============================================================
async function renderTopClients(root) {
  const data = await loadData();
  root.innerHTML = '';
  if (!data || !data.topClients || !data.topClients.length) {
    root.appendChild(pageHead('Clients', 'Top Clients', 'No P&L by Customer loaded'));
    root.appendChild(emptyState('Upload a Profit & Loss by Customer report.'));
    return;
  }
  const tc = data.topClients;
  const tcBasis = (data.topClientsBasis || (data.pl && data.pl.basis) || 'Cash');
  // % denominators must share the basis of the client figures themselves
  const totalIncome = (tcBasis === (data.pl && data.pl.basis) ? (data.pl && data.pl.totalIncome) : data.topClientsTotalIncome) || (data.pl && data.pl.totalIncome) || 0;

  root.appendChild(execHero({
    eyebrow: 'Top clients · YTD revenue · ' + fmtDate(data.periodStart) + ' – ' + fmtDate(data.periodEnd),
    title: 'Revenue concentration',
    big: fmtPct(100 * tc.slice(0, 10).reduce((s, c) => s + c.income_ytd, 0) / (totalIncome || 1)),
    sub: 'of firm revenue from top 10 clients',
  }));

  // The P&L-by-Customer export doesn't allocate expenses, so per-client "net
  // income" always equals revenue — showing it would imply per-client
  // profitability that doesn't exist. Only show the column if it ever differs.
  const hasRealNI = tc.some((r) => Math.abs((r.net_income_ytd || 0) - (r.income_ytd || 0)) > 0.005);
  root.appendChild(ownerTable({
    title: 'Top ' + tc.length + ' clients by YTD revenue',
    columns: [
      { label: 'Client', value: (r) => shortenClient(r.client) },
      { label: 'YTD revenue',    num: true, bold: true, value: (r) => fmtMoneyFull(r.income_ytd) },
      ...(hasRealNI ? [{ label: 'YTD net income', num: true, value: (r) => fmtMoneyFull(r.net_income_ytd) }] : []),
      { label: '% of book',      num: true, value: (r) => fmtPct(100 * r.income_ytd / (totalIncome || 1)) },
    ],
    rows: tc.slice(0, 25),
    foot: 'Source: Profit & Loss by Customer, ' + tcBasis.toLowerCase() + ' basis, Jan 1 – ' + fmtDate(data.periodEnd) + '.',
  }));
}

// ============================================================
// INVOICES VIEW — searchable index of every invoice (billed + paid)
// Sources:
//   data/invoices.json     merged YTD 2026 (billing history + payments)
//   data/invoices_full.json same + line-item details where available
// ============================================================
let _invoicesCache = null;
let _invoicesFullCache = null;
async function _fetchPwMaybe(path) {
  // no-store on the cache — force-cache served stale plaintext after the encryption migration
  const r = await fetch(path + '?_=' + Date.now(), { cache: 'no-store' });
  if (!r.ok) throw new Error(path + ' not available (HTTP ' + r.status + ')');
  const raw = await r.json();
  if (isPwBlob(raw)) {
    const kdf = State.session && State.session.kdfInput;
    if (!kdf) throw new Error('Session missing password (kdfInput). Sign out and back in to refresh.');
    const dec = await AsaCrypto.decryptJSON(raw, kdf);
    if (dec === null) throw new Error('Decryption failed — sign out and back in with the correct password.');
    return dec;
  }
  return raw;
}
async function loadInvoices() {
  if (_invoicesCache) return _invoicesCache;
  _invoicesCache = await _fetchPwMaybe('data/invoices.json');
  return _invoicesCache;
}
async function loadInvoicesFull() {
  if (_invoicesFullCache) return _invoicesFullCache;
  const arr = await _fetchPwMaybe('data/invoices_full.json');
  const byNum = {};
  arr.forEach((inv) => { byNum[inv.invoice_no] = inv; });
  _invoicesFullCache = { arr, byNum };
  return _invoicesFullCache;
}

function toIsoDate(mdy) {
  if (!mdy) return '';
  const m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(mdy);
  return m ? (m[3] + '-' + m[1] + '-' + m[2]) : mdy;
}

async function renderInvoices(root) {
  root.innerHTML = '';
  let invoices;
  try {
    invoices = await loadInvoices();
  } catch (e) {
    root.appendChild(pageHead('Invoices', 'Invoices', 'Couldn\'t load the invoice index'));
    root.appendChild(el('div', { class: 'error-card' },
      el('h3', null, 'Invoices view error'),
      el('p', null, String(e.message || e)),
      el('p', { style: { marginTop: '12px' } },
        'Try signing out and back in (Settings → Sign out, then sign in again). The data file may have been refreshed but the cached session is stale.'),
    ));
    return;
  }
  if (!Array.isArray(invoices)) {
    root.appendChild(pageHead('Invoices', 'Invoices', 'Invoice data shape unexpected'));
    root.appendChild(el('div', { class: 'error-card' },
      el('h3', null, 'Got the file but it isn\'t an array'),
      el('p', null, 'Type: ' + typeof invoices + (invoices && typeof invoices === 'object' ? '. Keys: ' + Object.keys(invoices).slice(0, 8).join(', ') : '')),
    ));
    return;
  }

  // Searchable index — match on client, matter, inv#, originator, transaction, status, paid date, due date
  const idx = invoices.map((inv, i) => ({
    i,
    haystack: [
      inv.client, inv.matter, inv.invoice_no, inv.originator || '',
      inv.transaction || '', inv.status || '', inv.paid_date || '', inv.due_date || '',
      inv.cross_ref || '',
    ].join(' ').toLowerCase(),
    paidIso: toIsoDate(inv.paid_date),
    dueIso: toIsoDate(inv.due_date),
  }));

  // Stats
  const totalBilled  = invoices.reduce((s, x) => s + (x.amount   || 0), 0);
  const totalPaid    = invoices.reduce((s, x) => s + (x.payments || 0), 0);
  const totalOpen    = invoices.reduce((s, x) => s + (x.balance  || 0), 0);
  const pastDueCount = invoices.filter((x) => x.status === 'Past Due').length;
  const paidCount    = invoices.filter((x) => x.status === 'Paid').length;
  const clientSet = new Set(invoices.map((x) => x.client).filter(Boolean));
  const matterSet = new Set(invoices.map((x) => x.matter).filter(Boolean));
  const originators = Array.from(new Set(invoices.map((x) => x.originator).filter(Boolean))).sort();
  const statuses    = Array.from(new Set(invoices.map((x) => x.status).filter(Boolean))).sort();
  const txTypes     = Array.from(new Set(invoices.flatMap((x) => (x.transaction || '').split(',').map((s) => s.trim()).filter(Boolean)))).sort();

  // Date range — paid dates seen
  const paidDates = idx.map((x) => x.paidIso).filter(Boolean).sort();
  const dueDates  = idx.map((x) => x.dueIso).filter(Boolean).sort();
  const dateMin = paidDates[0] || dueDates[0] || '';
  const dateMax = paidDates[paidDates.length - 1] || dueDates[dueDates.length - 1] || '';

  root.appendChild(execHero({
    eyebrow: 'YTD 2026 invoices · billed Jan 1 – Jun 8 · as of June 8, 2026',
    title: 'Invoices',
    big: fmtMoneyFull(totalBilled),
    sub: invoices.length.toLocaleString() + ' invoices · ' + clientSet.size + ' clients · ' + matterSet.size + ' matters · ' + originators.length + ' originators',
  }));

  // KPI row
  const kpis = el('div', { class: 'kpi-grid kpi-grid-4', style: { marginTop: '16px' } });
  kpis.appendChild(kpiCard('Total billed', fmtMoneyFull(totalBilled), invoices.length.toLocaleString() + ' invoices YTD'));
  kpis.appendChild(kpiCard('Collected', fmtMoneyFull(totalPaid),
    paidCount.toLocaleString() + ' paid invoices'));
  kpis.appendChild(kpiCard('Open balance', fmtMoneyFull(totalOpen),
    pastDueCount.toLocaleString() + ' past due',
    totalOpen > 1000000 ? 'danger' : 'warn'));
  kpis.appendChild(kpiCard('Collection rate', (totalBilled ? (100 * totalPaid / totalBilled).toFixed(1) : '0') + '%',
    'of billed amount received · YTD 2026 (Jan 1 – Jun 8) + pre-2026 outstanding'));
  root.appendChild(kpis);

  // Search/filter panel
  const panel = el('div', { class: 'panel', style: { marginTop: '20px' } });

  const searchInput = el('input', {
    class: 'invoice-search',
    type: 'search',
    placeholder: 'Search across ' + invoices.length.toLocaleString() + ' invoices — try "104852", "David Thorne", "Past Due", "Meridian"',
    autocomplete: 'off',
    spellcheck: 'false',
  });

  const filterRow = el('div', { class: 'invoice-filter-row' });
  const statusSelect = el('select', { class: 'invoice-filter' });
  statusSelect.appendChild(el('option', { value: '' }, 'All statuses'));
  statuses.forEach((s) => statusSelect.appendChild(el('option', { value: s }, s)));

  const origSelect = el('select', { class: 'invoice-filter' });
  origSelect.appendChild(el('option', { value: '' }, 'All originators'));
  originators.forEach((o) => origSelect.appendChild(el('option', { value: o }, o)));

  const txSelect = el('select', { class: 'invoice-filter' });
  txSelect.appendChild(el('option', { value: '' }, 'All transactions'));
  txTypes.forEach((t) => txSelect.appendChild(el('option', { value: t }, t)));

  const dateField = el('select', { class: 'invoice-filter' });
  dateField.appendChild(el('option', { value: 'paid_date' }, 'Paid date'));
  dateField.appendChild(el('option', { value: 'due_date' }, 'Due date'));

  const dateFromInput = el('input', { type: 'date', class: 'invoice-filter' });
  const dateToInput = el('input', { type: 'date', class: 'invoice-filter' });
  const minAmtInput = el('input', { type: 'number', class: 'invoice-filter invoice-filter-amt', placeholder: 'Min $', min: '0', step: '100' });
  const maxAmtInput = el('input', { type: 'number', class: 'invoice-filter invoice-filter-amt', placeholder: 'Max $', min: '0', step: '100' });

  const clearBtn = el('button', { class: 'btn btn-ghost invoice-clear' }, 'Clear filters');

  filterRow.appendChild(el('label', { class: 'invoice-filter-label' }, 'Status', statusSelect));
  filterRow.appendChild(el('label', { class: 'invoice-filter-label' }, 'Originator', origSelect));
  filterRow.appendChild(el('label', { class: 'invoice-filter-label' }, 'Transaction', txSelect));
  filterRow.appendChild(el('label', { class: 'invoice-filter-label' }, 'Date field', dateField));
  filterRow.appendChild(el('label', { class: 'invoice-filter-label' }, 'From', dateFromInput));
  filterRow.appendChild(el('label', { class: 'invoice-filter-label' }, 'To', dateToInput));
  filterRow.appendChild(el('label', { class: 'invoice-filter-label' }, 'Amount', el('div', { class: 'invoice-amt-pair' }, minAmtInput, maxAmtInput)));
  filterRow.appendChild(clearBtn);

  panel.appendChild(searchInput);
  panel.appendChild(filterRow);

  const summaryBar = el('div', { class: 'invoice-summary' });
  panel.appendChild(summaryBar);

  // Results table
  const tableWrap = el('div', { class: 'invoice-table-wrap' });
  const tableHead = el('thead', null,
    el('tr', null,
      el('th', { 'data-sort': 'date',       class: 'invoice-th sortable' }, 'Issue date ▾'),
      el('th', { 'data-sort': 'due_date',   class: 'invoice-th sortable' }, 'Due date'),
      el('th', { 'data-sort': 'paid_date',  class: 'invoice-th sortable' }, 'Paid date'),
      el('th', { 'data-sort': 'client',     class: 'invoice-th sortable' }, 'Client'),
      el('th', { 'data-sort': 'matter',     class: 'invoice-th sortable' }, 'Matter'),
      el('th', { 'data-sort': 'invoice_no', class: 'invoice-th sortable' }, 'Invoice #'),
      el('th', { 'data-sort': 'originator', class: 'invoice-th sortable' }, 'Originator'),
      el('th', { 'data-sort': 'status',     class: 'invoice-th sortable' }, 'Status'),
      el('th', { 'data-sort': 'amount',     class: 'invoice-th sortable num' }, 'Amount'),
      el('th', { 'data-sort': 'balance',    class: 'invoice-th sortable num' }, 'Balance'),
    )
  );
  const tableBody = el('tbody', { id: 'invoiceTbody' });
  const table = el('table', { class: 'data-table invoice-table' }, tableHead, tableBody);
  tableWrap.appendChild(table);
  panel.appendChild(tableWrap);

  // Pagination
  const pager = el('div', { class: 'invoice-pager' });
  panel.appendChild(pager);

  root.appendChild(panel);

  // ---- state ----
  // Seed from a drill-down (e.g. clicking a debtor on the Overview) then clear it.
  const drill = (State.navOpts && State.navOpts.q) ? String(State.navOpts.q) : '';
  State.navOpts = null;
  let state = {
    q: drill, status: '', orig: '', tx: '',
    dateField: 'paid_date', from: '', to: '',
    min: null, max: null,
    sort: 'date', dir: 'desc',
    page: 1, pageSize: 50,
    expanded: new Set(),
  };

  function applyFilters() {
    const q = state.q.trim().toLowerCase();
    const qParts = q ? q.split(/\s+/).filter(Boolean) : [];
    const out = [];
    for (const x of idx) {
      const inv = invoices[x.i];
      if (state.status && inv.status !== state.status) continue;
      if (state.orig && inv.originator !== state.orig) continue;
      if (state.tx && !(inv.transaction || '').split(',').map((s) => s.trim()).includes(state.tx)) continue;
      const iso = state.dateField === 'due_date' ? x.dueIso : x.paidIso;
      if (state.from && (!iso || iso < state.from)) continue;
      if (state.to && (!iso || iso > state.to)) continue;
      if (state.min != null && inv.amount < state.min) continue;
      if (state.max != null && inv.amount > state.max) continue;
      if (qParts.length) {
        let ok = true;
        for (const p of qParts) { if (x.haystack.indexOf(p) === -1) { ok = false; break; } }
        if (!ok) continue;
      }
      out.push(inv);
    }
    const dir = state.dir === 'asc' ? 1 : -1;
    const key = state.sort;
    out.sort((a, b) => {
      let av = a[key] == null ? '' : a[key];
      let bv = b[key] == null ? '' : b[key];
      if (key === 'paid_date' || key === 'due_date' || key === 'date') { av = toIsoDate(av); bv = toIsoDate(bv); }
      if (av < bv) return -1 * dir;
      if (av > bv) return  1 * dir;
      return 0;
    });
    return out;
  }

  function statusBadge(s) {
    if (!s) return '—';
    return el('span', { class: 'invoice-tag tx-status-' + s.replace(/\W+/g, '_') }, s);
  }
  function txBadge(t) {
    if (!t) return '';
    return el('span', { class: 'invoice-tag tx-' + t.replace(/\W+/g, '_') }, t);
  }

  function renderTable() {
    const filtered = applyFilters();
    const sumBilled  = filtered.reduce((s, x) => s + (x.amount   || 0), 0);
    const sumPaid    = filtered.reduce((s, x) => s + (x.payments || 0), 0);
    const sumOpen    = filtered.reduce((s, x) => s + (x.balance  || 0), 0);
    summaryBar.innerHTML = '';
    summaryBar.appendChild(el('div', null,
      el('strong', null, filtered.length.toLocaleString() + ' results'),
      el('span', { class: 'muted' }, ' · billed ' + fmtMoneyFull(sumBilled) + ' · paid ' + fmtMoneyFull(sumPaid) + ' · open ' + fmtMoneyFull(sumOpen)),
    ));
    const exportBtn = el('button', { class: 'btn btn-ghost btn-sm', onclick: () => exportCsv(filtered) }, 'Export CSV');
    summaryBar.appendChild(exportBtn);

    const start = (state.page - 1) * state.pageSize;
    const slice = filtered.slice(start, start + state.pageSize);

    tableBody.innerHTML = '';
    if (slice.length === 0) {
      const tr = el('tr', null, el('td', { colspan: '10', class: 'invoice-empty' }, 'No invoices match your filters.'));
      tableBody.appendChild(tr);
    } else {
      slice.forEach((inv) => {
        const expandKey = inv.invoice_no;
        const tr = el('tr', { class: 'invoice-row' + (inv.status === 'Past Due' ? ' is-past-due' : '') },
          el('td', null, inv.date || '—'),
          el('td', null, inv.due_date || '—'),
          el('td', null, inv.paid_date || '—'),
          el('td', null, highlight(inv.client, state.q)),
          el('td', { class: 'invoice-matter' }, highlight(inv.matter, state.q)),
          el('td', { class: 'invoice-num' }, highlight(inv.invoice_no, state.q)),
          el('td', null, highlight(inv.originator || '', state.q)),
          el('td', null, statusBadge(inv.status)),
          el('td', { class: 'num bold' }, fmtMoneyFull(inv.amount)),
          el('td', { class: 'num' + (inv.balance > 0 ? ' invoice-balance-open' : '') }, fmtMoneyFull(inv.balance || 0)),
        );
        tr.addEventListener('click', () => toggleRow(inv, expandKey));
        tableBody.appendChild(tr);
        if (state.expanded.has(expandKey)) {
          const detail = el('tr', { class: 'invoice-detail-row' },
            el('td', { colspan: '10' }, el('div', { class: 'invoice-detail-loading' }, 'Loading details…'))
          );
          tableBody.appendChild(detail);
          renderDetail(detail, inv);
        }
      });
    }

    pager.innerHTML = '';
    const pages = Math.max(1, Math.ceil(filtered.length / state.pageSize));
    if (state.page > pages) state.page = 1;
    const prev = el('button', { class: 'btn btn-ghost btn-sm', disabled: state.page <= 1 ? '' : null,
      onclick: () => { if (state.page > 1) { state.page--; renderTable(); } } }, '← Prev');
    const next = el('button', { class: 'btn btn-ghost btn-sm', disabled: state.page >= pages ? '' : null,
      onclick: () => { if (state.page < pages) { state.page++; renderTable(); } } }, 'Next →');
    const info = el('span', { class: 'muted' },
      'Page ' + state.page + ' of ' + pages + ' · ' + state.pageSize + ' per page');
    const sizeSel = el('select', { class: 'invoice-pagesize',
      onchange: (e) => { state.pageSize = +e.target.value; state.page = 1; renderTable(); } });
    [25, 50, 100, 250, 500].forEach((n) => {
      const o = el('option', { value: String(n) }, String(n));
      if (n === state.pageSize) o.selected = true;
      sizeSel.appendChild(o);
    });
    pager.appendChild(prev);
    pager.appendChild(info);
    pager.appendChild(next);
    pager.appendChild(sizeSel);
  }

  async function renderDetail(tr, inv) {
    try {
      let full; try { full = await loadInvoicesFull(); } catch (_) { full = { byNum: {} }; }
      const rec = full.byNum[inv.invoice_no] || inv;
      const td = tr.firstChild;
      td.innerHTML = '';

      // Summary card
      const card = el('div', { class: 'invoice-detail-card' });
      card.appendChild(el('div', { class: 'invoice-detail-grid' },
        kvCell('Status', inv.status || '—'),
        kvCell('Due date', inv.due_date || '—'),
        kvCell('Billed', fmtMoneyFull(inv.amount)),
        kvCell('Payments received', fmtMoneyFull(inv.payments || 0)),
        kvCell('Credit notes', fmtMoneyFull(inv.credit_notes || 0)),
        kvCell('Open balance', fmtMoneyFull(inv.balance || 0)),
        kvCell('Originator', inv.originator || '—'),
        kvCell('Transaction', inv.transaction || '—'),
      ));
      td.appendChild(card);

      // Payment events
      if (rec.payments_received && rec.payments_received.length) {
        td.appendChild(el('h4', { class: 'invoice-detail-h4' }, 'Payments received'));
        const pt = el('table', { class: 'data-table invoice-line-table' });
        pt.appendChild(el('thead', null, el('tr', null,
          el('th', null, 'Paid date'), el('th', null, 'Transaction'), el('th', { class: 'num' }, 'Amount'))));
        pt.appendChild(el('tbody', null, ...rec.payments_received.map((p) =>
          el('tr', null,
            el('td', null, p.paid_date),
            el('td', null, txBadge(p.transaction)),
            el('td', { class: 'num' }, fmtMoneyFull(p.amount))))));
        td.appendChild(pt);
      }

      // Line items
      const lines = rec.lines || [];
      if (lines.length) {
        td.appendChild(el('h4', { class: 'invoice-detail-h4' }, lines.length + ' line items'));
        const lt = el('table', { class: 'data-table invoice-line-table' });
        lt.appendChild(el('thead', null, el('tr', null,
          el('th', null, 'Date'), el('th', null, 'Type'), el('th', null, 'Description'), el('th', { class: 'num' }, 'Amount'))));
        lt.appendChild(el('tbody', null, ...lines.map((l) =>
          el('tr', null,
            el('td', null, l.date),
            el('td', null, el('span', { class: 'invoice-tag tx-' + l.type }, l.type)),
            el('td', null, l.desc),
            el('td', { class: 'num' }, fmtMoneyFull(l.amount))))));
        td.appendChild(lt);
      } else if (!rec.payments_received || !rec.payments_received.length) {
        td.appendChild(el('div', { class: 'invoice-detail-empty' }, 'No payment events or line items captured for this invoice yet.'));
      }
    } catch (e) {
      tr.firstChild.innerHTML = '<div class="invoice-detail-empty">Failed to load detail: ' + escapeHtml(e.message) + '</div>';
    }
  }

  function kvCell(label, value) {
    return el('div', { class: 'invoice-kv' },
      el('div', { class: 'invoice-kv-label' }, label),
      el('div', { class: 'invoice-kv-value' }, value));
  }

  function toggleRow(inv, key) {
    if (state.expanded.has(key)) state.expanded.delete(key);
    else state.expanded.add(key);
    renderTable();
  }

  function highlight(text, q) {
    if (!q) return text || '';
    const t = String(text || '');
    const parts = q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (!parts.length) return t;
    const rx = new RegExp('(' + parts.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')', 'gi');
    const frag = document.createDocumentFragment();
    let last = 0;
    t.replace(rx, (m, _g, off) => {
      if (off > last) frag.appendChild(document.createTextNode(t.slice(last, off)));
      frag.appendChild(el('mark', null, m));
      last = off + m.length;
      return m;
    });
    if (last < t.length) frag.appendChild(document.createTextNode(t.slice(last)));
    return frag;
  }

  function exportCsv(rows) {
    const header = ['Paid date', 'Due date', 'Client', 'Matter', 'Invoice #', 'Originator', 'Status', 'Transaction', 'Amount', 'Payments', 'Credit notes', 'Balance'];
    const lines = [header.join(',')];
    rows.forEach((r) => {
      const cells = [
        r.paid_date || '', r.due_date || '', r.client, r.matter, r.invoice_no,
        r.originator || '', r.status || '', r.transaction || '',
        (r.amount || 0).toFixed(2), (r.payments || 0).toFixed(2),
        (r.credit_notes || 0).toFixed(2), (r.balance || 0).toFixed(2),
      ];
      lines.push(cells.map((v) => {
        const s = String(v == null ? '' : v);
        return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      }).join(','));
    });
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'invoices-' + new Date().toISOString().slice(0, 10) + '.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // ---- wire events ----
  let debounce;
  searchInput.addEventListener('input', (e) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => { state.q = e.target.value; state.page = 1; renderTable(); }, 120);
  });
  statusSelect.addEventListener('change', (e) => { state.status = e.target.value; state.page = 1; renderTable(); });
  origSelect.addEventListener('change',   (e) => { state.orig   = e.target.value; state.page = 1; renderTable(); });
  txSelect.addEventListener('change',     (e) => { state.tx     = e.target.value; state.page = 1; renderTable(); });
  dateField.addEventListener('change',    (e) => { state.dateField = e.target.value; state.page = 1; renderTable(); });
  dateFromInput.addEventListener('change',(e) => { state.from   = e.target.value; state.page = 1; renderTable(); });
  dateToInput.addEventListener('change',  (e) => { state.to     = e.target.value; state.page = 1; renderTable(); });
  minAmtInput.addEventListener('input',   (e) => { const v = e.target.value; state.min = v === '' ? null : +v; state.page = 1; renderTable(); });
  maxAmtInput.addEventListener('input',   (e) => { const v = e.target.value; state.max = v === '' ? null : +v; state.page = 1; renderTable(); });
  clearBtn.addEventListener('click', () => {
    state = { ...state, q: '', status: '', orig: '', tx: '', from: '', to: '', min: null, max: null, page: 1 };
    searchInput.value = ''; statusSelect.value = ''; origSelect.value = ''; txSelect.value = '';
    dateFromInput.value = ''; dateToInput.value = '';
    minAmtInput.value = ''; maxAmtInput.value = '';
    renderTable();
  });
  $$('.invoice-th.sortable').forEach((th) => {
    th.addEventListener('click', () => {
      const k = th.dataset.sort;
      if (state.sort === k) state.dir = state.dir === 'asc' ? 'desc' : 'asc';
      else { state.sort = k; state.dir = (k === 'amount' || k === 'balance' || k === 'paid_date' || k === 'due_date') ? 'desc' : 'asc'; }
      $$('.invoice-th.sortable').forEach((t) => t.innerHTML = t.innerHTML.replace(/\s[▾▴]$/, ''));
      th.innerHTML += state.dir === 'asc' ? ' ▴' : ' ▾';
      renderTable();
    });
  });

  if (state.q) searchInput.value = state.q;   // reflect a drill-down seed in the search box
  renderTable();
}

// ============================================================
// UPLOAD VIEW
// ============================================================
async function renderUpload(root) {
  root.innerHTML = '';
  root.appendChild(pageHead('Add files', 'Upload',
    'Drop billing reports here — PDF, XLSX, CSV, or images. I figure out what kind of report it is when I crunch it.'));

  const card = el('div', { class: 'panel upload-panel' });

  const drop = el('label', { class: 'dropzone', for: 'fileInput' },
    el('div', { class: 'dropzone-icon' }, '⤓'),
    el('div', { class: 'dropzone-text' }, 'Drag files here or click to browse'),
    el('div', { class: 'dropzone-sub' }, 'Multiple files OK · PDF, XLSX, CSV, PNG, JPG · up to 20 MB each'),
  );
  const fileInput = el('input', { id: 'fileInput', type: 'file', multiple: '', style: { display: 'none' } });

  const noteInput = el('textarea', { class: 'textarea', placeholder: 'Optional note — what is this and what should I look at?' });
  const submit = el('button', { class: 'btn btn-primary' }, 'Upload');

  const queue = el('div', { class: 'upload-queue', id: 'uploadQueue' });
  const confirm = el('div', { class: 'upload-confirm', id: 'uploadConfirm' });
  const recent = el('div', { class: 'panel', id: 'uploadRecentPanel' },
    el('h3', null, 'Recent uploads'),
    el('div', { class: 'loading' }, 'Loading…'),
  );

  card.appendChild(drop);
  card.appendChild(fileInput);
  card.appendChild(el('label', { class: 'field-label', style: { marginTop: '14px' } }, 'Note (optional)'));
  card.appendChild(noteInput);
  card.appendChild(el('div', { class: 'upload-actions' }, submit));
  card.appendChild(queue);
  card.appendChild(confirm);
  root.appendChild(card);
  root.appendChild(recent);

  let staged = [];
  function refreshQueue() {
    queue.innerHTML = '';
    if (!staged.length) return;
    queue.appendChild(el('div', { class: 'queue-head' }, 'Staged: ' + staged.length + ' file(s)'));
    staged.forEach((f, i) => {
      queue.appendChild(el('div', { class: 'queue-row' },
        el('div', { class: 'queue-name' }, f.name),
        el('div', { class: 'queue-meta' }, fmtBytes(f.size)),
        el('button', { class: 'queue-x', onclick: () => { staged.splice(i, 1); refreshQueue(); } }, '✕'),
      ));
    });
  }

  function take(files) {
    for (const f of files) {
      // Encryption + base64 wrapping inflates the GitHub PUT body ~2.4x, and the
      // contents API caps out around 50MB — reject early with a clear message.
      if (f.size > 20 * 1024 * 1024) {
        toast(f.name + ' is ' + fmtBytes(f.size) + ' — over the 20 MB upload limit.', 'warn');
        continue;
      }
      staged.push(f);
    }
    refreshQueue();
  }
  fileInput.addEventListener('change', () => take(fileInput.files));
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    take(e.dataTransfer.files);
  });

  submit.addEventListener('click', async () => {
    if (!staged.length) { toast('Pick at least one file.', 'warn'); return; }
    submit.disabled = true; submit.textContent = 'Uploading…';
    confirm.innerHTML = '';
    const category = 'inbox';
    const note = noteInput.value.trim();
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const uploadedItems = [];
    const usedPaths = new Set();
    try {
      // iterate over a copy; remove each file from `staged` as it lands so a
      // retry after a mid-batch failure only re-sends what actually failed
      for (const f of staged.slice()) {
        const safe = slugify(f.name.replace(/\.[^.]+$/, '')) || 'file';
        const ext = (f.name.match(/\.[^.]+$/) || [''])[0].toLowerCase();
        const base = 'billing/uploads/' + category + '/' + stamp + '__' + State.session.username + '__';
        // Guarantee a unique path within the batch — all files share one `stamp`,
        // so two names that slugify the same would otherwise collide and overwrite.
        let path = base + safe + ext;
        for (let n = 2; usedPaths.has(path); n++) path = base + safe + '-' + n + ext;
        usedPaths.add(path);
        const buf = await f.arrayBuffer();
        const kdf = State.session && State.session.kdfInput;
        if (!kdf) throw new Error('No session key — refusing to upload unencrypted');
        // Encrypt bytes by base64ing them into a JSON wrapper, then encrypting the wrapper.
        const blob = await AsaCrypto.encryptJSON(
          { b64: bufferToBase64(buf), name: f.name, type: f.type || '' },
          kdf
        );
        const b64 = btoa(JSON.stringify(blob));
        const resp = await ghPutBlob(path, b64, 'billing upload (enc): ' + f.name);
        staged = staged.filter((x) => x !== f);
        refreshQueue();
        // Small spacing between commits to the same branch cuts down on the
        // 409s GitHub returns when commits land faster than its ref updates.
        await new Promise((r) => setTimeout(r, 250));
        uploadedItems.push({
          path, name: f.name, size: f.size, category,
          sha: (resp && resp.content && resp.content.sha) || null,
          commit: (resp && resp.commit && resp.commit.sha) ? resp.commit.sha.slice(0, 7) : null,
          ts: Date.now(),
        });
      }
      if (note) {
        await postComment({
          kind: 'upload_note',
          section: category,
          author: State.session.username,
          authorType: 'owner',
          text: note,
          refs: uploadedItems.map((u) => u.path),
        });
      }
      toast('Uploaded ' + uploadedItems.length + ' file(s).', 'ok');
      staged = []; refreshQueue();
      noteInput.value = '';
      renderUploadConfirmation(confirm, uploadedItems, !!note);
      loadRecentUploads(recent);
    } catch (e) {
      const done = uploadedItems.length, left = staged.length;
      const headMsg = done
        ? '✕ Uploaded ' + done + ' of ' + (done + left) + ' — failed on "' + (staged[0] && staged[0].name) + '"'
        : '✕ Upload failed';
      toast((done ? 'Partial upload — ' + done + ' landed, ' + left + ' left. ' : 'Upload failed: ') + e.message, 'err');
      confirm.innerHTML = '';
      confirm.appendChild(el('div', { class: 'confirm-card err' },
        el('div', { class: 'confirm-head' }, headMsg),
        el('div', { class: 'confirm-body' }, String(e.message || e) +
          (done ? ' — the ' + done + ' uploaded file(s) are committed; click Upload again to retry only the rest.' : '')),
      ));
    } finally {
      submit.disabled = false; submit.textContent = 'Upload';
    }
  });

  loadRecentUploads(recent);
}

function renderUploadConfirmation(host, items, hadNote) {
  host.innerHTML = '';
  const card = el('div', { class: 'confirm-card ok' },
    el('div', { class: 'confirm-head' }, '✓ Uploaded — committed to repo'),
    el('div', { class: 'confirm-sub' }, items.length + ' file' + (items.length === 1 ? '' : 's') + ' saved' + (hadNote ? ' · note posted to Comments' : '') + ' · I will process these on the next loop tick'),
  );
  const list = el('div', { class: 'confirm-list' });
  items.forEach((u) => {
    list.appendChild(el('div', { class: 'confirm-row' },
      el('div', { class: 'confirm-icon' }, '📄'),
      el('div', { class: 'confirm-main' },
        el('div', { class: 'confirm-name' }, u.name),
        el('div', { class: 'confirm-meta' },
          el('span', { class: 'pill' }, u.category),
          ' · ', fmtBytes(u.size),
          u.commit ? ' · commit ' + u.commit : '',
          ' · just now',
        ),
      ),
      el('a', { class: 'btn btn-ghost btn-sm', href: 'https://github.com/' + State.session.owner + '/' + State.session.repo + '/blob/main/' + u.path, target: '_blank', rel: 'noopener' }, 'View'),
    ));
  });
  card.appendChild(list);
  host.appendChild(card);
}

async function loadRecentUploads(host) {
  host.innerHTML = '';
  host.appendChild(el('h3', null, 'Recent uploads'));
  const loading = el('div', { class: 'loading' }, 'Listing…');
  host.appendChild(loading);
  const all = [];
  let listError = null;
  const lists = await Promise.all(SECTIONS.map((s) =>
    ghListDir('billing/uploads/' + s.key).catch((e) => { listError = e; return []; })));
  lists.forEach((items, i) => {
    for (const it of items) {
      if (it.type !== 'file' || it.name === '.gitkeep') continue;
      all.push({ section: SECTIONS[i].key, name: it.name, path: it.path, size: it.size, sha: it.sha, url: it.download_url });
    }
  });
  loading.remove();
  if (listError && !all.length) {
    host.appendChild(el('div', { class: 'muted', style: { padding: '8px 0' } },
      'Couldn\'t list uploads: ' + (listError.message || listError)));
    return;
  }
  if (!all.length) {
    host.appendChild(el('div', { class: 'muted', style: { padding: '8px 0' } }, 'No files uploaded yet.'));
    return;
  }
  all.sort((a, b) => (a.name < b.name ? 1 : -1));
  const tbody = el('tbody');
  all.slice(0, 12).forEach((f) => {
    const ts = parseUploadStamp(f.name);
    tbody.appendChild(el('tr', null,
      el('td', null, el('a', { href: '#', class: 'doc-link', onclick: (e) => { e.preventDefault(); openUploadedFile(f); } }, prettyFileName(f.name))),
      el('td', null, el('span', { class: 'pill' }, f.section)),
      el('td', { class: 'num' }, fmtBytes(f.size)),
      el('td', null, ts ? fmtRelative(ts) : '—'),
    ));
  });
  host.appendChild(el('table', { class: 'data-table' },
    el('thead', null, el('tr', null,
      el('th', null, 'File'), el('th', null, 'Category'),
      el('th', { class: 'num' }, 'Size'), el('th', null, 'When'),
    )),
    tbody,
  ));
  if (all.length > 12) {
    host.appendChild(el('p', { class: 'muted', style: { marginTop: '10px' } },
      'Showing 12 of ', String(all.length), '. Full list in the ',
      el('a', { href: '#', class: 'doc-link', onclick: (e) => { e.preventDefault(); navigate('documents'); } }, 'Documents'),
      ' tab.'
    ));
  }
}

function bufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}

// Fetch + (maybe) decrypt an uploaded file, then trigger a browser download
// with the original filename. Plaintext files still work transparently.
async function openUploadedFile(file) {
  try {
    const r = await fetch(file.url, { cache: 'no-store' });
    if (!r.ok) throw new Error('fetch ' + r.status);
    const buf = await r.arrayBuffer();
    let outBytes;
    let isEnc = false;
    let inner = null;
    // Detect the {salt,iv,ct,iter} blob shape FIRST; only non-blob bodies fall
    // through as plaintext. A blob that fails to decrypt must error loudly —
    // never hand the user ciphertext disguised as a real file.
    let parsed = null;
    try { parsed = JSON.parse(new TextDecoder().decode(buf)); } catch { /* not JSON → plaintext file */ }
    if (parsed && isPwBlob(parsed)) {
      const kdf = State.session && State.session.kdfInput;
      if (!kdf) throw new Error('No password in session — sign out and back in.');
      inner = await AsaCrypto.decryptJSON(parsed, kdf);
      if (!inner || !inner.b64) throw new Error('Decryption failed — wrong password for this file?');
      const bin = atob(inner.b64);
      const u8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
      outBytes = u8;
      isEnc = true;
    } else {
      outBytes = new Uint8Array(buf);
    }
    const a = document.createElement('a');
    // the encrypted wrapper preserves the user's original filename + MIME type
    const blob = new Blob([outBytes], { type: (inner && inner.type) || '' });
    a.href = URL.createObjectURL(blob);
    a.download = (inner && inner.name) || prettyFileName(file.name);
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
    if (isEnc) toast('Decrypted ' + a.download, 'ok');
  } catch (e) {
    toast('Open failed: ' + (e.message || e), 'err');
  }
}

// ============================================================
// DOCUMENTS VIEW (browse uploaded files)
// ============================================================
async function renderDocuments(root) {
  root.innerHTML = '';
  root.appendChild(pageHead('All uploads', 'Documents', 'Every file dropped into the billing portal, newest first.'));

  const loading = el('div', { class: 'loading' }, 'Listing files…');
  root.appendChild(loading);

  const all = [];
  let listError = null;
  // ghListDir already maps 404 → []; any other failure (revoked PAT, rate
  // limit, network) must NOT masquerade as "no documents"
  const lists = await Promise.all(SECTIONS.map((s) =>
    ghListDir('billing/uploads/' + s.key).catch((e) => { listError = e; return []; })));
  lists.forEach((items, i) => {
    for (const it of items) {
      if (it.type !== 'file' || it.name === '.gitkeep') continue;
      all.push({ section: SECTIONS[i].key, name: it.name, path: it.path, size: it.size, sha: it.sha, url: it.download_url });
    }
  });
  loading.remove();
  if (listError) {
    root.appendChild(el('div', { class: 'panel' },
      el('p', { class: 'muted' }, 'Couldn\'t list files: ' + (listError.message || listError) + ' — the GitHub token may be expired or rate-limited.')));
    if (!all.length) return;
  }
  if (!all.length) { root.appendChild(emptyState('No documents yet.')); return; }
  all.sort((a, b) => (a.name < b.name ? 1 : -1)); // ISO timestamp prefix → reverse-chrono

  const panel = el('div', { class: 'panel' },
    el('table', { class: 'data-table' },
      el('thead', null, el('tr', null,
        el('th', null, 'File'),
        el('th', null, 'Category'),
        el('th', { class: 'num' }, 'Size'),
        el('th', null, 'When'),
        el('th', null, ''),
      )),
      el('tbody', null, ...all.map((f) => {
        const ts = parseUploadStamp(f.name);
        return el('tr', null,
          el('td', null, el('a', { href: '#', class: 'doc-link', onclick: (e) => { e.preventDefault(); openUploadedFile(f); } }, prettyFileName(f.name))),
          el('td', null, el('span', { class: 'pill' }, f.section)),
          el('td', { class: 'num' }, fmtBytes(f.size)),
          el('td', null, ts ? fmtRelative(ts) : '—'),
          el('td', null, el('button', { class: 'btn btn-ghost btn-sm', onclick: async () => {
            if (!confirm('Delete ' + f.name + '?')) return;
            try { await ghDelete(f.path, f.sha, 'billing delete: ' + f.name); toast('Deleted.', 'ok'); renderDocuments(root); }
            catch (e) { toast('Delete failed: ' + e.message, 'err'); }
          }}, 'Delete')),
        );
      })),
    )
  );
  root.appendChild(panel);
}
function parseUploadStamp(name) {
  const m = name.match(/^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}(?:-\d+)?Z)/);
  if (!m) return null;
  return m[1].replace(/^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})(?:-(\d+))?Z$/,
    (_, d, h, mi, s, ms) => d + 'T' + h + ':' + mi + ':' + s + (ms ? '.' + ms : '') + 'Z');
}
function prettyFileName(name) {
  return name.replace(/^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}(?:-\d+)?Z__/, '').replace(/^[^_]+__/, '');
}

// ============================================================
// COMMENTS
// ============================================================
async function renderComments(root) {
  root.innerHTML = '';
  root.appendChild(pageHead('Discussion', 'Comments',
    'Talk to me about what you uploaded. I post AI insights here too — leave a comment and the next loop tick will reply.'));

  const composer = el('div', { class: 'panel' },
    el('label', { class: 'field-label' }, 'New comment'),
    el('textarea', { id: 'newComment', class: 'textarea', placeholder: 'Ask a question or leave a note — e.g. "Why did AR jump this week?"' }),
    el('div', { class: 'upload-actions' },
      el('button', { class: 'btn btn-primary', id: 'postCommentBtn' }, 'Post comment'),
    ),
  );
  root.appendChild(composer);

  $('#postCommentBtn').onclick = async () => {
    const text = $('#newComment').value.trim();
    if (!text) { toast('Type a comment first.', 'warn'); return; }
    $('#postCommentBtn').disabled = true;
    try {
      const posted = await postComment({
        kind: 'comment',
        section: null,
        author: State.session.username,
        authorType: 'owner',
        text,
        refs: [],
      });
      $('#newComment').value = '';
      toast('Comment posted.', 'ok');
      // Optimistic insert: prepend the new comment so it stays visible even
      // while GitHub's contents listing is still catching up (the API is
      // eventually consistent — directory listings can lag by 5-20s after PUT).
      State._optimisticComments = State._optimisticComments || {};
      State._optimisticComments[posted.id] = posted;
      await reloadCommentList(listHost);
      // Re-poll once after a delay to merge any server-side changes once GH catches up.
      setTimeout(() => { if (State.view === 'comments') reloadCommentList(listHost); }, 8000);
    } catch (e) {
      toast('Post failed: ' + e.message, 'err');
    } finally {
      $('#postCommentBtn').disabled = false;
    }
  };

  const listHost = el('div', { class: 'panel comment-list' });
  root.appendChild(listHost);
  await reloadCommentList(listHost);
}

async function reloadCommentList(host) {
  host.innerHTML = '<div class="loading">Loading comments…</div>';
  const kdf = State.session && State.session.kdfInput;
  const items = await ghListDir('billing/comments').catch(() => []);
  const files = items.filter((i) => i.type === 'file' && i.name.endsWith('.json'));
  const out = [];
  const seenIds = new Set();
  for (const f of files) {
    try {
      const r = await fetch(f.download_url, { cache: 'no-store' });
      const raw = await r.json();
      let j = raw;
      if (isPwBlob(raw)) {
        if (!kdf) continue;
        j = await AsaCrypto.decryptJSON(raw, kdf);
        if (j === null) { console.warn('comment decrypt failed for', f.name); continue; }
      }
      j._path = f.path; j._sha = f.sha;
      if (j.id) seenIds.add(j.id);
      out.push(j);
    } catch (e) { console.warn('comment fetch failed for', f.name, e); }
  }
  // Merge in any optimistic comments the server hasn't surfaced yet.
  const opt = State._optimisticComments || {};
  for (const id of Object.keys(opt)) {
    if (seenIds.has(id)) { delete opt[id]; continue; } // server has it now
    out.push(opt[id]);
  }
  out.sort((a, b) => (b.ts || 0) - (a.ts || 0));
  host.innerHTML = '';
  if (!out.length) { host.appendChild(emptyState('No comments yet.')); return; }
  out.forEach((c) => host.appendChild(renderCommentCard(c)));
}

function renderCommentCard(c) {
  const isAI = (c.authorType === 'ai' || c.kind === 'ai_insight' || c.author === 'ai');
  return el('div', { class: 'comment-card ' + (isAI ? 'ai' : 'human') },
    el('div', { class: 'comment-head' },
      el('div', { class: 'comment-author' },
        el('span', { class: 'comment-avatar ' + (isAI ? 'ai' : '') }, (c.author || '?').slice(0, 2).toUpperCase()),
        el('div', null,
          el('div', { class: 'comment-name' }, isAI ? 'AI Insight' : (c.author || 'owner')),
          el('div', { class: 'comment-when' }, fmtRelative(c.iso || (c.ts ? new Date(c.ts).toISOString() : null))),
        )
      ),
      c.section ? el('span', { class: 'pill' }, c.section) : null,
    ),
    el('div', { class: 'comment-body' }, c.text || ''),
    (c.refs && c.refs.length) ? el('div', { class: 'comment-refs' },
      ...c.refs.map((p) => el('a', { href: 'https://github.com/' + State.session.owner + '/' + State.session.repo + '/blob/main/' + p, target: '_blank', rel: 'noopener', class: 'doc-link' }, prettyFileName(p.split('/').pop()))),
    ) : null,
  );
}

async function postComment(c) {
  const ts = Date.now();
  const iso = new Date(ts).toISOString();
  const obj = {
    id: ts + '-' + Math.random().toString(36).slice(2, 6),
    ts, iso,
    ...c,
  };
  const kdf = State.session && State.session.kdfInput;
  if (!kdf) throw new Error('No session key — refusing to write comment unencrypted');
  const path = 'billing/comments/' + ts + '-' + obj.id.split('-')[1] + '.json';
  const body = JSON.stringify(await AsaCrypto.encryptJSON(obj, kdf));
  await ghPutText(path, body, 'billing comment: ' + (c.kind || 'comment'));
  return obj;
}

// ============================================================
// AI INSIGHTS
// ============================================================
async function renderInsights(root) {
  const data = await loadData(true);
  root.innerHTML = '';
  root.appendChild(pageHead('AI generated', 'Insights',
    data && data.lastUpdated ? 'Loop last ran ' + fmtRelative(data.lastUpdated) : 'Loop has not run yet'));

  if (!data || !data.insights || !data.insights.length) {
    root.appendChild(emptyState('No insights yet. The loop publishes them after processing uploads.'));
    return;
  }
  const panel = el('div', { class: 'panel' });
  data.insights.forEach((i) => {
    panel.appendChild(el('div', { class: 'insight-item' },
      el('div', { class: 'insight-date' }, fmtRelative(i.ts)),
      el('div', { class: 'insight-text' }, i.text || ''),
      i.refs && i.refs.length ? el('div', { class: 'comment-refs' },
        ...i.refs.map((p) => el('span', { class: 'pill' }, prettyFileName(p.split('/').pop()))),
      ) : null,
    ));
  });
  root.appendChild(panel);
}

// ============================================================
// SETTINGS
// ============================================================
async function renderSettings(root) {
  root.innerHTML = '';
  root.appendChild(pageHead('Account', 'Settings'));

  const s = State.session;
  const panel = el('div', { class: 'panel' },
    el('h3', null, 'Session'),
    el('p', null, 'Signed in as ', el('strong', null, s.username), ' (', s.role, ')'),
    el('p', null, 'GitHub: ', el('code', null, s.owner + '/' + s.repo)),
    el('h3', null, 'Reset'),
    el('p', { class: 'muted' }, 'To rotate credentials or add users, run ', el('a', { href: 'setup.html', class: 'doc-link' }, '/billing/setup.html'), ' and replace vault.json.'),
  );
  root.appendChild(panel);
}

// ============================================================
// init
// ============================================================
function init() {
  const form = $('#loginForm');
  if (form) {
    form.addEventListener('submit', handleLogin);
    window.__dnzLoginHandlerAttached = true;
  }
  // Saved sessions carry no secrets (see saveSession) — a reload re-prompts
  // for the password; we just prefill the username for convenience.
  const s = loadSession();
  if (s && s.username && form && form.username) form.username.value = s.username;
}
// ============================================================
// BILL'S CORNER — origination/commission sheets + A/R as Excel
//
// The loop generates encrypted XLSX blobs under billing/bills-corner/ (from
// payment-allocation uploads via PAYMENT_ALLOCATION_GOLDEN_PROMPT.md, plus A/R
// from data.json) and registers them in an encrypted manifest. This view lists
// them and decrypts + downloads in the browser. See billing/AGENT.md.
// ============================================================
// Interactive commission ledger: attorneys (rows) × pay periods (columns), each cell = that
// attorney's pay that period (billing-user commission + originator credits). Sortable columns,
// click a row to expand the billing/originator split, a stacked-bar chart of top earners, and a
// coverage banner. A new column appears whenever a payment-allocation report is processed.
let _ledgerChart = null;
function renderCommissionLedger(root, m) {
  const periods = (m && m.periods) || [];
  const rows = ((m && m.attorneys) || []).slice();
  if (!periods.length || !rows.length) return;
  const firm = m.firmTotals || {}, cov = m.coverage || {};
  const panel = el('div', { class: 'panel ledger-panel' });
  panel.appendChild(el('div', { class: 'panel-head' },
    el('h3', null, 'Attorney commissions by pay period'),
    el('span', { class: 'muted', style: { fontSize: '12px' } },
      rows.length + ' attorneys · ' + periods.length + ' pay periods · ' +
      fmtMoneyFull(m.grandTotal || 0) + ' paid · as of ' + fmtDate(m.asOf))));
  if (cov.note) panel.appendChild(el('div', { class: 'ledger-note' }, el('strong', null, 'Coverage: '), cov.note));

  // ---- stacked-bar chart: top earners, billing vs originator ----
  const chartH = Math.max(220, Math.min(rows.length, 12) * 28 + 64);
  if (window.Chart) panel.appendChild(el('div', { class: 'ledger-chart-wrap', style: { height: chartH + 'px', marginTop: '14px' } }, el('canvas', { id: 'ledgerChart' })));
  panel.appendChild(el('p', { class: 'muted', style: { fontSize: '11px', margin: '8px 2px 12px' } },
    'Click a column header to sort · click an attorney to see their billing vs originator split.'));

  // ---- interactive table ----
  const state = { sort: 'ytd', dir: -1 };
  const expanded = new Set();
  const cellPay = (r, id) => (r.cells[id] || {}).pay || 0;
  // A/R tie-in (schema 3): each attorney may carry their originated-A/R book
  // and the est. origination credit waiting in it at their other_work rate
  const hasAR = rows.some((r) => r.ar);
  const sortVal = (r, k) => k === 'name' ? r.name.toLowerCase() : k === 'ytd' ? r.ytd
    : k === 'arBook' ? ((r.ar && r.ar.book) || 0) : k === 'arCredit' ? ((r.ar && r.ar.estCredit) || 0) : cellPay(r, k);
  const cols = [{ key: 'name', label: 'Attorney', cls: 'ledger-name' },
    ...periods.map((p) => ({ key: p.id, label: p.label, cls: 'num', title: p.start + ' → ' + p.end })),
    { key: 'ytd', label: 'Paid YTD', cls: 'num ledger-ytd' },
    ...(hasAR ? [
      { key: 'arBook', label: 'A/R book', cls: 'num', title: 'Outstanding A/R on matters they originated (as of ' + fmtDate(m.arAsOf) + ')' },
      { key: 'arCredit', label: 'Credit in A/R', cls: 'num', title: 'Est. origination credit at their rate if that A/R is collected' },
    ] : [])];
  const headTr = el('tr');
  cols.forEach((c) => {
    const th = el('th', { class: c.cls + ' ledger-sortable', title: c.title || 'Click to sort' }, c.label);
    th.addEventListener('click', () => { if (state.sort === c.key) state.dir *= -1; else { state.sort = c.key; state.dir = c.key === 'name' ? 1 : -1; } renderBody(); });
    headTr.appendChild(th);
  });
  const thead = el('thead', null, headTr);
  const tbody = el('tbody');
  const tfoot = el('tfoot', null, el('tr', { class: 'ledger-total' },
    el('td', { class: 'ledger-name bold' }, 'Firm total'),
    ...periods.map((p) => el('td', { class: 'num bold' }, fmtMoneyFull(firm[p.id] || 0))),
    el('td', { class: 'num ledger-ytd bold' }, fmtMoneyFull(m.grandTotal || 0)),
    ...(hasAR ? [
      el('td', { class: 'num bold' }, fmtMoneyFull(rows.reduce((s, r) => s + ((r.ar && r.ar.book) || 0), 0))),
      el('td', { class: 'num bold' }, fmtMoneyFull(rows.reduce((s, r) => s + ((r.ar && r.ar.estCredit) || 0), 0))),
    ] : [])));
  function renderBody() {
    rows.sort((a, b) => { const av = sortVal(a, state.sort), bv = sortVal(b, state.sort); return (av < bv ? -1 : av > bv ? 1 : 0) * state.dir; });
    [...headTr.children].forEach((th, i) => { th.textContent = cols[i].label + (cols[i].key === state.sort ? (state.dir < 0 ? ' ▼' : ' ▲') : ''); });
    tbody.innerHTML = '';
    rows.forEach((r) => {
      const open = expanded.has(r.key);
      const tr = el('tr', { class: 'ledger-row' + (open ? ' is-open' : '') },
        el('td', { class: 'ledger-name' }, el('span', { class: 'ledger-caret' }, open ? '▾ ' : '▸ '), r.name),
        ...periods.map((p) => { const v = cellPay(r, p.id); return el('td', { class: 'num' + (v ? '' : ' ledger-zero') }, v ? fmtMoneyFull(v) : '—'); }),
        el('td', { class: 'num ledger-ytd bold' }, fmtMoneyFull(r.ytd)),
        ...(hasAR ? [
          el('td', { class: 'num' + (r.ar ? '' : ' ledger-zero') }, r.ar ? fmtMoneyFull(r.ar.book) : '—'),
          el('td', { class: 'num' + (r.ar && r.ar.estCredit ? '' : ' ledger-zero') }, r.ar && r.ar.estCredit ? '~' + fmtMoneyFull(r.ar.estCredit) : '—'),
        ] : []));
      tr.addEventListener('click', () => { if (open) expanded.delete(r.key); else expanded.add(r.key); renderBody(); });
      tbody.appendChild(tr);
      if (open) {
        const perP = periods.map((p) => { const c = r.cells[p.id]; return (c && c.pay) ? el('span', { class: 'ledger-detail-p' }, p.label + ': ' + fmtMoneyFull(c.pay) + '  (' + fmtMoneyFull(c.user) + ' billing + ' + fmtMoneyFull(c.orig) + ' orig)') : null; }).filter(Boolean);
        const arLine = r.ar ? el('div', { class: 'ledger-detail-pers', style: { marginTop: '6px' } },
          el('span', { class: 'ledger-detail-p' },
            'A/R book ' + fmtMoneyFull(r.ar.book) + ' (as of ' + fmtDate(r.ar.asOf) + ')' +
            (r.ar.b91 ? ' · ' + fmtMoneyFull(r.ar.b91) + ' of it is 90+ days old' : '') +
            (r.ar.estCredit ? ' · collecting it would pay them ~' + fmtMoneyFull(r.ar.estCredit) +
              ' in origination credit (' + Math.round(r.ar.ratePct * 100) + '%)' +
              (r.ar.estCredit91 ? ', of which ~' + fmtMoneyFull(r.ar.estCredit91) + ' is at risk in the 90+ bucket' : '')
              : ''))) : null;
        tbody.appendChild(el('tr', { class: 'ledger-detail' }, el('td', { colspan: String(cols.length) },
          el('div', { class: 'ledger-detail-row' },
            el('span', { class: 'ledger-chip ledger-chip-user' }, 'Billing commission ' + fmtMoneyFull(r.ytdUser)),
            el('span', { class: 'ledger-chip ledger-chip-orig' }, 'Originator credit ' + fmtMoneyFull(r.ytdOrig)),
            r.ar && r.ar.estCredit ? el('span', { class: 'ledger-chip' }, 'Est. credit waiting in A/R ~' + fmtMoneyFull(r.ar.estCredit)) : null),
          el('div', { class: 'ledger-detail-pers' }, ...perP),
          arLine)));
      }
    });
  }
  renderBody();
  const wrap = el('div', { class: 'ledger-wrap' });
  wrap.appendChild(el('table', { class: 'data-table ledger-table' }, thead, tbody, tfoot));
  panel.appendChild(wrap);
  if (m.note) panel.appendChild(el('p', { class: 'muted', style: { fontSize: '12px', marginTop: '10px' } }, m.note));
  root.appendChild(panel);

  // init Chart.js now that the canvas is in the DOM
  const cv = panel.querySelector('#ledgerChart');
  if (cv && window.Chart) {
    const top = rows.slice().sort((a, b) => b.ytd - a.ytd).slice(0, 12);
    if (_ledgerChart) { try { _ledgerChart.destroy(); } catch (e) {} _ledgerChart = null; }
    _ledgerChart = new Chart(cv, {
      type: 'bar',
      data: { labels: top.map((r) => r.name), datasets: [
        { label: 'Billing commission', data: top.map((r) => Math.round(r.ytdUser)), backgroundColor: '#2bb673', borderWidth: 0, borderRadius: 2 },
        { label: 'Originator credit', data: top.map((r) => Math.round(r.ytdOrig)), backgroundColor: '#b08a3a', borderWidth: 0, borderRadius: 2 },
        // the tie to A/R: estimated origination credit still sitting uncollected
        { label: 'Est. credit waiting in A/R', data: top.map((r) => Math.round((r.ar && r.ar.estCredit) || 0)), backgroundColor: 'rgba(176,138,58,.25)', borderColor: '#b08a3a', borderWidth: 1, borderRadius: 2 },
      ] },
      options: {
        indexAxis: 'y', responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        plugins: { legend: { position: 'top', labels: { boxWidth: 12, font: { size: 11 } } },
          tooltip: { callbacks: { label: (it) => '  ' + it.dataset.label + ': ' + fmtMoneyFull(it.parsed.x), footer: (items) => 'YTD: ' + fmtMoneyFull(items.reduce((s, i) => s + (i.parsed.x || 0), 0)) } } },
        scales: { x: { stacked: true, ticks: { callback: (v) => '$' + (v / 1000).toFixed(0) + 'k', font: { size: 10 }, color: '#5a6b85' }, grid: { color: 'rgba(13,27,42,.06)' } },
          y: { stacked: true, ticks: { font: { size: 11 }, color: '#324158' }, grid: { display: false } } },
      },
    });
  }
}

async function renderBillsCorner(root) {
  root.innerHTML = '';
  root.appendChild(pageHead("Bill's Corner",
    'Origination payments & commission ledger',
    'A running ledger of what each attorney is paid per pay period under the firm allocation rules — a new column lands every time a payment-allocation report is processed. Downloadable workbooks below.'));

  const kdf = State.session && State.session.kdfInput;

  // 1) Commission ledger matrix (attorneys × pay periods)
  let ledgerShown = false;
  let matrixPeriods = [];
  try {
    const r = await fetch('bills-corner/commission-matrix.json?_=' + Date.now(), { cache: 'no-store' });
    if (r.ok) {
      const raw = await r.json();
      const m = isPwBlob(raw) ? await AsaCrypto.decryptJSON(raw, kdf) : raw;
      if (m && m.periods && m.periods.length) { renderCommissionLedger(root, m); ledgerShown = true; matrixPeriods = m.periods; }
      else if (isPwBlob(raw) && !m) {
        // decrypt failed — say so instead of silently hiding the ledger
        root.appendChild(el('div', { class: 'panel' },
          el('p', { class: 'muted' }, 'Commission ledger could not be decrypted with this session. Log out and back in (the session password is the decryption key).')));
        ledgerShown = true;
      }
    }
  } catch (e) { /* no matrix yet */ }

  // 1b) Time-frame workbook builder — pick any date range, get the
  // golden-prompt-format multi-tab XLSX built in the browser from the
  // encrypted row-level allocation data.
  renderTimeframePicker(root, matrixPeriods);

  // 2) Downloadable workbooks (manifest)
  let manifest = [];
  try {
    const r = await fetch('bills-corner/manifest.json?_=' + Date.now(), { cache: 'no-store' });
    if (r.ok) { const raw = await r.json(); manifest = isPwBlob(raw) ? await AsaCrypto.decryptJSON(raw, kdf) : raw; }
  } catch (e) { /* no manifest yet */ }
  manifest = manifest || [];
  if (!manifest.length) {
    if (!ledgerShown) root.appendChild(emptyState('No sheets yet. Drop a payment-allocation report in Upload Reports — the loop reads the golden-prompt rules and generates the origination workbook here.'));
    return;
  }
  manifest.sort((a, b) => (String(a.generatedAt) < String(b.generatedAt) ? 1 : -1));

  for (const [kind, title, hint] of [
    ['commission', 'Origination / commission payments', 'One workbook per allocation period — a tab per billing attorney.'],
    ['ar', 'Accounts Receivable', 'A/R aging exported to Excel from the latest data.'],
  ]) {
    const items = manifest.filter((m) => m.kind === kind);
    if (!items.length) continue;
    root.appendChild(el('div', { class: 'panel' },
      el('div', { class: 'panel-head' }, el('h3', null, title),
        el('span', { class: 'muted', style: { fontSize: '12px' } }, hint)),
      el('table', { class: 'data-table' },
        el('thead', null, el('tr', null,
          el('th', null, 'Sheet'), el('th', null, 'Period'),
          el('th', { class: 'num' }, kind === 'commission' ? 'Attorneys' : ''),
          // commission workbooks total only the billing-user side; the ledger
          // above includes originator credits, so label the bases apart
          el('th', { class: 'num' }, kind === 'commission' ? 'Billing commission' : 'Total'), el('th', null, ''))),
        el('tbody', null, ...items.map((m) => el('tr', null,
          el('td', { class: 'bold' }, m.label || m.filename),
          el('td', null, m.period || '—'),
          el('td', { class: 'num' }, kind === 'commission' ? String(m.attorneys || '—') : ''),
          el('td', { class: 'num' }, m.grandTotal != null ? fmtMoneyFull(m.grandTotal) : '—'),
          el('td', null, el('button', { class: 'btn btn-primary btn-sm', onclick: () => downloadBillsSheet(m) }, '⬇ Download Excel'))))))));
  }
}

// ---- time-frame workbook builder ----
// Rows live in bills-corner/allocation-rows.json (encrypted): every
// payment-allocation row with its golden-prompt user_pct/orig_pct already
// computed. We filter by Payment/Credit Note date and assemble the standard
// multi-tab origination workbook entirely client-side via SheetJS.
let _allocRowsCache = null;
async function loadAllocationRows() {
  if (_allocRowsCache) return _allocRowsCache;
  const r = await fetch('bills-corner/allocation-rows.json?_=' + Date.now(), { cache: 'no-store' });
  if (!r.ok) throw new Error('allocation rows not available (HTTP ' + r.status + ')');
  const raw = await r.json();
  const kdf = State.session && State.session.kdfInput;
  const doc = isPwBlob(raw) ? await AsaCrypto.decryptJSON(raw, kdf) : raw;
  if (!doc || !doc.rows) throw new Error('could not decrypt allocation rows — sign out and back in');
  _allocRowsCache = doc;
  return doc;
}

function renderTimeframePicker(root, periods) {
  const start = el('input', { type: 'date', class: 'tf-date' });
  const end = el('input', { type: 'date', class: 'tf-date' });
  const preset = el('select', { class: 'tf-date' },
    el('option', { value: '' }, 'Pick a pay period…'),
    el('option', { value: 'all' }, 'Everything on file'),
    ...(periods || []).map((p) => el('option', { value: p.start + '|' + p.end }, p.label + '  (' + p.start + ' → ' + p.end + ')')));
  const btn = el('button', { class: 'btn btn-primary btn-sm' }, '⬇ Build Excel for range');
  const status = el('span', { class: 'muted', style: { fontSize: '12px', marginLeft: '10px' } });

  loadAllocationRows().then((doc) => {
    start.min = end.min = doc.minDate; start.max = end.max = doc.maxDate;
    start.value = doc.minDate; end.value = doc.maxDate;
    status.textContent = doc.rowCount + ' allocation rows on file, ' + fmtDate(doc.minDate) + ' – ' + fmtDate(doc.maxDate) + '.';
  }).catch((e) => { status.textContent = 'Row data unavailable: ' + (e.message || e); });

  preset.addEventListener('change', () => {
    if (!preset.value) return;
    if (preset.value === 'all') {
      if (start.min) { start.value = start.min; end.value = end.max; }
    } else {
      const [s, e2] = preset.value.split('|');
      start.value = s; end.value = e2;
    }
  });

  btn.addEventListener('click', async () => {
    try {
      if (!window.XLSX) throw new Error('Excel library still loading — try again in a second.');
      if (!start.value || !end.value) throw new Error('Pick a start and end date.');
      if (start.value > end.value) throw new Error('Start date is after end date.');
      btn.disabled = true; btn.textContent = 'Building…';
      const doc = await loadAllocationRows();
      const rows = doc.rows.filter((r) => r.d && r.d >= start.value && r.d <= end.value);
      if (!rows.length) throw new Error('No payments in that range — coverage is ' + fmtDate(doc.minDate) + ' – ' + fmtDate(doc.maxDate) + ' (with gaps).');
      const { blob, name, tabs, total } = buildAllocationWorkbook(rows, start.value, end.value);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 60000);
      toast('Downloaded ' + name + ' — ' + tabs + ' attorneys, ' + fmtMoneyFull(total) + ' billing commission.', 'ok');
    } catch (e) { toast(e.message || String(e), 'err'); }
    finally { btn.disabled = false; btn.textContent = '⬇ Build Excel for range'; }
  });

  root.appendChild(el('div', { class: 'panel' },
    el('div', { class: 'panel-head' },
      el('h3', null, 'Download by time frame'),
      el('span', { class: 'muted', style: { fontSize: '12px' } },
        'Any date range — the workbook is computed on the spot under the firm allocation rules.')),
    el('div', { style: { display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' } },
      preset, el('span', { class: 'muted' }, 'or'),
      start, el('span', { class: 'muted' }, 'to'), end, btn),
    el('p', { class: 'muted', style: { fontSize: '12px', marginTop: '10px' } }, status)));
}

const ACCT_FMT_XLSX = '_(* #,##0.00_);_(* (#,##0.00);_(* "-"??_);_(@_)';

// ---- Excel styling (xlsx-js-style) ----------------------------------------
// Gives every browser-generated workbook a consistent, "Cowork-grade" look —
// navy title band, gold header row, hairline-ruled banded body, ruled totals —
// WITHOUT touching any values, formats, or structure. Pass the row roles that
// each builder already knows as it assembles its rows.
const XL = { navy: '14263D', navy2: '22456B', gold: 'B08A3A', goldL: 'F3ECDD',
             white: 'FFFFFF', ink: '1F2A3A', line: 'D9DEE7', band: 'F6F8FB' };
function xlEdge(rgb, style) { return { style: style || 'thin', color: { rgb: rgb || XL.line } }; }
function dnzStyleSheet(ws, opt) {
  if (!ws || !ws['!ref']) return;
  const R = XLSX.utils.decode_range(ws['!ref']);
  const ncols = opt.ncols || (R.e.c + 1);
  const title = new Set(opt.titleRows || []);
  const titleStart = opt.titleStartCol || 0;
  const header = new Set(opt.headerRows || []);
  const total = new Set(opt.totalRows || []);
  const group = new Set(opt.groupRows || []);
  const blank = new Set(opt.blankRows || []);
  const date = new Set(opt.dateRows || []);
  ws['!merges'] = ws['!merges'] || [];
  ws['!rows'] = ws['!rows'] || [];
  let bodyIx = 0;
  for (let r = 0; r <= R.e.r; r++) {
    if (blank.has(r)) { ws['!rows'][r] = { hpt: 6 }; continue; }
    let band = false;
    if (title.has(r)) { ws['!rows'][r] = { hpt: 24 };
      ws['!merges'].push({ s: { r: r, c: titleStart }, e: { r: r, c: ncols - 1 } }); }
    else if (date.has(r)) { ws['!rows'][r] = { hpt: 17 };
      ws['!merges'].push({ s: { r: r, c: titleStart }, e: { r: r, c: ncols - 1 } }); }
    else if (header.has(r)) ws['!rows'][r] = { hpt: 19 };
    else if (!total.has(r) && !group.has(r)) { band = (bodyIx % 2 === 1); bodyIx++; }
    for (let c = 0; c < ncols; c++) {
      const addr = XLSX.utils.encode_cell({ r: r, c: c });
      let cell = ws[addr];
      if (!cell) cell = ws[addr] = { t: 'z' };
      const s = { alignment: { vertical: 'center' } };
      if (title.has(r)) {
        s.font = { bold: true, sz: 13, color: { rgb: XL.white } };
        s.fill = { fgColor: { rgb: XL.navy } };
      } else if (date.has(r)) {
        s.font = { italic: true, bold: true, sz: 10.5, color: { rgb: XL.navy2 } };
        s.fill = { fgColor: { rgb: XL.white } };
        s.alignment = { vertical: 'center', horizontal: 'left' };
        s.border = { bottom: xlEdge(XL.gold) };
      } else if (header.has(r)) {
        s.font = { bold: true, sz: 10, color: { rgb: XL.white } };
        s.fill = { fgColor: { rgb: XL.gold } };
        s.alignment = { vertical: 'center', horizontal: c === 0 ? 'left' : 'center', wrapText: true };
        s.border = { top: xlEdge(XL.gold), bottom: xlEdge(XL.gold),
                     left: xlEdge(XL.white), right: xlEdge(XL.white) };
      } else if (total.has(r)) {
        s.font = { bold: true, sz: 10, color: { rgb: XL.navy } };
        s.fill = { fgColor: { rgb: XL.goldL } };
        s.border = { top: xlEdge(XL.gold, 'medium'), bottom: xlEdge(XL.gold) };
      } else if (group.has(r)) {
        s.font = { bold: true, sz: 10, color: { rgb: XL.navy2 } };
        s.fill = { fgColor: { rgb: XL.band } };
        s.border = { bottom: xlEdge() };
      } else {
        s.font = { sz: 10, color: { rgb: XL.ink } };
        s.fill = { fgColor: { rgb: band ? XL.band : XL.white } };
        s.border = { bottom: xlEdge() };
      }
      if (cell.z) s.numFmt = cell.z;          // keep the accounting format
      cell.s = s;
    }
  }
}
function buildAllocationWorkbook(rows, startIso, endIso) {
  // group by billing user; staff rows (no rate in the table) get no tab,
  // matching the loop-generated workbooks
  const byUser = {};
  rows.forEach((r) => { if (!r.staff) (byUser[r.uk] = byUser[r.uk] || []).push(r); });
  const firstLast = (lastFirst) => {
    const [last, rest] = String(lastFirst).split(',');
    const first = ((rest || '').trim().split(/\s+/) || [''])[0];
    return ((first ? first + ' ' : '') + (last || '').trim()).trim();
  };
  const mdy = (iso) => { const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso); return m ? m[2] + '/' + m[3] + '/' + m[1] : iso; };
  const wb = XLSX.utils.book_new();
  let grand = 0, tabs = 0;
  Object.keys(byUser).sort().forEach((uk) => {
    const list = byUser[uk];
    const fl = firstLast(list[0].u);
    const aoa = [
      [null, 'Origination Payments — ' + fl],
      [null, 'As of ' + fmtDate(startIso) + ' – ' + fmtDate(endIso)],
      ['Payment/Credit Note date', 'User', 'Matter number', 'Originating attorney',
       'Bill issued at date', 'Bill due at date', 'Bill last sent at date', 'Collected hours value',
       'user percentage', 'collected user', 'Collected Originator', 'Originator Percentage'],
    ];
    let totalUser = 0;
    list.forEach((r) => {
      const cu = r.v * r.up; totalUser += cu;
      aoa.push([r.dt || null, r.u, r.m, r.o, r.i || null, r.due || null, r.ls || null,
        r.v, r.up, cu, r.own ? null : r.v * r.op, r.own ? null : r.op]);
    });
    aoa.push(['TOTAL FOR ' + fl, null, null, null, null, null, null, null, null, null, Math.round(totalUser * 100) / 100, 0]);
    const ws = XLSX.utils.aoa_to_sheet(aoa);
    // accounting number format on the monetary columns (H, J, K)
    const range = XLSX.utils.decode_range(ws['!ref']);
    for (let R = 3; R <= range.e.r; R++) {
      ['H', 'J', 'K'].forEach((col) => {
        const cell = ws[col + (R + 1)];
        if (cell && typeof cell.v === 'number') cell.z = ACCT_FMT_XLSX;
      });
    }
    ws['!cols'] = [{ wch: 16 }, { wch: 22 }, { wch: 14 }, { wch: 20 }, { wch: 14 }, { wch: 14 }, { wch: 16 }, { wch: 16 }, { wch: 12 }, { wch: 14 }, { wch: 16 }, { wch: 14 }];
    dnzStyleSheet(ws, { ncols: 12, titleRows: [0], titleStartCol: 1, dateRows: [1], headerRows: [2], totalRows: [aoa.length - 1] });
    XLSX.utils.book_append_sheet(wb, ws, fl.slice(0, 31));
    grand += totalUser; tabs++;
  });
  if (!tabs) throw new Error('No commission-earning attorneys had collections in that range.');
  const out = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  const name = 'Origination Payments ' + startIso + ' to ' + endIso + '.xlsx';
  return { blob: new Blob([out], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }), name, tabs, total: Math.round(grand * 100) / 100 };
}

// Build + download the A/R-by-Originating-Attorney workbook IN THE BROWSER,
// in the exact format of the uploaded source report (title row, header row,
// each attorney's clients, a "— Subtotal" row, blank separators, GRAND TOTAL).
// Source: bills-corner/ar-originator-detail.json (encrypted, full detail).
async function downloadOriginatorAR() {
  try {
    if (!window.XLSX) throw new Error('Excel library still loading — try again in a second.');
    const r = await fetch('bills-corner/ar-originator-detail.json?_=' + Date.now(), { cache: 'no-store' });
    if (!r.ok) throw new Error('detail not available (HTTP ' + r.status + ')');
    const raw = await r.json();
    const kdf = State.session && State.session.kdfInput;
    const d = isPwBlob(raw) ? await AsaCrypto.decryptJSON(raw, kdf) : raw;
    if (!d || !d.groups) throw new Error('could not decrypt the A/R detail — sign out and back in');
    const aoa = [];
    const roles = { titleRows: [0], dateRows: [1], blankRows: [], headerRows: [2], groupRows: [], totalRows: [] };
    aoa.push([d.title]);                 // row 1: title
    aoa.push(['As of ' + fmtDate(d.asOf)]); // row 2: date
    aoa.push(d.headers);                 // row 3: column headers
    const cells = (v) => (v == null ? null : v);
    d.groups.forEach((g) => {
      roles.groupRows.push(aoa.length);
      aoa.push([g.attorney]);            // attorney header (col A only)
      g.clients.forEach((c) => aoa.push([null, c.client, ...c.vals.map(cells)]));
      if (g.subtotal) { roles.totalRows.push(aoa.length); aoa.push([g.attorney + ' — Subtotal', null, ...g.subtotal.map((v) => (v == null ? 0 : v))]); }
      roles.blankRows.push(aoa.length);
      aoa.push([]);                      // blank separator
    });
    if (d.grand) { roles.totalRows.push(aoa.length); aoa.push(['GRAND TOTAL', null, ...d.grand.map((v) => (v == null ? 0 : v))]); }
    const ws = XLSX.utils.aoa_to_sheet(aoa);
    ws['!cols'] = [{ wch: 26 }, { wch: 40 }, { wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 14 }];
    // accounting format on the six numeric columns (C–H)
    const range = XLSX.utils.decode_range(ws['!ref']);
    for (let R = 0; R <= range.e.r; R++)
      for (const col of ['C', 'D', 'E', 'F', 'G', 'H']) {
        const cell = ws[col + (R + 1)];
        if (cell && typeof cell.v === 'number') cell.z = ACCT_FMT_XLSX;
      }
    dnzStyleSheet(ws, { ncols: (d.headers || []).length || 8, titleRows: roles.titleRows, blankRows: roles.blankRows, headerRows: roles.headerRows, groupRows: roles.groupRows, totalRows: roles.totalRows });
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Aging by Attorney & Client');
    const out = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([out], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }));
    a.download = d.filename || ('A-R by Originating Attorney ' + (d.asOf || '') + '.xlsx');
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
    toast('Downloaded ' + a.download + ' — ' + d.groups.length + ' attorneys.', 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

// Per-attorney A/R workbook — same format as the full originator workbook
// (title · headers · client rows · subtotal), but scoped to ONE attorney.
// Pulls the same encrypted bills-corner/ar-originator-detail.json and slices
// out that attorney's group. Falls back to an aging-bucket summary built from
// the on-screen row if the attorney isn't in the detail file.
function arNormName(s) {
  return String(s || '').toLowerCase().replace(/[^a-z ]/g, ' ').split(/\s+/).filter(Boolean).sort().join(' ');
}
async function downloadOriginatorARForAttorney(row, fallbackAsOf) {
  const attorney = (row && row.attorney) || '';
  try {
    if (!window.XLSX) throw new Error('Excel library still loading — try again in a second.');
    const safe = attorney.replace(/[\\/:*?"<>|]+/g, '').trim();
    let aoa, asOf = '', sheetName = 'A-R', roles = null, ncols = 8;
    try {
      const r = await fetch('bills-corner/ar-originator-detail.json?_=' + Date.now(), { cache: 'no-store' });
      if (!r.ok) throw new Error('detail HTTP ' + r.status);
      const raw = await r.json();
      const kdf = State.session && State.session.kdfInput;
      const d = isPwBlob(raw) ? await AsaCrypto.decryptJSON(raw, kdf) : raw;
      if (!d || !d.groups) throw new Error('no detail');
      asOf = d.asOf || '';
      const want = arNormName(attorney);
      const g = d.groups.find((x) => arNormName(x.attorney) === want)
             || d.groups.find((x) => arNormName(x.attorney).includes(want) || want.includes(arNormName(x.attorney)));
      if (g) {
        const cells = (v) => (v == null ? null : v);
        aoa = [];
        aoa.push([(d.title || 'Accounts Receivable — Aging by Originating Attorney & Client') + ' — ' + g.attorney]);
        aoa.push([asOf ? 'As of ' + fmtDate(asOf) : '']);
        aoa.push(d.headers);
        aoa.push([g.attorney]);
        g.clients.forEach((c) => aoa.push([null, c.client, ...c.vals.map(cells)]));
        if (g.subtotal) aoa.push([g.attorney + ' — Total', null, ...g.subtotal.map((v) => (v == null ? 0 : v))]);
        ncols = (d.headers || []).length || 8;
        roles = { titleRows: [0], headerRows: [2], groupRows: [3], totalRows: g.subtotal ? [aoa.length - 1] : [] };
        roles[asOf ? 'dateRows' : 'blankRows'] = [1];
      }
    } catch (_) { /* fall back below */ }

    if (!aoa) {
      // Fallback: aging-bucket summary from the on-screen row.
      if (!asOf) asOf = fallbackAsOf || '';
      aoa = [
        ['Accounts Receivable — ' + attorney],
        [asOf ? 'As of ' + fmtDate(asOf) : ''],
        ['Aging bucket', 'Balance'],
        ['1–30 days', row.b30 || 0],
        ['31–60 days', row.b60 || 0],
        ['61–90 days', row.b90 || 0],
        ['90+ days', row.b91 || 0],
        ['Total outstanding', row.total || 0],
      ];
      ncols = 2;
      roles = { titleRows: [0], headerRows: [2], totalRows: [7] };
      roles[asOf ? 'dateRows' : 'blankRows'] = [1];
    }

    const ws = XLSX.utils.aoa_to_sheet(aoa);
    ws['!cols'] = [{ wch: 28 }, { wch: 42 }, { wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 14 }];
    const range = XLSX.utils.decode_range(ws['!ref']);
    for (let R = 0; R <= range.e.r; R++)
      for (const col of ['B', 'C', 'D', 'E', 'F', 'G', 'H']) {
        const cell = ws[col + (R + 1)];
        if (cell && typeof cell.v === 'number') cell.z = ACCT_FMT_XLSX;
      }
    if (roles) dnzStyleSheet(ws, Object.assign({ ncols: ncols }, roles));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, sheetName.slice(0, 31));
    const out = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([out], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }));
    a.download = 'A-R — ' + (safe || 'attorney') + (asOf ? ' ' + asOf : '') + '.xlsx';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
    toast('Downloaded ' + a.download, 'ok');
  } catch (e) { toast(e.message || String(e), 'err'); }
}

async function downloadBillsSheet(entry) {
  try {
    const r = await fetch(entry.file + '?_=' + Date.now(), { cache: 'no-store' });
    if (!r.ok) throw new Error('fetch ' + r.status);
    const raw = await r.json();
    const kdf = State.session && State.session.kdfInput;
    const inner = isPwBlob(raw) ? await AsaCrypto.decryptJSON(raw, kdf) : raw;
    if (!inner || !inner.b64) throw new Error('decryption failed');
    const bin = atob(inner.b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([u8], { type: inner.type || 'application/octet-stream' }));
    a.download = inner.name || entry.filename || 'sheet.xlsx';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
    toast('Downloaded ' + a.download, 'ok');
  } catch (e) { toast('Download failed: ' + e.message, 'err'); }
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

})();

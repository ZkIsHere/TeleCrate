/* TeleCrate admin — vanilla JS, không dependency, không CDN.
   Mọi endpoint lỗi đều có trạng thái rõ; secret không bao giờ render ra bảng. */
(() => {
'use strict';

const $ = (id) => document.getElementById(id);
const state = {
  csrf: null,
  tab: 'overview',
  buckets: [],
  keys: [],
  refreshTimer: null,
  logTimer: null,
  logOffset: 0,
  logLimit: 50,
  logTotal: 0,
};

const TITLES = {
  overview: 'Tổng quan',
  storage: 'Buckets',
  keys: 'Access keys',
  config: 'Cấu hình',
  maintenance: 'Bảo trì',
  logs: 'Nhật ký',
};

/* ---------- helpers ---------- */
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}
function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + ' ' + u[i];
}
function fmtUptime(s) {
  s = Number(s) || 0;
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
function fmtTime(ts) {
  const d = new Date(Number(ts) * 1000);
  return isNaN(d) ? '—' : d.toLocaleString();
}
function toast(msg, kind) {
  const el = document.createElement('div');
  el.className = 'toast' + (kind === 'ok' ? ' ok' : kind === 'err' ? ' err' : '');
  el.textContent = msg;
  $('toast-region').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}
function setOffline(off) {
  $('offline-banner').classList.toggle('hidden', !off);
  const ds = $('daemon-state');
  ds.dataset.state = off ? 'down' : 'up';
  ds.textContent = off ? 'Daemon: mất kết nối' : 'Daemon: hoạt động';
}

async function api(url, opts = {}) {
  opts.headers = opts.headers || {};
  if (state.csrf) opts.headers['x-csrf-token'] = state.csrf;
  opts.credentials = 'include';
  let resp;
  try {
    resp = await fetch(url, opts);
  } catch (e) {
    setOffline(true);
    throw new Error('Không kết nối được daemon');
  }
  if (resp.status === 401) { showAuth(); throw new Error('Hết phiên đăng nhập'); }
  setOffline(false);
  return resp;
}

/* ---------- theme ---------- */
function initTheme() {
  const saved = localStorage.getItem('tc-theme');
  const theme = saved || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  document.documentElement.dataset.theme = theme;
}
$('btn-theme').addEventListener('click', () => {
  const cur = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = cur;
  localStorage.setItem('tc-theme', cur);
});

/* ---------- auth ---------- */
function showAuth() {
  $('auth-view').classList.remove('hidden');
  $('main-view').classList.add('hidden');
  stopTimers();
}
function showMain() {
  $('auth-view').classList.add('hidden');
  $('main-view').classList.remove('hidden');
  loadTab();
  state.refreshTimer = state.refreshTimer || setInterval(() => {
    if (state.tab === 'overview') loadOverview();
    if (state.tab === 'logs' && $('log-auto').checked) loadLogs();
  }, 5000);
}
function stopTimers() {
  clearInterval(state.refreshTimer); state.refreshTimer = null;
}
async function checkSession() {
  try {
    const r = await fetch('/admin/api/session', { credentials: 'include' });
    const d = await r.json();
    if (d.authenticated) { state.csrf = d.csrf_token; showMain(); } else showAuth();
  } catch { showAuth(); }
}
$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('login-error');
  err.classList.add('hidden');
  const btn = $('btn-login');
  btn.disabled = true;
  try {
    const r = await fetch('/admin/api/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: $('admin-password').value }),
      credentials: 'include',
    });
    const d = await r.json();
    if (r.ok && d.ok) {
      state.csrf = d.csrf_token;
      $('admin-password').value = '';
      toast('Đăng nhập thành công', 'ok');
      showMain();
    } else if (r.status === 429) {
      err.textContent = d.error || 'Quá nhiều lần sai — thử lại sau 1 phút';
      err.classList.remove('hidden');
    } else {
      err.textContent = d.error || 'Mật khẩu không chính xác';
      err.classList.remove('hidden');
    }
  } catch (ex) {
    err.textContent = 'Kết nối thất bại: ' + ex.message;
    err.classList.remove('hidden');
  }
  btn.disabled = false;
});
$('btn-logout').addEventListener('click', async () => {
  try { await api('/admin/api/logout', { method: 'POST' }); } catch {}
  state.csrf = null;
  showAuth();
});

/* ---------- tabs ---------- */
const NAV = document.querySelectorAll('.nav-item');
NAV.forEach((b) => b.addEventListener('click', () => switchTab(b.dataset.tab)));
function switchTab(t) {
  state.tab = t;
  NAV.forEach((b) => b.classList.toggle('active', b.dataset.tab === t));
  document.querySelectorAll('.tab').forEach((p) => p.classList.toggle('active', p.id === 'tab-' + t));
  $('tab-title').textContent = TITLES[t] || t;
  if (t === 'logs') state.logOffset = 0;
  loadTab();
}
function loadTab() {
  loadOverview();
  if (state.tab === 'storage') loadBuckets();
  if (state.tab === 'keys') loadKeys();
  if (state.tab === 'config') loadConfig();
  if (state.tab === 'logs') loadLogs();
}
$('btn-refresh').addEventListener('click', () => { loadTab(); toast('Đã làm mới', 'ok'); });
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModal();
  if (e.key === '/' && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) {
    const q = { storage: 'q-bucket', keys: 'q-key', logs: 'log-q' }[state.tab];
    if (q) { e.preventDefault(); $(q).focus(); }
  }
});

/* ---------- overview ---------- */
async function loadOverview() {
  const err = $('ov-error');
  err.classList.add('hidden');
  try {
    const r = await api('/admin/api/status');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const c = d.counts || {}, s = d.spool || {}, w = d.workers || {};
    const v = (x, fb) => x ?? fb ?? '—';
    $('ov-buckets').textContent = v(c.total_buckets, d.total_buckets);
    $('ov-objects').textContent = v(c.total_objects, d.total_objects);
    $('ov-keys').textContent = v(c.total_access_keys, d.total_access_keys);
    $('ov-spool').textContent = fmtBytes(v(s.used_bytes, d.spool_used_bytes));
    $('ov-jobs').textContent = `${v(w.pending_jobs_count, d.pending_jobs)} chờ / ${v(w.uploading_jobs_count, d.uploading_jobs)} chạy`;
    $('ov-workers').textContent = v(w.active_worker_count, d.worker_concurrency);
    $('ov-db').textContent = fmtBytes(d.db_size_bytes || 0);
    $('ov-uptime').textContent = fmtUptime(d.uptime_secs ?? d.uptime_seconds);
    $('app-version').textContent = d.version ? 'v' + d.version : '';
    setOffline(false);
  } catch (e) {
    err.textContent = 'Không nạp được trạng thái: ' + e.message;
    err.classList.remove('hidden');
  }
}

/* ---------- buckets ---------- */
async function loadBuckets() {
  const tb = $('bucket-tbody');
  tb.innerHTML = '<tr><td colspan="5" class="muted">Đang nạp…</td></tr>';
  $('bucket-error').classList.add('hidden');
  try {
    const r = await api('/admin/api/buckets');
    const d = await r.json();
    state.buckets = Array.isArray(d) ? d : (d.buckets || []);
    renderBuckets();
  } catch (e) {
    tb.innerHTML = '';
    const be = $('bucket-error');
    be.textContent = 'Lỗi nạp buckets: ' + e.message;
    be.classList.remove('hidden');
  }
}
function renderBuckets() {
  const q = $('q-bucket').value.toLowerCase().trim();
  const list = state.buckets.filter((b) => (b.name || '').toLowerCase().includes(q));
  const tb = $('bucket-tbody');
  if (!list.length) {
    tb.innerHTML = `<tr><td colspan="5" class="muted">${state.buckets.length ? 'Không khớp bộ lọc' : 'Chưa có bucket nào — tạo bucket đầu tiên để bắt đầu'}</td></tr>`;
    return;
  }
  tb.innerHTML = list.map((b) => `<tr>
    <td><strong>${esc(b.name)}</strong></td>
    <td>${esc(b.region)}</td>
    <td>${esc(b.versioning || b.versioning_status || 'Disabled')}</td>
    <td class="mono">${esc(b.created_at)}</td>
    <td><button class="btn sm ghost" data-act="view" data-n="${esc(b.name)}">Objects</button>
    <button class="btn sm danger" data-act="del" data-n="${esc(b.name)}">Xóa</button></td>
  </tr>`).join('');
  tb.querySelectorAll('button').forEach((btn) => btn.addEventListener('click', () => {
    if (btn.dataset.act === 'view') viewObjects(btn.dataset.n);
    else if (confirm(`Xóa bucket '${btn.dataset.n}'? Bucket phải rỗng.`)) deleteBucket(btn.dataset.n);
  }));
}
$('q-bucket').addEventListener('input', renderBuckets);
async function deleteBucket(n) {
  try {
    const r = await api(`/admin/api/buckets/${encodeURIComponent(n)}`, { method: 'DELETE' });
    const d = await r.json();
    if (r.ok && d.ok) { toast(`Đã xóa bucket '${n}'`, 'ok'); loadBuckets(); }
    else toast(d.error || 'Xóa thất bại', 'err');
  } catch (e) { toast(e.message, 'err'); }
}
async function viewObjects(bucket) {
  $('object-panel').classList.remove('hidden');
  $('object-title').textContent = `Objects — ${bucket}`;
  const tb = $('object-tbody');
  tb.innerHTML = '<tr><td colspan="5" class="muted">Đang nạp…</td></tr>';
  $('object-error').classList.add('hidden');
  try {
    const r = await api(`/admin/api/buckets/${encodeURIComponent(bucket)}/objects`);
    const d = await r.json();
    const list = Array.isArray(d) ? d : (d.objects || []);
    if (!list.length) {
      tb.innerHTML = '<tr><td colspan="5" class="muted">Bucket rỗng</td></tr>';
      return;
    }
    tb.innerHTML = list.map((o) => `<tr>
      <td class="mono"><strong>${esc(o.key)}</strong></td>
      <td class="mono">${fmtBytes(o.size)}</td>
      <td><span class="badge ${o.storage_state === 'remote' ? 'ok' : 'warn'}">${esc(o.storage_state)}</span></td>
      <td class="mono">${esc(o.etag || '—')}</td>
      <td class="mono">${esc(o.created_at)}</td>
    </tr>`).join('');
  } catch (e) {
    const oe = $('object-error');
    oe.textContent = 'Lỗi nạp objects: ' + e.message;
    oe.classList.remove('hidden');
    tb.innerHTML = '';
  }
}
$('btn-close-objects').addEventListener('click', () => $('object-panel').classList.add('hidden'));
$('btn-new-bucket').addEventListener('click', () => openModal({
  title: 'Tạo bucket',
  fields: [
    { id: 'm-name', label: 'Tên bucket', value: '' },
  ],
  onOk: async () => {
    const name = $('m-name').value.trim();
    if (!name) return 'Tên bucket bắt buộc';
    const r = await api('/admin/api/buckets', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    const d = await r.json();
    if (r.ok && d.ok) { toast(`Đã tạo bucket '${name}'`, 'ok'); loadBuckets(); return null; }
    return d.error || 'Tạo thất bại';
  },
}));

/* ---------- keys ---------- */
async function loadKeys() {
  const tb = $('key-tbody');
  tb.innerHTML = '<tr><td colspan="5" class="muted">Đang nạp…</td></tr>';
  $('key-error').classList.add('hidden');
  try {
    const r = await api('/admin/api/access-keys');
    const d = await r.json();
    state.keys = Array.isArray(d) ? d : (d.access_keys || []);
    renderKeys();
  } catch (e) {
    tb.innerHTML = '';
    const ke = $('key-error');
    ke.textContent = 'Lỗi nạp keys: ' + e.message;
    ke.classList.remove('hidden');
  }
}
function renderKeys() {
  const q = $('q-key').value.toLowerCase().trim();
  const list = state.keys.filter((k) => (k.access_key_id || '').toLowerCase().includes(q));
  const tb = $('key-tbody');
  if (!list.length) {
    tb.innerHTML = `<tr><td colspan="5" class="muted">${state.keys.length ? 'Không khớp bộ lọc' : 'Chưa có access key nào'}</td></tr>`;
    return;
  }
  tb.innerHTML = list.map((k) => `<tr>
    <td class="mono"><strong>${esc(k.access_key_id)}</strong></td>
    <td>${esc(k.user_id || '—')}</td>
    <td><span class="badge ${k.status === 'active' ? 'ok' : ''}">${esc(k.status || '—')}</span></td>
    <td class="mono">${esc(k.created_at)}</td>
    <td><button class="btn sm danger" data-id="${esc(k.access_key_id)}">Thu hồi</button></td>
  </tr>`).join('');
  tb.querySelectorAll('button').forEach((b) => b.addEventListener('click', async () => {
    if (!confirm(`Thu hồi key '${b.dataset.id}'? Các client dùng key này sẽ mất truy cập.`)) return;
    try {
      const r = await api(`/admin/api/access-keys/${encodeURIComponent(b.dataset.id)}`, { method: 'DELETE' });
      const d = await r.json();
      if (r.ok && d.ok) { toast('Đã thu hồi key', 'ok'); loadKeys(); }
      else toast(d.error || 'Thu hồi thất bại', 'err');
    } catch (e) { toast(e.message, 'err'); }
  }));
}
$('q-key').addEventListener('input', renderKeys);
$('btn-new-key').addEventListener('click', () => openModal({
  // Server tự sinh key id + secret (CSPRNG) — form chỉ hỏi user/mô tả.
  title: 'Tạo access key',
  fields: [
    { id: 'm-kuser', label: 'User / mô tả', value: 'admin' },
  ],
  onOk: async () => {
    const r = await api('/admin/api/access-keys', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: $('m-kuser').value.trim() || 'admin' }),
    });
    const d = await r.json();
    if (r.ok && d.ok && d.secret_key) {
      // Secret hiện ĐÚNG MỘT LẦN — không render vào bảng, không lưu đâu khác.
      const box = $('new-secret');
      box.innerHTML = `<strong>Lưu ngay — secret chỉ hiện một lần:</strong><br><span class="mono">ID: ${esc(d.access_key_id)}<br>Secret: ${esc(d.secret_key)}</span>`;
      box.classList.remove('hidden');
      loadKeys();
      return null;
    }
    return (d && d.error) || 'Tạo key thất bại';
  },
}));

/* ---------- config ---------- */
async function loadConfig() {
  const err = $('config-error');
  err.classList.add('hidden');
  try {
    const r = await api('/admin/api/config');
    const d = await r.json();
    if (!(r.ok && d.ok && d.config)) throw new Error((d && d.error) || 'HTTP ' + r.status);
    const c = d.config;
    $('cfg-port').value = c.listen_port ?? 7070;
    $('cfg-encryption').value = c.encryption || 'off';
    $('cfg-workers').value = c.worker_concurrency ?? 2;
    $('cfg-loglevel').value = c.log_level || 'info';
    $('cfg-logfile').checked = !!c.log_to_file;
    $('cfg-logdir').value = c.log_dir || '/var/lib/telecrate/logs';
    $('cfg-logret').value = c.log_retention_days ?? 14;
    $('cfg-chat').value = c.telegram_chat_id ?? '';
    $('cfg-token').value = '';
    $('cfg-adminpwd').value = '';
  } catch (e) {
    err.textContent = 'Lỗi nạp cấu hình: ' + e.message;
    err.classList.remove('hidden');
  }
}
$('config-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const items = [
    ['listen_port', $('cfg-port').value],
    ['encryption', $('cfg-encryption').value],
    ['worker_concurrency', $('cfg-workers').value],
    ['log_level', $('cfg-loglevel').value],
    ['log_to_file', $('cfg-logfile').checked ? 'true' : 'false'],
    ['log_dir', $('cfg-logdir').value],
    ['log_retention_days', $('cfg-logret').value],
    ['telegram_chat_id', $('cfg-chat').value],
  ];
  if ($('cfg-token').value) items.push(['telegram_bot_token', $('cfg-token').value]);
  if ($('cfg-adminpwd').value) items.push(['admin_password', $('cfg-adminpwd').value]);
  let ok = 0, firstErr = '';
  for (const [key, value] of items) {
    try {
      const r = await api('/admin/api/config', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, value }),
      });
      if (r.ok) ok++;
      else if (!firstErr) { try { firstErr = (await r.json()).error || ''; } catch {} }
    } catch (ex) { if (!firstErr) firstErr = ex.message; }
  }
  if (ok === items.length) { toast('Đã lưu cấu hình', 'ok'); $('cfg-token').value = ''; $('cfg-adminpwd').value = ''; }
  else toast(`Lưu ${ok}/${items.length}${firstErr ? ' — lỗi: ' + firstErr : ''}`, 'err');
  loadConfig();
});

/* ---------- maintenance ---------- */
document.querySelectorAll('[data-op]').forEach((b) => b.addEventListener('click', async () => {
  const out = $(b.dataset.out);
  out.classList.remove('hidden');
  out.textContent = 'Đang chạy…';
  b.disabled = true;
  try {
    const r = await api(b.dataset.op, { method: 'POST' });
    const d = await r.json();
    out.textContent = JSON.stringify(d, null, 2);
    toast(r.ok ? 'Hoàn tất' : 'Có lỗi — xem output', r.ok ? 'ok' : 'err');
  } catch (e) {
    out.textContent = 'Lỗi: ' + e.message;
    toast('Lỗi thực thi', 'err');
  }
  b.disabled = false;
}));

/* ---------- logs ---------- */
const LV_CLASS = { info: '', warn: 'warn', error: 'err' };
async function loadLogs() {
  const err = $('log-error');
  err.classList.add('hidden');
  const tb = $('log-tbody');
  try {
    const p = new URLSearchParams({
      limit: 50, offset: state.logOffset,
    });
    const lv = $('log-level').value, q = $('log-q').value.trim();
    if (lv) p.set('level', lv);
    if (q) p.set('q', q);
    const r = await api('/admin/api/audit-logs?' + p.toString());
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const list = d.entries || [];
    state.logTotal = d.total || 0;
    if (!list.length) {
      tb.innerHTML = '<tr><td colspan="5" class="muted">Không có bản ghi nào — thử nới bộ lọc</td></tr>';
    } else {
      tb.innerHTML = list.map((e) => `<tr>
        <td class="mono">${esc(fmtTime(e.ts))}</td>
        <td><span class="badge ${LV_CLASS[e.level] || ''}">${esc(e.level)}</span></td>
        <td>${esc(e.actor)}</td>
        <td class="mono">${esc(e.action)}</td>
        <td>${esc(e.detail)}</td>
      </tr>`).join('');
    }
    const pages = Math.max(1, Math.ceil(state.logTotal / 50));
    const cur = Math.floor(state.logOffset / 50) + 1;
    $('log-page').textContent = `Trang ${cur}/${pages} — tổng ${state.logTotal}`;
    $('log-count').textContent = '';
    $('log-prev').disabled = state.logOffset === 0;
    $('log-next').disabled = state.logOffset + 50 >= state.logTotal;
  } catch (e) {
    err.textContent = 'Lỗi nạp nhật ký: ' + e.message;
    err.classList.remove('hidden');
  }
}
$('btn-log-reload').addEventListener('click', () => { state.logOffset = 0; loadLogs(); });
$('log-level').addEventListener('change', () => { state.logOffset = 0; loadLogs(); });
$('log-q').addEventListener('input', () => { state.logOffset = 0; loadLogs(); });
$('log-prev').addEventListener('click', () => { state.logOffset = Math.max(0, state.logOffset - 50); loadLogs(); });
$('log-next').addEventListener('click', () => { state.logOffset += 50; loadLogs(); });
$('btn-log-export').addEventListener('click', async () => {
  try {
    const r = await api('/admin/api/audit-logs?limit=1000');
    const d = await r.json();
    const blob = new Blob([JSON.stringify(d.entries || [], null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'telecrate-audit.json';
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Đã xuất nhật ký (đã redact ở server)', 'ok');
  } catch (e) { toast('Xuất thất bại: ' + e.message, 'err'); }
});

/* ---------- modal ---------- */
let modalOk = null;
function openModal({ title, fields, onOk }) {
  $('modal-title').textContent = title;
  $('modal-fields').innerHTML = fields.map((f) =>
    `<label class="field"><span>${esc(f.label)}</span><input id="${f.id}" value="${esc(f.value || '')}"></label>`
  ).join('');
  $('modal-error').classList.add('hidden');
  modalOk = onOk;
  $('modal').classList.remove('hidden');
  const first = $('modal-fields').querySelector('input');
  if (first) first.focus();
}
function closeModal() { $('modal').classList.add('hidden'); modalOk = null; }
$('modal-cancel').addEventListener('click', closeModal);
$('modal').addEventListener('click', (e) => { if (e.target === $('modal')) closeModal(); });
$('modal-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!modalOk) return;
  const err = $('modal-error');
  err.classList.add('hidden');
  $('modal-ok').disabled = true;
  try {
    const msg = await modalOk();
    if (msg) { err.textContent = msg; err.classList.remove('hidden'); }
    else closeModal();
  } catch (ex) {
    err.textContent = ex.message;
    err.classList.remove('hidden');
  }
  $('modal-ok').disabled = false;
});

/* ---------- start ---------- */
initTheme();
checkSession();
})();

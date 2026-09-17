/* TeleCrate Admin Console — Vanilla JS, 100% offline, zero external dependencies.
   Strict compliance with AGENTS.md:
   - Real metrics only, no mock charts, no fabricated data.
   - AWS S3-like hierarchical file browser with prefixes, folders, breadcrumb, multi-select.
   - Access key management with status toggle, permissions, last-used, secret shown ONCE.
   - Responsive, dark/light theme, live pipeline & multipart cleanup. */

(() => {
'use strict';

const $ = (id) => document.getElementById(id);

const state = {
  csrf: null,
  tab: 'overview',
  buckets: [],
  keys: [],
  refreshTimer: null,
  // File browser state
  currentBucket: null,
  currentPrefix: '',
  selectedObjects: new Set(),
  // Jobs state
  jobFilter: '',
  // Logs state
  logLevel: '',
  logOffset: 0,
  logLimit: 50,
  logTotal: 0,
};

const TITLES = {
  overview: 'Tổng quan',
  storage: 'Buckets',
  keys: 'Access keys',
  config: 'Cấu hình',
  jobs: 'Jobs',
  maintenance: 'Bảo trì',
  logs: 'Nhật ký',
};

/* ==========================================================================
   Helpers
   ========================================================================== */
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n <= 0) return '0 B';
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + ' ' + u[i];
}

function fmtUptime(s) {
  s = Number(s) || 0;
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(typeof ts === 'number' ? ts * 1000 : ts);
  return isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

function toast(msg, kind) {
  const el = document.createElement('div');
  el.className = 'toast' + (kind === 'ok' ? ' ok' : kind === 'err' ? ' err' : '');
  el.textContent = msg;
  const reg = $('toast-region');
  if (reg) {
    reg.appendChild(el);
    setTimeout(() => el.remove(), 4000);
  }
}

function setOffline(off) {
  const ob = $('offline-banner');
  if (ob) ob.classList.toggle('hidden', !off);
  const ds = $('daemon-state');
  if (ds) {
    ds.dataset.state = off ? 'down' : 'up';
    ds.textContent = off ? 'Daemon: mất kết nối' : 'Daemon: hoạt động';
  }
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
  if (resp.status === 401) {
    showAuth();
    throw new Error('Hết phiên đăng nhập');
  }
  setOffline(false);
  return resp;
}

/* ==========================================================================
   Theme & Mobile Navigation
   ========================================================================== */
function initTheme() {
  const saved = localStorage.getItem('tc-theme');
  const theme = saved || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  document.documentElement.dataset.theme = theme;
}

$('btn-theme')?.addEventListener('click', () => {
  const cur = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = cur;
  localStorage.setItem('tc-theme', cur);
  if (state.tab === 'overview') drawAllCharts();
});

$('btn-hamburger')?.addEventListener('click', () => {
  $('sidebar')?.classList.toggle('open');
});

/* ==========================================================================
   Authentication & Session
   ========================================================================== */
function showAuth() {
  $('auth-view')?.classList.remove('hidden');
  $('main-view')?.classList.add('hidden');
  stopTimers();
}

function showMain() {
  $('auth-view')?.classList.add('hidden');
  $('main-view')?.classList.remove('hidden');
  loadTab();
  startTimers();
}

function startTimers() {
  stopTimers();
  state.refreshTimer = setInterval(() => {
    if (state.tab === 'overview') loadOverview();
    if (state.tab === 'jobs' && $('jobs-auto')?.checked) loadJobs();
    if (state.tab === 'logs' && $('log-auto')?.checked) loadLogs();
  }, 5000);
}

function stopTimers() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
}

async function checkSession() {
  try {
    const r = await fetch('/admin/api/session', { credentials: 'include' });
    const d = await r.json();
    if (d.authenticated) {
      state.csrf = d.csrf_token;
      showMain();
    } else {
      showAuth();
    }
  } catch {
    showAuth();
  }
}

$('login-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('login-error');
  err.classList.add('hidden');
  const btn = $('btn-login');
  btn.disabled = true;
  try {
    const r = await fetch('/admin/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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
      err.textContent = d.error || 'Quá nhiều lần thử — vui lòng chờ 1 phút';
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

$('btn-logout')?.addEventListener('click', async () => {
  try { await api('/admin/api/logout', { method: 'POST' }); } catch {}
  state.csrf = null;
  showAuth();
});

/* ==========================================================================
   Tabs Routing
   ========================================================================== */
const NAV = document.querySelectorAll('.nav-item');
NAV.forEach((b) => b.addEventListener('click', () => {
  switchTab(b.dataset.tab);
  $('sidebar')?.classList.remove('open');
}));

function switchTab(t) {
  state.tab = t;
  NAV.forEach((b) => b.classList.toggle('active', b.dataset.tab === t));
  document.querySelectorAll('.tab').forEach((p) => p.classList.toggle('active', p.id === 'tab-' + t));
  $('tab-title').textContent = TITLES[t] || t;
  if (t === 'logs') state.logOffset = 0;
  loadTab();
}

function loadTab() {
  if (state.tab === 'overview') loadOverview();
  else if (state.tab === 'storage') loadBuckets();
  else if (state.tab === 'keys') loadKeys();
  else if (state.tab === 'config') loadConfig();
  else if (state.tab === 'jobs') loadJobs();
  else if (state.tab === 'maintenance') loadMaintenance();
  else if (state.tab === 'logs') loadLogs();
}

$('btn-refresh')?.addEventListener('click', () => {
  loadTab();
  toast('Đã làm mới', 'ok');
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeModal();
    closeObjectDetail();
  }
  if (e.key === '/' && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement?.tagName)) {
    const q = { storage: 'q-bucket', keys: 'q-key', logs: 'log-q' }[state.tab];
    if (q && $(q)) { e.preventDefault(); $(q).focus(); }
  }
});

/* ==========================================================================
   Canvas Line Chart Drawer (Offline, Zero Dependencies)
   ========================================================================== */
let cachedMetrics = [];

function drawLineChart(canvasId, points, formatVal, color) {
  const canvas = $(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = (rect.width || 380) * dpr;
  canvas.height = (rect.height || 160) * dpr;
  ctx.scale(dpr, dpr);

  const w = rect.width || 380;
  const h = rect.height || 160;
  const isDark = document.documentElement.dataset.theme === 'dark';

  ctx.clearRect(0, 0, w, h);

  if (!points || points.length === 0) {
    ctx.fillStyle = isDark ? '#6e7681' : '#8c959f';
    ctx.font = '12px system-ui';
    ctx.textAlign = 'center';
    ctx.fillText('Chưa có dữ liệu lịch sử', w / 2, h / 2);
    return;
  }

  const padLeft = 46, padRight = 14, padTop = 14, padBottom = 24;
  const plotW = w - padLeft - padRight;
  const plotH = h - padTop - padBottom;

  const vals = points.map((p) => p.val);
  let minV = Math.min(...vals);
  let maxV = Math.max(...vals);
  if (minV === maxV) { minV = Math.max(0, minV - 1); maxV += 1; }

  // Draw subtle horizontal grid lines
  const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
  const textColor = isDark ? '#9198a1' : '#59636e';
  ctx.font = '10.5px monospace';
  ctx.textAlign = 'right';
  ctx.fillStyle = textColor;

  const steps = 3;
  for (let i = 0; i <= steps; i++) {
    const yVal = minV + (maxV - minV) * (i / steps);
    const yPos = padTop + plotH - (i / steps) * plotH;
    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padLeft, yPos);
    ctx.lineTo(w - padRight, yPos);
    ctx.stroke();
    ctx.fillText(formatVal ? formatVal(yVal) : Math.round(yVal), padLeft - 6, yPos + 3.5);
  }

  // Calculate coordinates
  const coords = points.map((p, idx) => {
    const x = padLeft + (idx / (points.length - 1 || 1)) * plotW;
    const y = padTop + plotH - ((p.val - minV) / (maxV - minV)) * plotH;
    return { x, y };
  });

  // Fill gradient area under curve
  const strokeColor = color || (isDark ? '#4493f8' : '#0969da');
  const grad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
  grad.addColorStop(0, strokeColor + (isDark ? '33' : '22'));
  grad.addColorStop(1, strokeColor + '00');

  ctx.beginPath();
  ctx.moveTo(coords[0].x, padTop + plotH);
  coords.forEach((c) => ctx.lineTo(c.x, c.y));
  ctx.lineTo(coords[coords.length - 1].x, padTop + plotH);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Draw smooth line
  ctx.beginPath();
  coords.forEach((c, i) => {
    if (i === 0) ctx.moveTo(c.x, c.y);
    else ctx.lineTo(c.x, c.y);
  });
  ctx.strokeStyle = strokeColor;
  ctx.lineWidth = 2;
  ctx.stroke();

  // Draw last value dot
  const last = coords[coords.length - 1];
  ctx.beginPath();
  ctx.arc(last.x, last.y, 3.5, 0, Math.PI * 2);
  ctx.fillStyle = strokeColor;
  ctx.fill();
}

function drawAllCharts() {
  if (!cachedMetrics || cachedMetrics.length === 0) return;
  const isDark = document.documentElement.dataset.theme === 'dark';

  drawLineChart('chart-objects', cachedMetrics.map((m) => ({ val: m.objects || 0 })), (v) => Math.round(v), isDark ? '#4493f8' : '#0969da');
  drawLineChart('chart-spool', cachedMetrics.map((m) => ({ val: m.spool_used_bytes ?? m.spool_bytes ?? 0 })), fmtBytes, isDark ? '#d29922' : '#9a6700');
  drawLineChart('chart-storage', cachedMetrics.map((m) => ({ val: m.total_size_bytes ?? m.db_bytes ?? 0 })), fmtBytes, isDark ? '#3fb950' : '#1a7f37');
  drawLineChart('chart-jobs', cachedMetrics.map((m) => ({ val: (m.pending_jobs || 0) + (m.uploading_jobs || 0) })), (v) => Math.round(v), isDark ? '#f85149' : '#cf222e');
}

/* ==========================================================================
   Overview Tab
   ========================================================================== */
async function loadOverview() {
  const err = $('ov-error');
  err?.classList.add('hidden');
  try {
    const r = await api('/admin/api/status');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();

    const c = d.counts || {};
    const s = d.spool || {};
    const w = d.workers || {};
    const v = (x, fb) => x ?? fb ?? '—';

    $('ov-buckets').textContent = v(c.total_buckets, d.total_buckets);
    $('ov-objects').textContent = v(c.total_objects, d.total_objects);
    $('ov-keys').textContent = v(c.total_access_keys, d.total_access_keys);
    $('ov-chunks').textContent = v(c.total_chunks, 0);

    const spoolBytes = Number(v(s.used_bytes, d.spool_used_bytes)) || 0;
    const spoolQuota = Number(s.quota_bytes) || 0;
    $('ov-spool').textContent = fmtBytes(spoolBytes);
    $('ov-spool-detail').textContent = spoolQuota > 0 ? `Hạn mức: ${fmtBytes(spoolQuota)}` : 'Không giới hạn';

    const spoolPct = spoolQuota > 0 ? Math.min(100, Math.round((spoolBytes / spoolQuota) * 100)) : 0;
    $('spool-pct').textContent = spoolPct + '%';
    const fill = $('spool-fill');
    if (fill) {
      fill.style.width = spoolPct + '%';
      fill.className = 'progress-fill' + (spoolPct > 90 ? ' err' : spoolPct > 70 ? ' warn' : '');
    }

    $('ov-db').textContent = fmtBytes(d.db_size_bytes || 0);
    $('ov-pending').textContent = `${v(w.pending_jobs_count, d.pending_jobs || 0)} chờ / ${v(w.uploading_jobs_count, d.uploading_jobs || 0)} chạy`;
    $('ov-workers').textContent = v(w.active_worker_count, d.worker_concurrency || 2);

    // Health strip
    const hsDot = $('hs-dot');
    if (hsDot) hsDot.className = 'state-dot' + (spoolPct > 90 ? ' err' : spoolPct > 75 ? ' warn' : '');
    $('hs-status').textContent = 'Hệ thống sẵn sàng';
    $('hs-uptime').textContent = fmtUptime(d.uptime_secs ?? d.uptime_seconds);
    $('hs-version').textContent = d.version ? 'v' + d.version : 'v0.1.0';
    $('app-version').textContent = d.version ? 'v' + d.version : '';

    // Badges in sidebar
    if ($('nav-badge-buckets')) $('nav-badge-buckets').textContent = v(c.total_buckets, '');
    if ($('nav-badge-keys')) $('nav-badge-keys').textContent = v(c.total_access_keys, '');
    if ($('nav-badge-jobs')) $('nav-badge-jobs').textContent = v(w.pending_jobs_count, '');

    // Fetch metric history for charts
    try {
      const mr = await api('/admin/api/metrics-history');
      if (mr.ok) {
        const md = await mr.json();
        cachedMetrics = md.metrics || [];
        drawAllCharts();
      }
    } catch {}

    setOffline(false);
  } catch (e) {
    if (err) {
      err.textContent = 'Không nạp được trạng thái: ' + e.message;
      err.classList.remove('hidden');
    }
  }
}

/* ==========================================================================
   Buckets & AWS S3-like File Browser Tab
   ========================================================================== */
async function loadBuckets() {
  const tb = $('bucket-tbody');
  if (tb) tb.innerHTML = '<tr><td colspan="7" class="muted">Đang nạp…</td></tr>';
  $('bucket-error')?.classList.add('hidden');
  try {
    const r = await api('/admin/api/buckets');
    const d = await r.json();
    state.buckets = Array.isArray(d) ? d : (d.buckets || []);
    renderBuckets();
  } catch (e) {
    if (tb) tb.innerHTML = '';
    const be = $('bucket-error');
    if (be) {
      be.textContent = 'Lỗi nạp buckets: ' + e.message;
      be.classList.remove('hidden');
    }
  }
}

function renderBuckets() {
  const q = $('q-bucket')?.value.toLowerCase().trim() || '';
  const list = state.buckets.filter((b) => (b.name || '').toLowerCase().includes(q));
  const tb = $('bucket-tbody');
  if (!tb) return;

  if (!list.length) {
    tb.innerHTML = `<tr><td colspan="7" class="muted">${state.buckets.length ? 'Không khớp bộ lọc' : 'Chưa có bucket nào — bấm "Tạo bucket" để bắt đầu'}</td></tr>`;
    return;
  }

  tb.innerHTML = list.map((b) => `<tr>
    <td><strong><a href="javascript:void(0)" class="btn-open-bucket" data-b="${esc(b.name)}">${esc(b.name)}</a></strong></td>
    <td>${esc(b.region || 'us-east-1')}</td>
    <td><span class="badge ${b.versioning === 'Enabled' ? 'ok' : ''}">${esc(b.versioning || 'Disabled')}</span></td>
    <td class="num mono">${b.object_count ?? '—'}</td>
    <td class="num mono">${fmtBytes(b.total_bytes ?? 0)}</td>
    <td class="mono small">${esc(fmtTime(b.created_at))}</td>
    <td>
      <button class="btn sm ghost btn-open-bucket" data-b="${esc(b.name)}">Xem files</button>
      <button class="btn sm danger btn-del-bucket" data-b="${esc(b.name)}">Xóa</button>
    </td>
  </tr>`).join('');

  tb.querySelectorAll('.btn-open-bucket').forEach((el) =>
    el.addEventListener('click', () => openFileBrowser(el.dataset.b))
  );

  tb.querySelectorAll('.btn-del-bucket').forEach((el) =>
    el.addEventListener('click', () => {
      const name = el.dataset.b;
      if (confirm(`Xóa bucket '${name}'? Bucket phải rỗng mới được xóa.`)) {
        deleteBucket(name);
      }
    })
  );
}

$('q-bucket')?.addEventListener('input', renderBuckets);

async function deleteBucket(n) {
  try {
    const r = await api(`/admin/api/buckets/${encodeURIComponent(n)}`, { method: 'DELETE' });
    const d = await r.json();
    if (r.ok && d.ok) {
      toast(`Đã xóa bucket '${n}'`, 'ok');
      loadBuckets();
    } else {
      toast(d.error || 'Xóa thất bại', 'err');
    }
  } catch (e) {
    toast(e.message, 'err');
  }
}

$('btn-new-bucket')?.addEventListener('click', () => openModal({
  title: 'Tạo S3 Bucket mới',
  fields: [
    { id: 'm-bname', label: 'Tên bucket (chuẩn DNS, chữ thường)', value: '' },
    { id: 'm-bregion', label: 'Region', value: 'us-east-1' },
  ],
  onOk: async () => {
    const name = $('m-bname').value.trim();
    const region = $('m-bregion').value.trim() || 'us-east-1';
    if (!name) return 'Tên bucket không được để trống';
    const r = await api('/admin/api/buckets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, region }),
    });
    const d = await r.json();
    if (r.ok && d.ok) {
      toast(`Đã tạo bucket '${name}'`, 'ok');
      loadBuckets();
      return null;
    }
    return d.error || 'Tạo bucket thất bại';
  },
}));

/* ---------- File Browser (AWS S3-like hierarchical view) ---------- */
function openFileBrowser(bucket, prefix = '') {
  state.currentBucket = bucket;
  state.currentPrefix = prefix;
  state.selectedObjects.clear();
  $('bucket-list-view')?.classList.add('hidden');
  $('file-browser')?.classList.remove('hidden');
  closeObjectDetail();
  renderBreadcrumb();
  loadPrefixObjects();
}

$('fb-back')?.addEventListener('click', () => {
  $('file-browser')?.classList.add('hidden');
  $('bucket-list-view')?.classList.remove('hidden');
  closeObjectDetail();
  loadBuckets();
});

function renderBreadcrumb() {
  const bc = $('fb-breadcrumb');
  if (!bc) return;
  const parts = state.currentPrefix.split('/').filter(Boolean);
  let html = `<span class="crumb" data-prefix="">${esc(state.currentBucket)}</span>`;
  let accum = '';
  parts.forEach((p, idx) => {
    accum += p + '/';
    const isLast = idx === parts.length - 1;
    html += ` <span class="crumb-sep">/</span> <span class="crumb ${isLast ? 'active' : ''}" data-prefix="${esc(accum)}">${esc(p)}</span>`;
  });
  bc.innerHTML = html;

  bc.querySelectorAll('.crumb').forEach((el) => {
    if (!el.classList.contains('active')) {
      el.addEventListener('click', () => {
        state.currentPrefix = el.dataset.prefix;
        state.selectedObjects.clear();
        renderBreadcrumb();
        loadPrefixObjects();
      });
    }
  });
}

async function loadPrefixObjects() {
  const tb = $('fb-tbody');
  if (tb) tb.innerHTML = '<tr><td colspan="7" class="muted">Đang nạp file…</td></tr>';
  $('fb-error')?.classList.add('hidden');
  updateBatchBar();

  try {
    const p = new URLSearchParams({
      prefix: state.currentPrefix,
      delimiter: '/',
    });
    const r = await api(`/admin/api/buckets/${encodeURIComponent(state.currentBucket)}/objects?${p.toString()}`);
    const d = await r.json();

    const folders = d.common_prefixes || [];
    const objects = d.objects || [];

    if (!folders.length && !objects.length) {
      tb.innerHTML = `<tr><td colspan="7" class="muted">${state.currentPrefix ? 'Thư mục rỗng' : 'Bucket rỗng'}</td></tr>`;
      return;
    }

    let rows = '';

    // Folders
    folders.forEach((folder) => {
      const folderName = folder.slice(state.currentPrefix.length);
      rows += `<tr class="fb-row-folder" data-folder="${esc(folder)}">
        <td></td>
        <td>
          <div class="fb-name-cell">
            <svg class="fb-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M1.75 1A1.75 1.75 0 0 0 0 2.75v10.5C0 14.216.784 15 1.75 15h12.5A1.75 1.75 0 0 0 16 13.25v-8.5A1.75 1.75 0 0 0 14.25 3H7.5a.25.25 0 0 1-.2-.1l-.9-1.2A1.75 1.75 0 0 0 4.9 1H1.75z"/></svg>
            <strong>${esc(folderName)}</strong>
          </div>
        </td>
        <td class="muted">—</td>
        <td><span class="badge">folder</span></td>
        <td class="muted">—</td>
        <td class="muted">—</td>
        <td></td>
      </tr>`;
    });

    // Objects
    objects.forEach((obj) => {
      const fileName = obj.key.slice(state.currentPrefix.length);
      const isChecked = state.selectedObjects.has(obj.key);
      rows += `<tr>
        <td><input type="checkbox" class="fb-cb" data-key="${esc(obj.key)}" ${isChecked ? 'checked' : ''}></td>
        <td>
          <div class="fb-name-cell">
            <svg class="fb-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M2 1.75C2 .784 2.784 0 3.75 0h6.586c.464 0 .909.184 1.237.513l2.914 2.914c.329.328.513.773.513 1.237v9.586A1.75 1.75 0 0 1 13.25 16H3.75A1.75 1.75 0 0 1 2 14.25V1.75z"/></svg>
            <a href="javascript:void(0)" class="fb-obj-link" data-key="${esc(obj.key)}">${esc(fileName)}</a>
          </div>
        </td>
        <td class="num mono">${fmtBytes(obj.size)}</td>
        <td><span class="badge ${obj.storage_state === 'remote' ? 'ok' : 'warn'}">${esc(obj.storage_state)}</span></td>
        <td class="mono small muted">${esc(obj.etag ? obj.etag.replace(/"/g, '') : '—')}</td>
        <td class="mono small">${esc(fmtTime(obj.created_at))}</td>
        <td>
          <button class="btn sm ghost fb-btn-detail" data-key="${esc(obj.key)}">Chi tiết</button>
          <button class="btn sm danger fb-btn-del" data-key="${esc(obj.key)}">Xóa</button>
        </td>
      </tr>`;
    });

    tb.innerHTML = rows;

    // Folder click
    tb.querySelectorAll('.fb-row-folder').forEach((el) => {
      el.addEventListener('click', (e) => {
        if (e.target.tagName === 'INPUT') return;
        state.currentPrefix = el.dataset.folder;
        state.selectedObjects.clear();
        renderBreadcrumb();
        loadPrefixObjects();
      });
    });

    // Checkbox click
    tb.querySelectorAll('.fb-cb').forEach((cb) => {
      cb.addEventListener('change', () => {
        if (cb.checked) state.selectedObjects.add(cb.dataset.key);
        else state.selectedObjects.delete(cb.dataset.key);
        updateBatchBar();
      });
    });

    // Object detail click
    tb.querySelectorAll('.fb-obj-link, .fb-btn-detail').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        openObjectDetail(el.dataset.key);
      });
    });

    // Single object delete
    tb.querySelectorAll('.fb-btn-del').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        const key = el.dataset.key;
        if (confirm(`Xóa object '${key}'?`)) {
          deleteSingleObject(key);
        }
      });
    });

  } catch (e) {
    if (tb) tb.innerHTML = '';
    const fe = $('fb-error');
    if (fe) {
      fe.textContent = 'Lỗi nạp objects: ' + e.message;
      fe.classList.remove('hidden');
    }
  }
}

$('fb-select-all')?.addEventListener('change', (e) => {
  const checked = e.target.checked;
  document.querySelectorAll('.fb-cb').forEach((cb) => {
    cb.checked = checked;
    if (checked) state.selectedObjects.add(cb.dataset.key);
    else state.selectedObjects.delete(cb.dataset.key);
  });
  updateBatchBar();
});

function updateBatchBar() {
  const count = state.selectedObjects.size;
  const bar = $('fb-batch-bar');
  if (bar) {
    bar.classList.toggle('hidden', count === 0);
    $('fb-selected-count').textContent = count;
  }
}

$('fb-batch-delete')?.addEventListener('click', async () => {
  const count = state.selectedObjects.size;
  if (!count) return;
  if (!confirm(`Xóa vĩnh viễn ${count} object đã chọn khỏi bucket '${state.currentBucket}'?`)) return;

  const btn = $('fb-batch-delete');
  btn.disabled = true;
  let deleted = 0;
  for (const key of Array.from(state.selectedObjects)) {
    try {
      const r = await api(`/admin/api/buckets/${encodeURIComponent(state.currentBucket)}/objects/${encodeURIComponent(key)}`, {
        method: 'DELETE',
      });
      if (r.ok) deleted++;
    } catch {}
  }
  toast(`Đã xóa ${deleted}/${count} objects`, 'ok');
  state.selectedObjects.clear();
  btn.disabled = false;
  loadPrefixObjects();
});

async function deleteSingleObject(key) {
  try {
    const r = await api(`/admin/api/buckets/${encodeURIComponent(state.currentBucket)}/objects/${encodeURIComponent(key)}`, {
      method: 'DELETE',
    });
    const d = await r.json();
    if (r.ok && d.ok) {
      toast(`Đã xóa '${key}'`, 'ok');
      closeObjectDetail();
      loadPrefixObjects();
    } else {
      toast(d.error || 'Xóa thất bại', 'err');
    }
  } catch (e) {
    toast(e.message, 'err');
  }
}

/* ---------- Object Detail Side Panel ---------- */
async function openObjectDetail(key) {
  const panel = $('object-detail');
  const body = $('od-body');
  if (!panel || !body) return;

  panel.classList.remove('hidden');
  $('od-title').textContent = 'Chi tiết object';
  body.innerHTML = '<div class="muted">Đang nạp thông tin…</div>';

  try {
    const r = await api(`/admin/api/buckets/${encodeURIComponent(state.currentBucket)}/objects/${encodeURIComponent(key)}`);
    const d = await r.json();
    const obj = d.object || {};

    body.innerHTML = `
      <div class="sp-row"><span class="sp-label">Key:</span><span class="sp-val mono"><strong>${esc(obj.key)}</strong></span></div>
      <div class="sp-row"><span class="sp-label">Bucket:</span><span class="sp-val">${esc(state.currentBucket)}</span></div>
      <div class="sp-row"><span class="sp-label">Kích thước:</span><span class="sp-val mono">${fmtBytes(obj.size)} (${obj.size ?? 0} bytes)</span></div>
      <div class="sp-row"><span class="sp-label">Trạng thái:</span><span class="sp-val"><span class="badge ${obj.storage_state === 'remote' ? 'ok' : 'warn'}">${esc(obj.storage_state)}</span></span></div>
      <div class="sp-row"><span class="sp-label">ETag:</span><span class="sp-val mono">${esc(obj.etag || '—')}</span></div>
      <div class="sp-row"><span class="sp-label">Version ID:</span><span class="sp-val mono">${esc(obj.version_id || 'null')}</span></div>
      <div class="sp-row"><span class="sp-label">Content-Type:</span><span class="sp-val">${esc(obj.content_type || 'application/octet-stream')}</span></div>
      <div class="sp-row"><span class="sp-label">Khởi tạo:</span><span class="sp-val mono small">${esc(fmtTime(obj.created_at))}</span></div>
      <div class="sp-row"><span class="sp-label">Cập nhật:</span><span class="sp-val mono small">${esc(fmtTime(obj.updated_at))}</span></div>
      <hr style="border:0;border-top:1px solid var(--border);margin:12px 0">
      <div style="display:flex;gap:8px">
        <button class="btn sm danger block" id="od-btn-del">Xóa object này</button>
      </div>
    `;

    $('od-btn-del')?.addEventListener('click', () => {
      if (confirm(`Xóa object '${key}'?`)) {
        deleteSingleObject(key);
      }
    });
  } catch (e) {
    body.innerHTML = `<div class="alert-error">Lỗi nạp chi tiết: ${esc(e.message)}</div>`;
  }
}

function closeObjectDetail() {
  $('object-detail')?.classList.add('hidden');
}
$('od-close')?.addEventListener('click', closeObjectDetail);

/* ==========================================================================
   Access Keys Tab
   ========================================================================== */
async function loadKeys() {
  const tb = $('key-tbody');
  if (tb) tb.innerHTML = '<tr><td colspan="7" class="muted">Đang nạp…</td></tr>';
  $('key-error')?.classList.add('hidden');
  try {
    const r = await api('/admin/api/access-keys');
    const d = await r.json();
    state.keys = Array.isArray(d) ? d : (d.access_keys || []);
    renderKeys();
  } catch (e) {
    if (tb) tb.innerHTML = '';
    const ke = $('key-error');
    if (ke) {
      ke.textContent = 'Lỗi nạp keys: ' + e.message;
      ke.classList.remove('hidden');
    }
  }
}

function renderKeys() {
  const q = $('q-key')?.value.toLowerCase().trim() || '';
  const list = state.keys.filter((k) => (k.access_key_id || '').toLowerCase().includes(q) || (k.user_id || '').toLowerCase().includes(q));
  const tb = $('key-tbody');
  if (!tb) return;

  if (!list.length) {
    tb.innerHTML = `<tr><td colspan="7" class="muted">${state.keys.length ? 'Không khớp bộ lọc' : 'Chưa có access key nào — bấm "Tạo key" để tạo'}</td></tr>`;
    return;
  }

  tb.innerHTML = list.map((k) => `<tr>
    <td class="mono"><strong>${esc(k.access_key_id)}</strong></td>
    <td>${esc(k.user_id || 'admin')}</td>
    <td><span class="badge ${k.status === 'active' ? 'ok' : 'err'}">${esc(k.status || 'active')}</span></td>
    <td class="mono small">${esc(k.allowed_buckets || '*')}</td>
    <td class="mono small">${k.last_used_at ? esc(fmtTime(k.last_used_at)) : '<span class="muted">chưa dùng</span>'}</td>
    <td class="mono small">${esc(fmtTime(k.created_at))}</td>
    <td>
      <button class="btn sm ghost btn-toggle-key" data-id="${esc(k.access_key_id)}" data-status="${esc(k.status || 'active')}">
        ${k.status === 'active' ? 'Tạm dừng' : 'Kích hoạt'}
      </button>
      <button class="btn sm danger btn-revoke-key" data-id="${esc(k.access_key_id)}">Thu hồi</button>
    </td>
  </tr>`).join('');

  tb.querySelectorAll('.btn-toggle-key').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.dataset.id;
      const nextStatus = btn.dataset.status === 'active' ? 'inactive' : 'active';
      try {
        const r = await api(`/admin/api/access-keys/${encodeURIComponent(id)}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: nextStatus }),
        });
        if (r.ok) {
          toast(`Đã đổi trạng thái key sang ${nextStatus}`, 'ok');
          loadKeys();
        } else {
          const d = await r.json();
          toast(d.error || 'Cập nhật thất bại', 'err');
        }
      } catch (e) {
        toast(e.message, 'err');
      }
    });
  });

  tb.querySelectorAll('.btn-revoke-key').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.dataset.id;
      if (!confirm(`Thu hồi vĩnh viễn key '${id}'? Các ứng dụng dùng key này sẽ lập tức mất quyền truy cập S3.`)) return;
      try {
        const r = await api(`/admin/api/access-keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
        const d = await r.json();
        if (r.ok && d.ok) {
          toast('Đã thu hồi key', 'ok');
          loadKeys();
        } else {
          toast(d.error || 'Thu hồi thất bại', 'err');
        }
      } catch (e) {
        toast(e.message, 'err');
      }
    });
  });
}

$('q-key')?.addEventListener('input', renderKeys);

$('btn-new-key')?.addEventListener('click', () => openModal({
  title: 'Tạo Access Key mới',
  fields: [
    { id: 'm-kuser', label: 'Tên / Mô tả người dùng', value: 'admin' },
    { id: 'm-kbuckets', label: 'Buckets được phép (* = tất cả, hoặc phân cách bằng dấu phẩy)', value: '*' },
    { id: 'm-kpolicy', label: 'Chính sách (read-write, read-only, admin)', value: 'read-write' },
  ],
  onOk: async () => {
    const r = await api('/admin/api/access-keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: $('m-kuser').value.trim() || 'admin',
        allowed_buckets: $('m-kbuckets').value.trim() || '*',
        policy: $('m-kpolicy').value.trim() || 'read-write',
      }),
    });
    const d = await r.json();
    if (r.ok && d.ok && d.secret_key) {
      const box = $('new-secret');
      if (box) {
        box.innerHTML = `
          <strong>LƯU Ý QUAN TRỌNG — Secret key chỉ hiển thị ĐÚNG 1 LẦN:</strong><br>
          <div style="margin-top:6px;font-family:var(--mono);background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--border)">
            Access Key ID: <strong>${esc(d.access_key_id)}</strong><br>
            Secret Key:    <strong>${esc(d.secret_key)}</strong>
          </div>
        `;
        box.classList.remove('hidden');
      }
      loadKeys();
      return null;
    }
    return (d && d.error) || 'Tạo key thất bại';
  },
}));

/* ==========================================================================
   Configuration Tab
   ========================================================================== */
async function loadConfig() {
  const err = $('config-error');
  err?.classList.add('hidden');
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
    if (err) {
      err.textContent = 'Lỗi nạp cấu hình: ' + e.message;
      err.classList.remove('hidden');
    }
  }
}

$('btn-tg-test')?.addEventListener('click', async () => {
  const res = $('tg-test-result');
  if (res) res.textContent = 'Đang kiểm tra kết nối Telegram…';
  try {
    const r = await api('/admin/api/telegram/test', { method: 'POST' });
    const d = await r.json();
    if (r.ok && d.ok) {
      if (res) res.textContent = `Kết nối thành công! Bot: @${d.username || 'bot'}`;
      toast('Telegram API hoạt động bình thường', 'ok');
    } else {
      if (res) res.textContent = `Thất bại: ${d.error || 'Không kết nối được'}`;
      toast('Kiểm tra Telegram thất bại', 'err');
    }
  } catch (e) {
    if (res) res.textContent = 'Lỗi: ' + e.message;
    toast(e.message, 'err');
  }
});

$('config-form')?.addEventListener('submit', async (e) => {
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
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, value }),
      });
      if (r.ok) ok++;
      else if (!firstErr) {
        try { firstErr = (await r.json()).error || ''; } catch {}
      }
    } catch (ex) {
      if (!firstErr) firstErr = ex.message;
    }
  }
  if (ok === items.length) {
    toast('Đã lưu cấu hình thành công', 'ok');
    $('cfg-token').value = '';
    $('cfg-adminpwd').value = '';
  } else {
    toast(`Lưu ${ok}/${items.length}${firstErr ? ' — lỗi: ' + firstErr : ''}`, 'err');
  }
  loadConfig();
});

/* ==========================================================================
   Jobs Tab
   ========================================================================== */
async function loadJobs() {
  const tb = $('jobs-tbody');
  if (tb) tb.innerHTML = '<tr><td colspan="7" class="muted">Đang nạp jobs…</td></tr>';
  $('jobs-error')?.classList.add('hidden');
  try {
    const filter = state.jobFilter || $('jobs-filter')?.value || '';
    const p = new URLSearchParams();
    if (filter) p.set('state', filter);
    const r = await api('/admin/api/jobs?' + p.toString());
    const d = await r.json();

    const counts = d.counts || { pending: 0, uploading: 0, completed: 0, failed: 0 };
    renderPipelineBar(counts);

    const list = d.jobs || [];
    if (!list.length) {
      tb.innerHTML = '<tr><td colspan="7" class="muted">Không có job nào phù hợp</td></tr>';
      return;
    }

    tb.innerHTML = list.map((j) => `<tr>
      <td class="mono small">#${esc(j.id)}</td>
      <td class="mono"><strong>${esc(j.bucket)}</strong> / ${esc(j.key)}</td>
      <td><span class="badge ${j.state === 'completed' ? 'ok' : j.state === 'uploading' ? 'info' : j.state === 'failed' ? 'err' : 'warn'}">${esc(j.state)}</span></td>
      <td class="num mono">${j.retry_count ?? 0}</td>
      <td class="mono small">${j.next_attempt_at ? esc(fmtTime(j.next_attempt_at)) : '—'}</td>
      <td class="mono small">${j.worker_id ? esc(j.worker_id) : '<span class="muted">—</span>'}</td>
      <td class="small ${j.last_error ? 'muted' : 'muted'}">${esc(j.last_error || '—')}</td>
    </tr>`).join('');
  } catch (e) {
    if (tb) tb.innerHTML = '';
    const je = $('jobs-error');
    if (je) {
      je.textContent = 'Lỗi nạp jobs: ' + e.message;
      je.classList.remove('hidden');
    }
  }
}

function renderPipelineBar(counts) {
  const bar = $('pipeline-bar');
  if (!bar) return;
  const steps = [
    { id: 'pending', label: 'Chờ upload', count: counts.pending || 0 },
    { id: 'uploading', label: 'Đang tải lên', count: counts.uploading || 0 },
    { id: 'completed', label: 'Hoàn tất', count: counts.completed || 0 },
    { id: 'failed', label: 'Thất bại', count: counts.failed || 0 },
  ];
  bar.innerHTML = steps.map((s) => `
    <div class="pipe-step ${state.jobFilter === s.id ? 'active' : ''}" data-state="${s.id}">
      <div class="pipe-count">${s.count}</div>
      <div class="pipe-label">${s.label}</div>
    </div>
  `).join('');

  bar.querySelectorAll('.pipe-step').forEach((el) => {
    el.addEventListener('click', () => {
      state.jobFilter = state.jobFilter === el.dataset.state ? '' : el.dataset.state;
      if ($('jobs-filter')) $('jobs-filter').value = state.jobFilter;
      loadJobs();
    });
  });
}

$('jobs-filter')?.addEventListener('change', (e) => {
  state.jobFilter = e.target.value;
  loadJobs();
});

/* ==========================================================================
   Maintenance Tab (GC, Doctor, Backup & Multipart Uploads)
   ========================================================================== */
async function loadMaintenance() {
  loadMultipartUploads();
}

document.querySelectorAll('[data-op]').forEach((b) => b.addEventListener('click', async () => {
  const out = $(b.dataset.out);
  if (out) {
    out.classList.remove('hidden');
    out.textContent = 'Đang thực hiện…';
  }
  b.disabled = true;
  try {
    const r = await api(b.dataset.op, { method: 'POST' });
    const d = await r.json();
    if (out) out.textContent = JSON.stringify(d, null, 2);
    toast(r.ok ? 'Hoàn tất' : 'Có lỗi — xem chi tiết output', r.ok ? 'ok' : 'err');
  } catch (e) {
    if (out) out.textContent = 'Lỗi: ' + e.message;
    toast('Lỗi thực thi', 'err');
  }
  b.disabled = false;
}));

async function loadMultipartUploads() {
  const tb = $('mp-tbody');
  if (tb) tb.innerHTML = '<tr><td colspan="6" class="muted">Đang nạp…</td></tr>';
  $('mp-error')?.classList.add('hidden');
  try {
    const r = await api('/admin/api/multipart/uploads');
    const d = await r.json();
    const list = d.uploads || [];
    if (!list.length) {
      tb.innerHTML = '<tr><td colspan="6" class="muted">Không có multipart upload nào đang dở dang</td></tr>';
      return;
    }
    tb.innerHTML = list.map((u) => `<tr>
      <td class="mono small"><strong>${esc(u.upload_id)}</strong></td>
      <td>${esc(u.bucket)}</td>
      <td class="mono">${esc(u.key)}</td>
      <td>${esc(u.content_type || '—')}</td>
      <td class="mono small">${esc(fmtTime(u.initiated_at))}</td>
      <td><button class="btn sm danger btn-abort-mp" data-id="${esc(u.upload_id)}">Hủy upload</button></td>
    </tr>`).join('');

    tb.querySelectorAll('.btn-abort-mp').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        if (!confirm(`Hủy upload '${id}' và xóa các chunks tạm thời?`)) return;
        try {
          const r = await api(`/admin/api/multipart/${encodeURIComponent(id)}/abort`, { method: 'POST' });
          if (r.ok) {
            toast('Đã hủy multipart upload', 'ok');
            loadMultipartUploads();
          } else {
            const d = await r.json();
            toast(d.error || 'Hủy thất bại', 'err');
          }
        } catch (e) {
          toast(e.message, 'err');
        }
      });
    });
  } catch (e) {
    if (tb) tb.innerHTML = '';
    const me = $('mp-error');
    if (me) {
      me.textContent = 'Lỗi nạp multipart uploads: ' + e.message;
      me.classList.remove('hidden');
    }
  }
}

/* ==========================================================================
   Audit Logs Tab
   ========================================================================== */
const LV_CLASS = { info: 'info', warn: 'warn', error: 'err' };

async function loadLogs() {
  const err = $('log-error');
  err?.classList.add('hidden');
  const tb = $('log-tbody');
  try {
    const p = new URLSearchParams({
      limit: 50,
      offset: state.logOffset,
    });
    if (state.logLevel) p.set('level', state.logLevel);
    const q = $('log-q')?.value.trim() || '';
    if (q) p.set('q', q);

    const r = await api('/admin/api/audit-logs?' + p.toString());
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const list = d.entries || [];
    state.logTotal = d.total || 0;

    if (!list.length) {
      tb.innerHTML = '<tr><td colspan="5" class="muted">Không có bản ghi nào phù hợp</td></tr>';
    } else {
      tb.innerHTML = list.map((e) => `<tr>
        <td class="mono small">${esc(fmtTime(e.ts))}</td>
        <td><span class="badge ${LV_CLASS[e.level] || ''}">${esc(e.level)}</span></td>
        <td><strong>${esc(e.actor)}</strong></td>
        <td class="mono">${esc(e.action)}</td>
        <td class="small">${esc(e.detail)}</td>
      </tr>`).join('');
    }

    const pages = Math.max(1, Math.ceil(state.logTotal / 50));
    const cur = Math.floor(state.logOffset / 50) + 1;
    $('log-page').textContent = `Trang ${cur}/${pages} — tổng ${state.logTotal}`;
    $('log-prev').disabled = state.logOffset === 0;
    $('log-next').disabled = state.logOffset + 50 >= state.logTotal;
  } catch (e) {
    if (err) {
      err.textContent = 'Lỗi nạp nhật ký: ' + e.message;
      err.classList.remove('hidden');
    }
  }
}

document.querySelectorAll('#log-level-seg .seg').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#log-level-seg .seg').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    state.logLevel = btn.dataset.lv || '';
    state.logOffset = 0;
    loadLogs();
  });
});

$('btn-log-reload')?.addEventListener('click', () => { state.logOffset = 0; loadLogs(); });
$('log-q')?.addEventListener('input', () => { state.logOffset = 0; loadLogs(); });
$('log-prev')?.addEventListener('click', () => { state.logOffset = Math.max(0, state.logOffset - 50); loadLogs(); });
$('log-next')?.addEventListener('click', () => { state.logOffset += 50; loadLogs(); });

$('btn-log-export')?.addEventListener('click', async () => {
  try {
    const r = await api('/admin/api/audit-logs?limit=1000');
    const d = await r.json();
    const blob = new Blob([JSON.stringify(d.entries || [], null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'telecrate-audit.json';
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Đã xuất nhật ký (đã redact dữ liệu nhạy cảm)', 'ok');
  } catch (e) {
    toast('Xuất thất bại: ' + e.message, 'err');
  }
});

/* ==========================================================================
   Generic Modal
   ========================================================================== */
let modalOk = null;
function openModal({ title, fields, onOk }) {
  $('modal-title').textContent = title;
  $('modal-fields').innerHTML = fields.map((f) =>
    `<label class="field"><span>${esc(f.label)}</span><input id="${f.id}" value="${esc(f.value || '')}"></label>`
  ).join('');
  $('modal-error')?.classList.add('hidden');
  modalOk = onOk;
  $('modal')?.classList.remove('hidden');
  const first = $('modal-fields')?.querySelector('input');
  if (first) first.focus();
}

function closeModal() {
  $('modal')?.classList.add('hidden');
  modalOk = null;
}

$('modal-cancel')?.addEventListener('click', closeModal);
$('modal')?.addEventListener('click', (e) => { if (e.target === $('modal')) closeModal(); });

$('modal-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!modalOk) return;
  const err = $('modal-error');
  err?.classList.add('hidden');
  $('modal-ok').disabled = true;
  try {
    const msg = await modalOk();
    if (msg) {
      err.textContent = msg;
      err.classList.remove('hidden');
    } else {
      closeModal();
    }
  } catch (ex) {
    err.textContent = ex.message;
    err.classList.remove('hidden');
  }
  $('modal-ok').disabled = false;
});

/* ==========================================================================
   Start & Viewport Handling
   ========================================================================== */
let resizeTimer = null;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    if (state.tab === 'overview') drawAllCharts();
  }, 100);
});

initTheme();
checkSession();
})();

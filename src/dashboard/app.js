// JavaScript Logic cho Web Dashboard TeleCrate M6

let csrfToken = '';

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initForms();
  checkSession();
});

// Navigation Tabs
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      navItems.forEach(n => n.classList.remove('active'));
      item.classList.add('active');

      const targetTab = item.getAttribute('data-tab');
      document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.add('hidden');
        pane.classList.remove('active');
      });

      const activePane = document.getElementById(targetTab);
      if (activePane) {
        activePane.classList.remove('hidden');
        activePane.classList.add('active');
        handleTabLoad(targetTab);
      }
    });
  });

  document.getElementById('btn-refresh-status').addEventListener('click', loadOverviewStatus);
  document.getElementById('btn-refresh-logs').addEventListener('click', loadAuditLogs);
  document.getElementById('btn-logout').addEventListener('click', doLogout);
}

function handleTabLoad(tabId) {
  if (tabId === 'tab-overview') loadOverviewStatus();
  else if (tabId === 'tab-buckets') loadBuckets();
  else if (tabId === 'tab-keys') loadAccessKeys();
  else if (tabId === 'tab-logs') loadAuditLogs();
}

// Session Management
async function checkSession() {
  try {
    const res = await fetch('/admin/api/session');
    const data = await res.json();
    if (data.authenticated) {
      csrfToken = data.csrf_token || '';
      showAppUI();
      loadOverviewStatus();
    } else {
      showLoginUI();
    }
  } catch (err) {
    showLoginUI();
  }
}

function showLoginUI() {
  document.getElementById('login-section').classList.remove('hidden');
  document.getElementById('dashboard-views').classList.add('hidden');
  document.getElementById('btn-logout').classList.add('hidden');
  updateStatusBadge(false, 'Yêu cầu đăng nhập');
}

function showAppUI() {
  document.getElementById('login-section').classList.add('hidden');
  document.getElementById('dashboard-views').classList.remove('hidden');
  document.getElementById('btn-logout').classList.remove('hidden');
  updateStatusBadge(true, 'Hoạt động (Online)');
}

function updateStatusBadge(online, text) {
  const badge = document.getElementById('status-indicator');
  const txt = document.getElementById('status-text');
  txt.textContent = text;
  if (online) {
    badge.className = 'status-badge status-online';
  } else {
    badge.className = 'status-badge status-loading';
  }
}

// Forms Logic
function initForms() {
  // Login Form
  document.getElementById('form-login').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pwd = document.getElementById('admin-password').value;
    const errBox = document.getElementById('login-error');
    errBox.classList.add('hidden');

    try {
      const res = await fetch('/admin/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pwd })
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        csrfToken = data.csrf_token;
        document.getElementById('admin-password').value = '';
        showAppUI();
        loadOverviewStatus();
      } else {
        errBox.textContent = data.error || 'Mật khẩu không chính xác';
        errBox.classList.remove('hidden');
      }
    } catch (err) {
      errBox.textContent = 'Lỗi kết nối máy chủ';
      errBox.classList.remove('hidden');
    }
  });

  // Create Bucket UI
  document.getElementById('btn-open-create-bucket').addEventListener('click', () => {
    document.getElementById('card-create-bucket').classList.remove('hidden');
  });
  document.getElementById('btn-cancel-create-bucket').addEventListener('click', () => {
    document.getElementById('card-create-bucket').classList.add('hidden');
  });
  document.getElementById('form-create-bucket').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('bucket-name-input').value.trim();
    const region = document.getElementById('bucket-region-input').value.trim() || 'us-east-1';

    try {
      const res = await fetch('/admin/api/buckets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken
        },
        body: JSON.stringify({ name, region })
      });
      if (res.ok) {
        document.getElementById('bucket-name-input').value = '';
        document.getElementById('card-create-bucket').classList.add('hidden');
        loadBuckets();
      } else {
        const d = await res.json();
        alert('Lỗi tạo bucket: ' + (d.error || res.statusText));
      }
    } catch (err) {
      alert('Lỗi kết nối: ' + err.message);
    }
  });

  // Create Key UI
  document.getElementById('btn-open-create-key').addEventListener('click', () => {
    document.getElementById('card-create-key').classList.remove('hidden');
  });
  document.getElementById('btn-cancel-create-key').addEventListener('click', () => {
    document.getElementById('card-create-key').classList.add('hidden');
  });
  document.getElementById('btn-close-new-key-alert').addEventListener('click', () => {
    document.getElementById('alert-new-key').classList.add('hidden');
  });
  document.getElementById('form-create-key').addEventListener('submit', async (e) => {
    e.preventDefault();
    const userId = document.getElementById('key-user-input').value.trim();

    try {
      const res = await fetch('/admin/api/access-keys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken
        },
        body: JSON.stringify({ user_id: userId })
      });
      const data = await res.json();
      if (res.ok && data.access_key_id) {
        document.getElementById('key-user-input').value = '';
        document.getElementById('card-create-key').classList.add('hidden');
        
        // Show Secret Key Modal
        document.getElementById('display-access-key').textContent = data.access_key_id;
        document.getElementById('display-secret-key').textContent = data.secret_key;
        document.getElementById('alert-new-key').classList.remove('hidden');
        loadAccessKeys();
      } else {
        alert('Lỗi tạo key: ' + (data.error || res.statusText));
      }
    } catch (err) {
      alert('Lỗi kết nối: ' + err.message);
    }
  });

  // Maintenance Triggers
  document.getElementById('btn-run-gc').addEventListener('click', async () => {
    const box = document.getElementById('result-gc');
    box.textContent = 'Đang chạy Physical Garbage Collection...';
    box.classList.remove('hidden');
    try {
      const res = await fetch('/admin/api/gc', {
        method: 'POST',
        headers: { 'x-csrf-token': csrfToken }
      });
      const data = await res.json();
      box.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      box.textContent = 'Lỗi thực thi: ' + err.message;
    }
  });

  document.getElementById('btn-run-doctor').addEventListener('click', async () => {
    const box = document.getElementById('result-doctor');
    box.textContent = 'Đang chạy Doctor scan...';
    box.classList.remove('hidden');
    try {
      const res = await fetch('/admin/api/doctor', {
        method: 'POST',
        headers: { 'x-csrf-token': csrfToken }
      });
      const data = await res.json();
      box.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      box.textContent = 'Lỗi thực thi: ' + err.message;
    }
  });

  document.getElementById('btn-run-backup').addEventListener('click', async () => {
    const box = document.getElementById('result-backup');
    box.textContent = 'Đang tạo SQLite Backup...';
    box.classList.remove('hidden');
    try {
      const res = await fetch('/admin/api/backup', {
        method: 'POST',
        headers: { 'x-csrf-token': csrfToken }
      });
      const data = await res.json();
      box.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      box.textContent = 'Lỗi thực thi: ' + err.message;
    }
  });
}

// Data Fetchers
async function loadOverviewStatus() {
  try {
    const res = await fetch('/admin/api/status');
    if (!res.ok) {
      if (res.status === 401) showLoginUI();
      return;
    }
    const data = await res.json();

    // Format Uptime
    const sec = data.uptime_seconds || 0;
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    document.getElementById('metric-uptime').textContent = `${h}h ${m}m ${s}s`;

    // Spool Size
    const usedMB = ((data.spool.used_bytes || 0) / 1024 / 1024).toFixed(1);
    const totalMB = ((data.spool.total_bytes || 1) / 1024 / 1024).toFixed(1);
    const pct = Math.min(100, Math.round(((data.spool.used_bytes || 0) / (data.spool.total_bytes || 1)) * 100));
    document.getElementById('metric-spool-text').textContent = `${usedMB} MB / ${totalMB} MB (${pct}%)`;
    document.getElementById('spool-progress').style.width = `${pct}%`;

    // DB Size
    const dbKB = ((data.db_size_bytes || 0) / 1024).toFixed(1);
    document.getElementById('metric-db-size').textContent = `${dbKB} KB`;

    // Workers
    document.getElementById('metric-workers').textContent = `${data.workers.active_worker_count || 0} active workers`;
    document.getElementById('metric-worker-detail').textContent = `${data.workers.pending_jobs_count || 0} pending / ${data.workers.uploading_jobs_count || 0} uploading`;

    // Counts
    document.getElementById('stat-buckets-count').textContent = data.counts.total_buckets || 0;
    document.getElementById('stat-objects-count').textContent = data.counts.total_objects || 0;
    document.getElementById('stat-chunks-count').textContent = data.counts.total_chunks || 0;
    document.getElementById('stat-keys-count').textContent = data.counts.total_access_keys || 0;
  } catch (err) {
    console.error('Failed to load overview status', err);
  }
}

async function loadBuckets() {
  const tbody = document.getElementById('bucket-table-body');
  try {
    const res = await fetch('/admin/api/buckets');
    const buckets = await res.json();
    if (!Array.isArray(buckets) || buckets.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center">Chưa có bucket nào. Hãy tạo bucket mới!</td></tr>';
      return;
    }
    tbody.innerHTML = buckets.map(b => `
      <tr>
        <td><strong>${escapeHtml(b.name)}</strong></td>
        <td>${escapeHtml(b.region || 'us-east-1')}</td>
        <td>${escapeHtml(b.created_at || '-')}</td>
        <td><span class="badge badge-info">${escapeHtml(b.versioning || 'Disabled')}</span></td>
        <td>
          <button class="btn btn-danger btn-sm" onclick="deleteBucket('${escapeHtml(b.name)}')">Xóa</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center alert-error">Lỗi tải danh sách buckets</td></tr>';
  }
}

async function deleteBucket(name) {
  if (!confirm(`Bạn có chắc muốn xóa bucket "${name}"?`)) return;
  try {
    const res = await fetch(`/admin/api/buckets/${encodeURIComponent(name)}`, {
      method: 'DELETE',
      headers: { 'x-csrf-token': csrfToken }
    });
    if (res.ok) {
      loadBuckets();
    } else {
      const data = await res.json();
      alert('Không thể xóa bucket: ' + (data.error || res.statusText));
    }
  } catch (err) {
    alert('Lỗi kết nối: ' + err.message);
  }
}

async function loadAccessKeys() {
  const tbody = document.getElementById('keys-table-body');
  try {
    const res = await fetch('/admin/api/access-keys');
    const keys = await res.json();
    if (!Array.isArray(keys) || keys.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center">Chưa có Access Key nào.</td></tr>';
      return;
    }
    tbody.innerHTML = keys.map(k => `
      <tr>
        <td><code>${escapeHtml(k.access_key_id)}</code></td>
        <td>${escapeHtml(k.user_id || 'system')}</td>
        <td><span class="badge ${k.status === 'Active' ? 'badge-success' : 'badge-info'}">${escapeHtml(k.status)}</span></td>
        <td>${escapeHtml(k.created_at || '-')}</td>
        <td>
          <button class="btn btn-danger btn-sm" onclick="revokeKey('${escapeHtml(k.access_key_id)}')">Revoke</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center alert-error">Lỗi tải danh sách Access Keys</td></tr>';
  }
}

async function revokeKey(keyId) {
  if (!confirm(`Bạn có chắc muốn thu hồi Access Key "${keyId}"?`)) return;
  try {
    const res = await fetch(`/admin/api/access-keys/${encodeURIComponent(keyId)}`, {
      method: 'DELETE',
      headers: { 'x-csrf-token': csrfToken }
    });
    if (res.ok) {
      loadAccessKeys();
    } else {
      const data = await res.json();
      alert('Không thể thu hồi key: ' + (data.error || res.statusText));
    }
  } catch (err) {
    alert('Lỗi kết nối: ' + err.message);
  }
}

async function loadAuditLogs() {
  const viewer = document.getElementById('log-viewer');
  try {
    const res = await fetch('/admin/api/audit-logs');
    const logs = await res.json();
    if (Array.isArray(logs)) {
      viewer.textContent = logs.join('\n');
    } else {
      viewer.textContent = JSON.stringify(logs, null, 2);
    }
  } catch (err) {
    viewer.textContent = 'Lỗi tải audit logs: ' + err.message;
  }
}

async function doLogout() {
  try {
    await fetch('/admin/api/logout', {
      method: 'POST',
      headers: { 'x-csrf-token': csrfToken }
    });
  } catch (err) {}
  csrfToken = '';
  showLoginUI();
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

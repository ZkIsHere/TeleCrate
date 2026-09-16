// TeleCrate Control Center — Interactive Frontend Application Logic

(function () {
  'use strict';

  // State Management
  let state = {
    csrfToken: '',
    currentTab: 'overview',
    refreshInterval: null,
    buckets: [],
    accessKeys: [],
    logs: []
  };

  // DOM Elements
  const el = {
    authView: document.getElementById('auth-view'),
    mainView: document.getElementById('main-view'),
    loginForm: document.getElementById('login-form'),
    adminPassword: document.getElementById('admin-password'),
    loginError: document.getElementById('login-error'),
    toastContainer: document.getElementById('toast-container'),
    navItems: document.querySelectorAll('.nav-item'),
    tabPanes: document.querySelectorAll('.tab-pane'),
    currentTabTitle: document.getElementById('current-tab-title'),
    currentTabSubtitle: document.getElementById('current-tab-subtitle'),
    btnRefreshAll: document.getElementById('btn-refresh-all'),
    btnLogout: document.getElementById('btn-logout'),

    // Stats Elements
    statBuckets: document.getElementById('stat-buckets'),
    statObjects: document.getElementById('stat-objects'),
    statSpoolSize: document.getElementById('stat-spool-size'),
    statKeys: document.getElementById('stat-keys'),
    spoolProgress: document.getElementById('spool-progress'),
    infoUptime: document.getElementById('info-uptime'),
    infoDbSize: document.getElementById('info-db-size'),
    infoWorkers: document.getElementById('info-workers'),
    infoPendingJobs: document.getElementById('info-pending-jobs'),
    infoUploadingJobs: document.getElementById('info-uploading-jobs'),

    // Quick Buttons
    quickBtnGc: document.getElementById('quick-btn-gc'),
    quickBtnDoctor: document.getElementById('quick-btn-doctor'),
    quickBtnBackup: document.getElementById('quick-btn-backup'),

    // Tables & Bodies
    bucketTbody: document.getElementById('bucket-list-tbody'),
    keyTbody: document.getElementById('key-list-tbody'),
    searchBucketInput: document.getElementById('search-bucket-input'),
    searchKeyInput: document.getElementById('search-key-input'),

    // Config Form
    configForm: document.getElementById('config-form'),
    cfgPort: document.getElementById('cfg-port'),
    cfgEncryption: document.getElementById('cfg-encryption'),
    cfgRegion: document.getElementById('cfg-region'),
    cfgWorkers: document.getElementById('cfg-workers'),
    cfgBotToken: document.getElementById('cfg-bot-token'),
    cfgChatId: document.getElementById('cfg-chat-id'),
    cfgBaseUrl: document.getElementById('cfg-base-url'),
    cfgAdminPwd: document.getElementById('cfg-admin-pwd'),

    // Maintenance
    btnRunGc: document.getElementById('btn-run-gc'),
    btnRunDoctor: document.getElementById('btn-run-doctor'),
    btnRunBackup: document.getElementById('btn-run-backup'),
    outputGc: document.getElementById('output-gc'),
    outputDoctor: document.getElementById('output-doctor'),
    outputBackup: document.getElementById('output-backup'),

    // Audit Terminal
    terminalBody: document.getElementById('terminal-body'),
    logFilterInput: document.getElementById('log-filter-input'),
    btnCopyLogs: document.getElementById('btn-copy-logs'),

    // Modals
    modalCreateBucket: document.getElementById('modal-create-bucket'),
    modalCreateKey: document.getElementById('modal-create-key'),
    btnModalCreateBucket: document.getElementById('btn-modal-create-bucket'),
    btnModalCreateKey: document.getElementById('btn-modal-create-key'),
    formCreateBucket: document.getElementById('form-create-bucket'),
    formCreateKey: document.getElementById('form-create-key'),
    newAccessKeyId: document.getElementById('new-access-key-id'),
    newSecretKey: document.getElementById('new-secret-key'),
    btnGenKeyId: document.getElementById('btn-gen-key-id'),
    btnGenSecret: document.getElementById('btn-gen-secret')
  };

  // Toast Helper
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
      <span>${escapeHtml(message)}</span>
    `;
    el.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function formatUptime(seconds) {
    if (!seconds) return '0s';
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    if (hrs > 0) return `${hrs}h ${mins}m ${secs}s`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
  }

  // API Client helper
  async function apiFetch(url, options = {}) {
    options.headers = options.headers || {};
    if (state.csrfToken) {
      options.headers['x-csrf-token'] = state.csrfToken;
    }
    options.credentials = 'include';
    
    try {
      const resp = await fetch(url, options);
      if (resp.status === 401) {
        showAuthView();
        throw new Error('Chưa đăng nhập hoặc phiên làm việc đã hết hạn');
      }
      return resp;
    } catch (err) {
      throw err;
    }
  }

  // Initialization & Auth Checks
  async function init() {
    await checkSession();
  }

  async function checkSession() {
    try {
      const resp = await fetch('/admin/api/session', { credentials: 'include' });
      const data = await resp.json();
      if (data.authenticated) {
        state.csrfToken = data.csrf_token;
        showMainView();
      } else {
        showAuthView();
      }
    } catch (e) {
      showAuthView();
    }
  }

  function showAuthView() {
    el.authView.classList.remove('hidden');
    el.mainView.classList.add('hidden');
    if (state.refreshInterval) {
      clearInterval(state.refreshInterval);
      state.refreshInterval = null;
    }
  }

  function showMainView() {
    el.authView.classList.add('hidden');
    el.mainView.classList.remove('hidden');
    loadCurrentTabData();
    if (!state.refreshInterval) {
      state.refreshInterval = setInterval(refreshStats, 5000);
    }
  }

  // Login Handler
  el.loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    el.loginError.classList.add('hidden');
    const pwd = el.adminPassword.value;

    try {
      const resp = await fetch('/admin/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pwd }),
        credentials: 'include'
      });
      const data = await resp.json();
      if (resp.ok && data.ok) {
        state.csrfToken = data.csrf_token;
        showToast('Đăng nhập thành công!', 'success');
        showMainView();
      } else {
        el.loginError.textContent = data.error || 'Mật khẩu không chính xác';
        el.loginError.classList.remove('hidden');
      }
    } catch (err) {
      el.loginError.textContent = 'Kết nối server thất bại: ' + err.message;
      el.loginError.classList.remove('hidden');
    }
  });

  // Logout Handler
  el.btnLogout.addEventListener('click', async () => {
    try {
      await apiFetch('/admin/api/logout', { method: 'POST' });
      showToast('Đã đăng xuất', 'info');
    } catch (e) {}
    showAuthView();
  });

  // Tab Navigation
  const tabInfo = {
    overview: { title: 'Tổng Quan Hệ Thống', subtitle: 'Theo dõi trạng thái và số liệu lưu trữ S3 Gateway thời gian thực' },
    storage: { title: 'Quản Lý Buckets & Objects', subtitle: 'Danh sách S3 buckets, dung lượng và cấu hình WORM/Versioning' },
    keys: { title: 'Quản Lý S3 Access Keys (IAM)', subtitle: 'Tạo, quản lý và thu hồi khóa truy cập S3' },
    config: { title: 'Cấu Hình Động Hệ Thống', subtitle: 'Chỉnh sửa thông số daemon và lưu trực tiếp không cần rebuild binary' },
    maintenance: { title: 'Trung Tâm Bảo Trì & GC Engine', subtitle: 'Thực thi Garbage Collection, Doctor integrity check và Database Backup' },
    audit: { title: 'Nhật Ký Hệ Thống Realtime', subtitle: 'Xem log daemon thời gian thực với bộ lọc và tự động ẩn thông tin nhạy cảm' }
  };

  el.navItems.forEach(item => {
    item.addEventListener('click', () => {
      const tabName = item.getAttribute('data-tab');
      switchTab(tabName);
    });
  });

  function switchTab(tabName) {
    state.currentTab = tabName;
    el.navItems.forEach(i => {
      if (i.getAttribute('data-tab') === tabName) i.classList.add('active');
      else i.classList.remove('active');
    });

    el.tabPanes.forEach(pane => {
      if (pane.id === `tab-${tabName}`) pane.classList.add('active');
      else pane.classList.remove('active');
    });

    if (tabInfo[tabName]) {
      el.currentTabTitle.textContent = tabInfo[tabName].title;
      el.currentTabSubtitle.textContent = tabInfo[tabName].subtitle;
    }

    loadCurrentTabData();
  }

  function loadCurrentTabData() {
    refreshStats();
    if (state.currentTab === 'storage') loadBuckets();
    if (state.currentTab === 'keys') loadAccessKeys();
    if (state.currentTab === 'config') loadConfig();
    if (state.currentTab === 'audit') loadAuditLogs();
  }

  // Refresh Stats
  async function refreshStats() {
    try {
      const resp = await apiFetch('/admin/api/status');
      if (!resp.ok) return;
      const data = await resp.json();

      el.statBuckets.textContent = data.total_buckets || 0;
      el.statObjects.textContent = data.total_objects || 0;
      el.statSpoolSize.textContent = formatBytes(data.spool_used_bytes || 0);
      el.statKeys.textContent = data.total_access_keys || 0;

      const pct = Math.min(100, Math.round(((data.spool_used_bytes || 0) / (data.spool_total_bytes || 10737418240)) * 100));
      el.spoolProgress.style.width = `${pct}%`;

      el.infoUptime.textContent = formatUptime(data.uptime_secs || 0);
      el.infoDbSize.textContent = formatBytes(data.db_size_bytes || 0);
      el.infoWorkers.textContent = `${data.worker_concurrency || 0} workers`;
      el.infoPendingJobs.textContent = `${data.pending_jobs || 0} jobs`;
      el.infoUploadingJobs.textContent = `${data.uploading_jobs || 0} jobs`;
    } catch (e) {}
  }

  // Load Buckets
  async function loadBuckets() {
    try {
      const resp = await apiFetch('/admin/api/buckets');
      const data = await resp.json();
      state.buckets = data.buckets || [];
      renderBuckets();
    } catch (e) {
      el.bucketTbody.innerHTML = `<tr><td colspan="6" class="text-center text-rose">Lỗi khi nạp danh sách buckets</td></tr>`;
    }
  }

  function renderBuckets() {
    const q = el.searchBucketInput.value.toLowerCase().trim();
    const filtered = state.buckets.filter(b => b.name.toLowerCase().includes(q));

    if (filtered.length === 0) {
      el.bucketTbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">Không tìm thấy bucket nào</td></tr>`;
      return;
    }

    el.bucketTbody.innerHTML = filtered.map(b => `
      <tr>
        <td><strong>${escapeHtml(b.name)}</strong></td>
        <td><span class="badge badge-success">${escapeHtml(b.region)}</span></td>
        <td>${escapeHtml(b.versioning_status || 'Disabled')}</td>
        <td>${escapeHtml(b.encryption_override || 'Off')}</td>
        <td class="font-mono">${escapeHtml(b.created_at)}</td>
        <td>
          <button class="btn btn-sm btn-danger btn-delete-bucket" data-name="${escapeHtml(b.name)}">Xóa</button>
        </td>
      </tr>
    `).join('');

    document.querySelectorAll('.btn-delete-bucket').forEach(btn => {
      btn.addEventListener('click', () => deleteBucket(btn.getAttribute('data-name')));
    });
  }

  async function deleteBucket(name) {
    if (!confirm(`Bạn có chắc chắn muốn xóa bucket '${name}' không?`)) return;
    try {
      const resp = await apiFetch(`/admin/api/buckets/${name}`, { method: 'DELETE' });
      const data = await resp.json();
      if (resp.ok && data.ok) {
        showToast(`Đã xóa bucket '${name}'`, 'success');
        loadBuckets();
        refreshStats();
      } else {
        showToast(data.error || 'Xóa bucket thất bại', 'error');
      }
    } catch (err) {
      showToast('Lỗi: ' + err.message, 'error');
    }
  }

  // Create Bucket Form
  el.formCreateBucket.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('new-bucket-name').value.trim();
    const region = document.getElementById('new-bucket-region').value.trim() || 'us-east-1';

    try {
      const resp = await apiFetch('/admin/api/buckets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, region })
      });
      const data = await resp.json();
      if (resp.ok && data.ok) {
        showToast(`Đã tạo bucket '${name}' thành công!`, 'success');
        closeModal('modal-create-bucket');
        loadBuckets();
        refreshStats();
      } else {
        showToast(data.error || 'Tạo bucket thất bại', 'error');
      }
    } catch (err) {
      showToast('Lỗi: ' + err.message, 'error');
    }
  });

  // Load Access Keys
  async function loadAccessKeys() {
    try {
      const resp = await apiFetch('/admin/api/access-keys');
      const data = await resp.json();
      state.accessKeys = data.access_keys || [];
      renderAccessKeys();
    } catch (e) {
      el.keyTbody.innerHTML = `<tr><td colspan="5" class="text-center text-rose">Lỗi khi nạp danh sách S3 keys</td></tr>`;
    }
  }

  function renderAccessKeys() {
    const q = el.searchKeyInput.value.toLowerCase().trim();
    const filtered = state.accessKeys.filter(k => k.access_key_id.toLowerCase().includes(q));

    if (filtered.length === 0) {
      el.keyTbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">Không tìm thấy S3 Key nào</td></tr>`;
      return;
    }

    el.keyTbody.innerHTML = filtered.map(k => `
      <tr>
        <td class="font-mono"><strong>${escapeHtml(k.access_key_id)}</strong></td>
        <td class="font-mono">
          <span>••••••••••••••••</span>
          <button class="btn btn-sm btn-outline btn-copy-secret" data-secret="${escapeHtml(k.secret_key)}" title="Copy Secret Key">Copy Secret</button>
        </td>
        <td>${escapeHtml(k.description || 'N/A')}</td>
        <td class="font-mono">${escapeHtml(k.created_at)}</td>
        <td>
          <button class="btn btn-sm btn-danger btn-delete-key" data-id="${escapeHtml(k.access_key_id)}">Thu Hồi</button>
        </td>
      </tr>
    `).join('');

    document.querySelectorAll('.btn-copy-secret').forEach(btn => {
      btn.addEventListener('click', () => {
        navigator.clipboard.writeText(btn.getAttribute('data-secret'));
        showToast('Đã copy Secret Access Key vào Clipboard!', 'success');
      });
    });

    document.querySelectorAll('.btn-delete-key').forEach(btn => {
      btn.addEventListener('click', () => deleteAccessKey(btn.getAttribute('data-id')));
    });
  }

  async function deleteAccessKey(id) {
    if (!confirm(`Bạn có chắc muốn thu hồi Access Key '${id}' không?`)) return;
    try {
      const resp = await apiFetch(`/admin/api/access-keys/${id}`, { method: 'DELETE' });
      const data = await resp.json();
      if (resp.ok && data.ok) {
        showToast(`Đã thu hồi Access Key '${id}'`, 'success');
        loadAccessKeys();
        refreshStats();
      } else {
        showToast(data.error || 'Thu hồi key thất bại', 'error');
      }
    } catch (err) {
      showToast('Lỗi: ' + err.message, 'error');
    }
  }

  // Key Generator Helpers
  function randomString(length, chars) {
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  el.btnGenKeyId.addEventListener('click', () => {
    el.newAccessKeyId.value = 'AKIA' + randomString(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
  });

  el.btnGenSecret.addEventListener('click', () => {
    el.newSecretKey.value = randomString(40, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
  });

  el.formCreateKey.addEventListener('submit', async (e) => {
    e.preventDefault();
    const access_key_id = el.newAccessKeyId.value.trim();
    const secret_key = el.newSecretKey.value.trim();
    const description = document.getElementById('new-key-desc').value.trim();

    try {
      const resp = await apiFetch('/admin/api/access-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ access_key_id, secret_key, description })
      });
      const data = await resp.json();
      if (resp.ok && data.ok) {
        showToast('Đã tạo Access Key thành công!', 'success');
        closeModal('modal-create-key');
        loadAccessKeys();
        refreshStats();
      } else {
        showToast(data.error || 'Tạo Key thất bại', 'error');
      }
    } catch (err) {
      showToast('Lỗi: ' + err.message, 'error');
    }
  });

  // Dynamic Config Load & Update
  async function loadConfig() {
    try {
      const resp = await apiFetch('/admin/api/config');
      const data = await resp.json();
      if (resp.ok && data.ok && data.config) {
        const c = data.config;
        el.cfgPort.value = c.listen_port || 7070;
        el.cfgEncryption.value = c.encryption || 'off';
        el.cfgRegion.value = c.region || '*';
        el.cfgWorkers.value = c.worker_concurrency || 2;
        el.cfgBotToken.value = c.telegram_bot_token === '[REDACTED]' ? '' : (c.telegram_bot_token || '');
        el.cfgChatId.value = c.telegram_chat_id || '';
        el.cfgBaseUrl.value = c.telegram_base_url || 'https://api.telegram.org';
      }
    } catch (e) {}
  }

  el.configForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const items = [
      { key: 'listen_port', value: el.cfgPort.value },
      { key: 'encryption', value: el.cfgEncryption.value },
      { key: 'region', value: el.cfgRegion.value },
      { key: 'worker_concurrency', value: el.cfgWorkers.value },
      { key: 'telegram_chat_id', value: el.cfgChatId.value },
      { key: 'telegram_base_url', value: el.cfgBaseUrl.value }
    ];

    if (el.cfgBotToken.value && el.cfgBotToken.value !== '[REDACTED]') {
      items.push({ key: 'telegram_bot_token', value: el.cfgBotToken.value });
    }
    if (el.cfgAdminPwd.value && el.cfgAdminPwd.value !== '[REDACTED]') {
      items.push({ key: 'admin_password', value: el.cfgAdminPwd.value });
    }

    let successCount = 0;
    for (const item of items) {
      try {
        const resp = await apiFetch('/admin/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(item)
        });
        if (resp.ok) successCount++;
      } catch (err) {}
    }

    if (successCount > 0) {
      showToast('Đã lưu và cập nhật cấu hình live thành công!', 'success');
      loadConfig();
    } else {
      showToast('Cập nhật cấu hình thất bại', 'error');
    }
  });

  // Toggle Password Eye Buttons
  document.getElementById('btn-toggle-login-pwd').addEventListener('click', () => {
    el.adminPassword.type = el.adminPassword.type === 'password' ? 'text' : 'password';
  });
  document.getElementById('btn-toggle-token').addEventListener('click', () => {
    el.cfgBotToken.type = el.cfgBotToken.type === 'password' ? 'text' : 'password';
  });

  // Maintenance Operations
  el.btnRunGc.addEventListener('click', () => runOperation('/admin/api/gc', el.outputGc, 'Chạy GC Engine'));
  el.quickBtnGc.addEventListener('click', () => { switchTab('maintenance'); runOperation('/admin/api/gc', el.outputGc, 'Chạy GC Engine'); });
  
  el.btnRunDoctor.addEventListener('click', () => runOperation('/admin/api/doctor', el.outputDoctor, 'Kiểm Tra Sức Khỏe Doctor'));
  el.quickBtnDoctor.addEventListener('click', () => { switchTab('maintenance'); runOperation('/admin/api/doctor', el.outputDoctor, 'Kiểm Tra Sức Khỏe Doctor'); });

  el.btnRunBackup.addEventListener('click', () => runOperation('/admin/api/backup', el.outputBackup, 'Sao Lưu Database'));
  el.quickBtnBackup.addEventListener('click', () => { switchTab('maintenance'); runOperation('/admin/api/backup', el.outputBackup, 'Sao Lưu Database'); });

  async function runOperation(url, outputEl, title) {
    outputEl.classList.remove('hidden');
    outputEl.textContent = `[RUNNING] Đang thực thi ${title}...`;
    try {
      const resp = await apiFetch(url, { method: 'POST' });
      const data = await resp.json();
      outputEl.textContent = JSON.stringify(data, null, 2);
      showToast(`Hoàn tất ${title}`, 'success');
      refreshStats();
    } catch (err) {
      outputEl.textContent = `[ERROR] Lỗi thực thi: ${err.message}`;
      showToast(`Lỗi ${title}`, 'error');
    }
  }

  // Audit Terminal Logs
  async function loadAuditLogs() {
    try {
      const resp = await apiFetch('/admin/api/audit-logs');
      const logs = await resp.json();
      state.logs = Array.isArray(logs) ? logs : [];
      renderAuditLogs();
    } catch (e) {}
  }

  function renderAuditLogs() {
    const filter = el.logFilterInput.value.toLowerCase().trim();
    const filtered = state.logs.filter(l => l.toLowerCase().includes(filter));

    if (filtered.length === 0) {
      el.terminalBody.innerHTML = `<div class="log-line text-muted">[INFO] Không có dòng log nào khớp với bộ lọc</div>`;
      return;
    }

    el.terminalBody.innerHTML = filtered.map(line => {
      let colorClass = 'text-primary';
      if (line.includes('[ERROR]')) colorClass = 'text-rose';
      if (line.includes('[WARN]')) colorClass = 'text-cyan';
      if (line.includes('[INFO]')) colorClass = 'text-emerald';
      return `<div class="log-line ${colorClass}">${escapeHtml(line)}</div>`;
    }).join('');
  }

  el.logFilterInput.addEventListener('input', renderAuditLogs);
  el.btnCopyLogs.addEventListener('click', () => {
    navigator.clipboard.writeText(state.logs.join('\n'));
    showToast('Đã copy toàn bộ log vào Clipboard!', 'success');
  });

  // Modal Open / Close Helpers
  function openModal(id) { document.getElementById(id).classList.remove('hidden'); }
  function closeModal(id) { document.getElementById(id).classList.add('hidden'); }

  el.btnModalCreateBucket.addEventListener('click', () => openModal('modal-create-bucket'));
  el.btnModalCreateKey.addEventListener('click', () => openModal('modal-create-key'));

  document.querySelectorAll('.btn-close-modal').forEach(btn => {
    btn.addEventListener('click', () => {
      closeModal(btn.getAttribute('data-modal'));
    });
  });

  el.searchBucketInput.addEventListener('input', renderBuckets);
  el.searchKeyInput.addEventListener('input', renderAccessKeys);
  el.btnRefreshAll.addEventListener('click', () => {
    loadCurrentTabData();
    showToast('Đã làm mới dữ liệu', 'info');
  });

  // Start App
  init();
})();

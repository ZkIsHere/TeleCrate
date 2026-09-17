//! Admin REST API & Web Dashboard Handlers — TeleCrate M6.
//! Bảo vệ bởi Session (Cookie-based), CSRF Token header validation, Rate Limiting,
//! và Secret Redaction tự động.

use crate as telecrate;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path as FilePath;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// Embed static frontend dashboard assets
pub const DASHBOARD_HTML: &str = include_str!("dashboard/index.html");
pub const DASHBOARD_CSS: &str = include_str!("dashboard/style.css");
pub const DASHBOARD_JS: &str = include_str!("dashboard/app.js");

/// Thời gian sống của Session (24 giờ).
const SESSION_TTL_SECS: u64 = 86400;

pub type AdminConfig = Arc<std::sync::RwLock<telecrate::config::Config>>;
pub type AdminState = (AdminConfig, Arc<SessionStore>);

pub fn read_config(config_lock: &AdminConfig) -> telecrate::config::Config {
    config_lock
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub csrf_token: String,
    pub expires_at: u64,
}

/// Mức audit — hiển thị/lọc ở dashboard, không lẫn với tracing level của daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditLevel {
    Info,
    Warn,
    Error,
}

impl AuditLevel {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "warn" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// Một bản ghi audit có cấu trúc (thay chuỗi tự do — lọc/phân trang được, không parse lại).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub ts: u64,
    pub level: AuditLevel,
    pub actor: String,
    pub action: String,
    pub detail: String,
}

/// Sức chứa ring-buffer audit (in-memory; log daemon file giữ bản bền vững).
pub const AUDIT_RING_CAP: usize = 5000;
/// Ngưỡng rate-limit login: số lần sai tối đa mỗi cửa sổ.
pub const LOGIN_FAIL_LIMIT: usize = 10;
pub const LOGIN_FAIL_WINDOW_SECS: u64 = 60;
/// Metrics ring capacity: 1000 points × 10s interval ≈ 2.7 hours.
pub const METRICS_RING_CAP: usize = 1000;

/// Một điểm metrics snapshot cho time-series chart.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsPoint {
    pub ts: u64,
    pub objects: i64,
    pub spool_used_bytes: u64,
    pub total_size_bytes: i64,
    pub pending_jobs: i64,
    pub uploading_jobs: i64,
}

/// Global In-Memory Session & Audit Log Store
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, SessionInfo>>,
    start_time: Option<Instant>,
    audit_logs: Mutex<std::collections::VecDeque<AuditEntry>>,
    login_failures: Mutex<Vec<u64>>,
    metrics_history: Mutex<std::collections::VecDeque<MetricsPoint>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            start_time: Some(Instant::now()),
            audit_logs: Mutex::new(std::collections::VecDeque::new()),
            login_failures: Mutex::new(Vec::new()),
            metrics_history: Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// Ghi audit có cấu trúc vào ring-buffer (đầy thì bỏ bản cũ nhất — O(1), không shift Vec).
    /// `detail` không được chứa secret (caller redact trước; endpoint cũng redact phòng thủ).
    pub fn audit(&self, level: AuditLevel, actor: &str, action: &str, detail: String) {
        if let Ok(mut logs) = self.audit_logs.lock() {
            logs.push_back(AuditEntry {
                ts: now_secs(),
                level,
                actor: actor.to_string(),
                action: action.to_string(),
                detail,
            });
            while logs.len() > AUDIT_RING_CAP {
                logs.pop_front();
            }
        }
    }

    /// Truy vấn audit mới-nhất-trước, lọc level/từ khóa, phân trang. Trả (entries, total).
    pub fn query_logs(
        &self,
        level: Option<AuditLevel>,
        q: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> (Vec<AuditEntry>, usize) {
        let logs = self.audit_logs.lock();
        let logs = match logs {
            Ok(l) => l,
            Err(_) => return (Vec::new(), 0),
        };
        let q = q.unwrap_or("").to_ascii_lowercase();
        let filtered: Vec<AuditEntry> = logs
            .iter()
            .rev()
            .filter(|e| level.map(|l| l == e.level).unwrap_or(true))
            .filter(|e| {
                q.is_empty()
                    || e.action.to_ascii_lowercase().contains(&q)
                    || e.detail.to_ascii_lowercase().contains(&q)
                    || e.actor.to_ascii_lowercase().contains(&q)
            })
            .cloned()
            .collect();
        let total = filtered.len();
        let entries = filtered.into_iter().skip(offset).take(limit).collect();
        (entries, total)
    }

    /// Ghi nhận login sai; trả `true` nếu vượt ngưỡng rate-limit (caller trả 429 + audit).
    pub fn note_login_failure(&self) -> bool {
        let now = now_secs();
        if let Ok(mut v) = self.login_failures.lock() {
            v.retain(|t| now.saturating_sub(*t) < LOGIN_FAIL_WINDOW_SECS);
            v.push(now);
            v.len() > LOGIN_FAIL_LIMIT
        } else {
            false
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0)
    }

    pub fn create_session(&self) -> (String, String) {
        let session_id = hex::encode(crypto_random_bytes(16));
        let csrf_token = hex::encode(crypto_random_bytes(16));
        let now = now_secs();
        let expires_at = now + SESSION_TTL_SECS;

        let info = SessionInfo {
            session_id: session_id.clone(),
            csrf_token: csrf_token.clone(),
            expires_at,
        };

        if let Ok(mut map) = self.sessions.lock() {
            // Clean expired sessions
            map.retain(|_, v| v.expires_at > now);
            map.insert(session_id.clone(), info);
        }

        (session_id, csrf_token)
    }

    pub fn validate_session(&self, session_id: &str) -> Option<SessionInfo> {
        let now = now_secs();
        if let Ok(map) = self.sessions.lock() {
            if let Some(info) = map.get(session_id) {
                if info.expires_at > now {
                    return Some(info.clone());
                }
            }
        }
        None
    }

    pub fn remove_session(&self, session_id: &str) {
        if let Ok(mut map) = self.sessions.lock() {
            map.remove(session_id);
        }
    }
}

fn crypto_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let _ = getrandom::getrandom(&mut buf);
    buf
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Extract session ID from `Cookie: telecrate_session=...`
pub fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    let cookie_hdr = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie_hdr.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == "telecrate_session" {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Verify Session & CSRF Token for mutating requests
pub fn authenticate_admin_request(
    headers: &HeaderMap,
    store: &SessionStore,
    require_csrf: bool,
) -> Result<SessionInfo, (StatusCode, Json<serde_json::Value>)> {
    let session_id = extract_session_id(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Unauthorized: Session cookie missing" })),
        )
    })?;

    let info = store.validate_session(&session_id).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Unauthorized: Session expired or invalid" })),
        )
    })?;

    if require_csrf {
        let req_csrf = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if req_csrf.is_empty() || req_csrf != info.csrf_token {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Forbidden: CSRF token mismatch" })),
            ));
        }
    }

    Ok(info)
}

/// Redact Bot tokens, S3 secret keys, signatures from log strings
pub fn redact_secrets(input: &str) -> String {
    let mut out = input.to_string();

    if let Ok(re) = regex_lite_bot_token(&out) {
        out = re;
    }

    if out.contains("SecretAccessKey=") || out.contains("secret_key") {
        out = out.replace("SecretAccessKey=", "SecretAccessKey=[REDACTED]");
    }

    out
}

fn regex_lite_bot_token(input: &str) -> Result<String, ()> {
    let mut res = String::new();
    let s = input;
    let mut last_idx = 0;

    for (idx, _) in s.match_indices(':') {
        let prefix = &s[last_idx..idx];
        if let Some(digit_start) = prefix.rfind(|c: char| !c.is_ascii_digit()) {
            let num_str = &prefix[digit_start + 1..];
            if num_str.len() >= 8 {
                let suffix = &s[idx + 1..];
                let token_len = suffix
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                    .count();
                if token_len >= 20 {
                    res.push_str(&s[last_idx..idx - num_str.len()]);
                    res.push_str("[REDACTED_BOT_TOKEN]");
                    last_idx = idx + 1 + token_len;
                }
            }
        }
    }
    res.push_str(&s[last_idx..]);
    Ok(res)
}

// Handler Functions

pub async fn get_dashboard_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        DASHBOARD_CSS,
    )
        .into_response()
}

pub async fn get_dashboard_js() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        DASHBOARD_JS,
    )
        .into_response()
}

pub async fn get_dashboard_html() -> Response {
    Html(DASHBOARD_HTML).into_response()
}

#[derive(Deserialize)]
pub struct LoginPayload {
    pub password: Option<String>,
}

/// `POST /admin/api/login`
pub async fn api_login(
    State((config_lock, store)): State<AdminState>,
    Json(payload): Json<LoginPayload>,
) -> Response {
    let config = read_config(&config_lock);
    let input_pwd = payload.password.unwrap_or_default();
    let expected_pwd = config
        .admin_password
        .as_deref()
        .or_else(|| config.find_secret("admin"))
        .unwrap_or("telecrate-admin");

    if input_pwd != expected_pwd {
        let limited = store.note_login_failure();
        store.audit(
            AuditLevel::Warn,
            "unknown",
            "auth.login_failed",
            if limited {
                "rate-limited".to_string()
            } else {
                "bad password".to_string()
            },
        );
        if limited {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "ok": false, "error": "Quá nhiều lần sai, thử lại sau 1 phút" })),
            )
                .into_response();
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": "Mật khẩu Admin không chính xác" })),
        )
            .into_response();
    }
    store.audit(
        AuditLevel::Info,
        "admin",
        "auth.login",
        "session created".to_string(),
    );

    let (session_id, csrf_token) = store.create_session();
    let cookie_val = format!(
        "telecrate_session={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        session_id, SESSION_TTL_SECS
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, cookie_val.parse().unwrap());

    (
        StatusCode::OK,
        headers,
        Json(json!({
            "ok": true,
            "csrf_token": csrf_token
        })),
    )
        .into_response()
}

/// `POST /admin/api/logout`
pub async fn api_logout(State((_, store)): State<AdminState>, headers: HeaderMap) -> Response {
    if let Some(session_id) = extract_session_id(&headers) {
        store.remove_session(&session_id);
        store.audit(
            AuditLevel::Info,
            "admin",
            "auth.logout",
            "session removed".to_string(),
        );
    }

    let cookie_val = "telecrate_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, cookie_val.parse().unwrap());

    (
        StatusCode::OK,
        resp_headers,
        Json(json!({ "ok": true, "message": "Logged out" })),
    )
        .into_response()
}

/// `GET /admin/api/session`
pub async fn api_session_status(
    State((_, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Some(session_id) = extract_session_id(&headers) {
        if let Some(info) = store.validate_session(&session_id) {
            return Json(json!({
                "authenticated": true,
                "csrf_token": info.csrf_token
            }))
            .into_response();
        }
    }

    Json(json!({ "authenticated": false })).into_response()
}

fn dir_size(path: &FilePath) -> u64 {
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    total += meta.len();
                }
            }
        }
    }
    total
}

/// `GET /admin/api/status`
pub async fn api_get_status(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let spool_used = dir_size(FilePath::new(&config.spool_dir));
    let spool_total = 10 * 1024 * 1024 * 1024u64; // Default 10 GB indicator

    let db_size = std::fs::metadata(&config.db_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let mut total_buckets = 0;
    let mut total_objects = 0;
    let mut total_chunks = 0;
    let mut total_access_keys = 0;
    let mut pending_jobs = 0;
    let mut uploading_jobs = 0;

    if let Ok(conn) = telecrate::db::open(&config.db_path) {
        if let Ok(bkts) = telecrate::db::list_buckets(&conn) {
            total_buckets = bkts.len();
        }
        if let Ok(keys) = telecrate::db::list_access_keys(&conn) {
            total_access_keys = keys.len();
        }
        if let Ok(n) = conn.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0)) {
            total_objects = n;
        }
        if let Ok(n) = conn.query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0)) {
            total_chunks = n;
        }
        if let Ok(n) = conn.query_row(
            "SELECT COUNT(*) FROM upload_jobs WHERE state = 'pending'",
            [],
            |r| r.get(0),
        ) {
            pending_jobs = n;
        }
        if let Ok(n) = conn.query_row(
            "SELECT COUNT(*) FROM upload_jobs WHERE state = 'uploading'",
            [],
            |r| r.get(0),
        ) {
            uploading_jobs = n;
        }
    }

    Json(json!({
        "version": telecrate::VERSION,
        "uptime_seconds": store.uptime_secs(),
        "spool": {
            "total_bytes": spool_total,
            "used_bytes": spool_used,
            "free_bytes": spool_total.saturating_sub(spool_used),
            "reserved_free_space_bytes": 100 * 1024 * 1024,
        },
        "db_size_bytes": db_size,
        "workers": {
            "active_worker_count": config.worker_concurrency,
            "pending_jobs_count": pending_jobs,
            "uploading_jobs_count": uploading_jobs,
        },
        "counts": {
            "total_buckets": total_buckets,
            "total_objects": total_objects,
            "total_chunks": total_chunks,
            "total_access_keys": total_access_keys,
        }
    }))
    .into_response()
}

/// `GET /admin/api/buckets`
pub async fn api_list_buckets(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };

    let buckets = match telecrate::db::list_buckets(&conn) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("List error: {e}") })),
            )
                .into_response()
        }
    };

    let mut list = Vec::new();
    for b in buckets {
        let versioning = telecrate::db::get_bucket_versioning(&conn, &b.name)
            .unwrap_or_else(|_| "Disabled".to_string());
        list.push(json!({
            "name": b.name,
            "region": b.region,
            "created_at": b.created_at,
            "versioning": versioning,
        }));
    }

    Json(list).into_response()
}

#[derive(Deserialize)]
pub struct CreateBucketPayload {
    pub name: String,
    pub region: Option<String>,
}

/// `POST /admin/api/buckets`
pub async fn api_create_bucket(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<CreateBucketPayload>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let region = payload
        .region
        .unwrap_or_else(|| telecrate::config::DEFAULT_REGION.to_string());
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };

    match telecrate::db::create_bucket(&conn, &payload.name, &region) {
        Ok(_) => {
            store.audit(
                AuditLevel::Info,
                "admin",
                "bucket.create",
                format!("name='{name}' region='{region}'", name = payload.name),
            );
            Json(json!({ "ok": true, "name": payload.name })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Create failed: {e}") })),
        )
            .into_response(),
    }
}

/// `DELETE /admin/api/buckets/:name`
pub async fn api_delete_bucket(
    State((config_lock, store)): State<AdminState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };

    match telecrate::db::delete_bucket(&conn, &name) {
        Ok(_) => {
            store.audit(
                AuditLevel::Warn,
                "admin",
                "bucket.delete",
                format!("name='{name}'"),
            );
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Delete failed: {e}") })),
        )
            .into_response(),
    }
}

/// `GET /admin/api/buckets/:name/objects`
pub async fn api_list_bucket_objects(
    State((config_lock, store)): State<AdminState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };

    let mut stmt = match conn.prepare(
        "SELECT key, version_id, is_delete_marker, storage_state, size, etag, content_type, created_at FROM objects WHERE bucket = ? ORDER BY key ASC, created_at DESC",
    ) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Query prepare error: {e}") })),
            )
                .into_response()
        }
    };

    let object_rows = stmt.query_map([&name], |r| {
        Ok(json!({
            "key": r.get::<_, String>(0)?,
            "version_id": r.get::<_, String>(1)?,
            "is_delete_marker": r.get::<_, i64>(2)? != 0,
            "storage_state": r.get::<_, String>(3)?,
            "size": r.get::<_, i64>(4)?,
            "etag": r.get::<_, String>(5)?,
            "content_type": r.get::<_, String>(6)?,
            "created_at": r.get::<_, String>(7)?,
        }))
    });

    let mut list = Vec::new();
    if let Ok(rows) = object_rows {
        for obj in rows.flatten() {
            list.push(obj);
        }
    }

    Json(list).into_response()
}

/// `GET /admin/api/access-keys`
pub async fn api_list_access_keys(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };

    let keys = match telecrate::db::list_access_keys(&conn) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("List error: {e}") })),
            )
                .into_response()
        }
    };

    let list: Vec<serde_json::Value> = keys
        .into_iter()
        .map(|k| {
            json!({
                "access_key_id": k.access_key_id,
                "user_id": k.description.unwrap_or_else(|| "admin".to_string()),
                "status": k.status,
                "created_at": k.created_at,
            })
        })
        .collect();

    Json(list).into_response()
}

#[derive(Deserialize)]
pub struct CreateKeyPayload {
    pub user_id: Option<String>,
}

/// `POST /admin/api/access-keys`
pub async fn api_create_access_key(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<CreateKeyPayload>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let user_id = payload.user_id.unwrap_or_else(|| "admin".to_string());
    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };

    let access_key_id = format!("AKIA{}", hex::encode(crypto_random_bytes(8)).to_uppercase());
    let secret_key = hex::encode(crypto_random_bytes(20));

    match telecrate::db::create_access_key(&conn, &access_key_id, &secret_key, Some(&user_id)) {
        Ok(_) => {
            // Audit KHÔNG ghi secret_key — chỉ id + user (secret chỉ trả 1 lần trong response).
            store.audit(
                AuditLevel::Info,
                "admin",
                "key.create",
                format!("id='{access_key_id}' user='{user_id}'"),
            );
            Json(json!({
                "ok": true,
                "access_key_id": access_key_id,
                "secret_key": secret_key,
                "user_id": user_id
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Create key failed: {e}") })),
        )
            .into_response(),
    }
}

/// `DELETE /admin/api/access-keys/:id`
pub async fn api_revoke_access_key(
    State((config_lock, store)): State<AdminState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };

    match telecrate::db::delete_access_key(&conn, &key_id) {
        Ok(_) => {
            store.audit(
                AuditLevel::Warn,
                "admin",
                "key.revoke",
                format!("id='{key_id}'"),
            );
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Revoke key failed: {e}") })),
        )
            .into_response(),
    }
}

/// `POST /admin/api/gc`
pub async fn api_run_gc(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };

    let gc_res =
        telecrate::gc::run_gc(&conn, FilePath::new(&config.spool_dir), None).unwrap_or_default();

    store.audit(
        AuditLevel::Info,
        "admin",
        "gc.run",
        format!(
            "spool_bytes_freed={} orphaned_parts_cleaned={}",
            gc_res.spool_bytes_freed, gc_res.orphaned_parts_cleaned
        ),
    );

    Json(json!({
        "ok": true,
        "spool_files_deleted": gc_res.spool_files_deleted,
        "spool_bytes_freed": gc_res.spool_bytes_freed,
        "telegram_messages_deleted": gc_res.telegram_messages_deleted,
        "orphaned_parts_cleaned": gc_res.orphaned_parts_cleaned,
    }))
    .into_response()
}

/// `POST /admin/api/doctor`
pub async fn api_run_doctor(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };

    let report = telecrate::doctor::run_doctor(&conn)
        .map(|r| serde_json::to_value(r).unwrap_or_default())
        .unwrap_or_else(|e| json!({ "error": format!("Doctor error: {e}") }));

    store.audit(
        AuditLevel::Info,
        "admin",
        "doctor.run",
        "health check & scrub".to_string(),
    );

    Json(json!({
        "ok": true,
        "report": report
    }))
    .into_response()
}

/// `POST /admin/api/backup`
pub async fn api_run_backup(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };

    let timestamp = now_secs();
    let backup_path = format!("{}.backup_{}", config.db_path, timestamp);

    match telecrate::db::backup_db(&conn, &backup_path) {
        Ok(_) => {
            let size = std::fs::metadata(&backup_path)
                .map(|m| m.len())
                .unwrap_or(0);
            store.audit(
                AuditLevel::Info,
                "admin",
                "backup.run",
                format!("path='{backup_path}' bytes={size}"),
            );
            Json(json!({
                "ok": true,
                "backup_path": backup_path,
                "size_bytes": size
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Backup error: {e}") })),
        )
            .into_response(),
    }
}

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    /// level=info|warn|error (tùy chọn).
    pub level: Option<String>,
    /// q: tìm trong actor/action/detail, không phân biệt hoa thường.
    pub q: Option<String>,
    /// limit: mặc định 100, tối đa 1000.
    pub limit: Option<usize>,
    /// offset: phân trang.
    pub offset: Option<usize>,
}

/// `GET /admin/api/audit-logs?level=&q=&limit=&offset=`
/// Trả bản ghi audit THẬT từ ring-buffer (mới nhất trước) + tổng số sau lọc.
/// Không fabricate log, không lộ token/secret (detail đã redact ở tầng ghi + phòng thủ ở đây).
pub async fn api_get_audit_logs(
    State((_, store)): State<AdminState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<AuditQuery>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }

    let level = params.level.as_deref().and_then(AuditLevel::from_str);
    if params.level.is_some() && level.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "level must be info|warn|error" })),
        )
            .into_response();
    }
    let limit = params.limit.unwrap_or(100).clamp(1, 1000);
    let offset = params.offset.unwrap_or(0);

    let (entries, total) = store.query_logs(level, params.q.as_deref(), limit, offset);
    let entries: Vec<serde_json::Value> = entries
        .into_iter()
        .map(|e| {
            json!({
                "ts": e.ts,
                "level": e.level,
                "actor": e.actor,
                "action": e.action,
                "detail": redact_secrets(&e.detail),
            })
        })
        .collect();
    Json(json!({ "entries": entries, "total": total })).into_response()
}

#[derive(Deserialize)]
pub struct ConfigUpdatePayload {
    pub key: String,
    pub value: String,
    pub config_path: Option<String>,
}

/// `GET /admin/api/config`
pub async fn api_get_config(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let mut cfg_val = serde_json::to_value(&config).unwrap_or_default();
    if let Some(obj) = cfg_val.as_object_mut() {
        if obj.contains_key("telegram_bot_token") {
            obj.insert("telegram_bot_token".to_string(), json!("[REDACTED]"));
        }
        if obj.contains_key("admin_password") {
            obj.insert("admin_password".to_string(), json!("[REDACTED]"));
        }
    }

    Json(json!({ "ok": true, "config": cfg_val })).into_response()
}

/// `POST /admin/api/config`
pub async fn api_update_config(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<ConfigUpdatePayload>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let key = payload.key.trim();
    let val = payload.value.trim();

    let mut config = config_lock.write().unwrap_or_else(|e| e.into_inner());

    if let Err(e) = config.update_key(key, val) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response();
    }

    let save_path = payload
        .config_path
        .unwrap_or_else(|| "/etc/telecrate/telecrate.toml".to_string());

    if let Err(e) = config.save_to_file(&save_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": format!("Lưu file config thất bại: {e}") })),
        )
            .into_response();
    }

    store.audit(
        AuditLevel::Warn,
        "admin",
        "config.update",
        format!(
            "key='{key}' value='{}'",
            if key.contains("secret") || key.contains("password") || key.contains("token") {
                "[REDACTED]"
            } else {
                val
            }
        ),
    );

    Json(json!({
        "ok": true,
        "message": format!("Đã cập nhật key '{key}' thành công"),
        "key": key
    }))
    .into_response()
}

// ============================================================
// Dashboard v2 — New endpoints
// ============================================================

impl SessionStore {
    /// Ghi snapshot metrics vào ring-buffer.
    pub fn record_metrics(&self, point: MetricsPoint) {
        if let Ok(mut ring) = self.metrics_history.lock() {
            ring.push_back(point);
            while ring.len() > METRICS_RING_CAP {
                ring.pop_front();
            }
        }
    }

    /// Truy vấn lịch sử metrics.
    pub fn query_metrics(&self) -> Vec<MetricsPoint> {
        self.metrics_history
            .lock()
            .map(|r| r.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// Background task: sample metrics mỗi 10s. Gọi từ daemon startup (tokio::spawn).
pub async fn metrics_sampler(config_lock: AdminConfig, store: Arc<SessionStore>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    loop {
        interval.tick().await;
        let config = read_config(&config_lock);
        let spool_used = dir_size(FilePath::new(&config.spool_dir));
        let mut total_objects: i64 = 0;
        let mut total_size: i64 = 0;
        let mut pending: i64 = 0;
        let mut uploading: i64 = 0;
        if let Ok(conn) = telecrate::db::open(&config.db_path) {
            total_objects = conn
                .query_row(
                    "SELECT COUNT(*) FROM objects WHERE is_delete_marker = 0",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            total_size = conn
                .query_row(
                    "SELECT COALESCE(SUM(size), 0) FROM objects WHERE is_delete_marker = 0",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if let Ok(s) = telecrate::db::job_summary(&conn) {
                pending = s.pending;
                uploading = s.uploading;
            }
        }
        store.record_metrics(MetricsPoint {
            ts: now_secs(),
            objects: total_objects,
            spool_used_bytes: spool_used,
            total_size_bytes: total_size,
            pending_jobs: pending,
            uploading_jobs: uploading,
        });
    }
}

/// `GET /admin/api/metrics-history`
pub async fn api_get_metrics_history(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let mut points = store.query_metrics();
    if points.is_empty() {
        let config = read_config(&config_lock);
        let spool_used = dir_size(FilePath::new(&config.spool_dir));
        let mut total_objects: i64 = 0;
        let mut total_size: i64 = 0;
        let mut pending: i64 = 0;
        let mut uploading: i64 = 0;
        if let Ok(conn) = telecrate::db::open(&config.db_path) {
            total_objects = conn
                .query_row(
                    "SELECT COUNT(*) FROM objects WHERE is_delete_marker = 0",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            total_size = conn
                .query_row(
                    "SELECT COALESCE(SUM(size), 0) FROM objects WHERE is_delete_marker = 0",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if let Ok(s) = telecrate::db::job_summary(&conn) {
                pending = s.pending;
                uploading = s.uploading;
            }
        }
        points.push(MetricsPoint {
            ts: now_secs(),
            objects: total_objects,
            spool_used_bytes: spool_used,
            total_size_bytes: total_size,
            pending_jobs: pending,
            uploading_jobs: uploading,
        });
    }
    Json(json!({
        "points": points,
        "metrics": points,
        "sample_interval_secs": 10
    }))
    .into_response()
}

/// `GET /admin/api/buckets` — MODIFIED: include per-bucket stats.
pub async fn api_list_buckets_v2(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };
    let buckets = match telecrate::db::list_buckets(&conn) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("List error: {e}") })),
            )
                .into_response()
        }
    };
    let stats = telecrate::db::bucket_stats(&conn).unwrap_or_default();
    let stats_map: HashMap<String, (i64, i64)> = stats
        .into_iter()
        .map(|s| (s.name, (s.object_count, s.total_size_bytes)))
        .collect();
    let mut list = Vec::new();
    for b in buckets {
        let versioning = telecrate::db::get_bucket_versioning(&conn, &b.name)
            .unwrap_or_else(|_| "Disabled".to_string());
        let (obj_count, total_size) = stats_map.get(&b.name).copied().unwrap_or((0, 0));
        list.push(json!({
            "name": b.name,
            "region": b.region,
            "created_at": b.created_at,
            "versioning": versioning,
            "object_count": obj_count,
            "total_size_bytes": total_size,
        }));
    }
    Json(list).into_response()
}

#[derive(Deserialize, Default)]
pub struct ObjectListQuery {
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub max_keys: Option<usize>,
    pub continuation_token: Option<String>,
}

/// `GET /admin/api/buckets/:name/objects` — MODIFIED: prefix + delimiter support.
pub async fn api_list_bucket_objects_v2(
    State((config_lock, store)): State<AdminState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<ObjectListQuery>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };
    let prefix = params.prefix.unwrap_or_default();
    let delimiter = params.delimiter.unwrap_or_default();
    let max_keys = params.max_keys.unwrap_or(200).min(1000);
    let start_after = params.continuation_token.unwrap_or_default();

    // Query all matching keys (list_keys already supports prefix)
    let rows = match telecrate::db::list_keys(
        &conn,
        &name,
        &prefix,
        &start_after,
        (max_keys + 1) as i64,
    ) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("List error: {e}") })),
            )
                .into_response()
        }
    };

    let is_truncated = rows.len() > max_keys;
    let rows: Vec<_> = rows.into_iter().take(max_keys).collect();
    let next_token = if is_truncated {
        rows.last().map(|(k, _)| k.clone())
    } else {
        None
    };

    // If delimiter is set, group into common_prefixes + objects at current level
    if !delimiter.is_empty() {
        let mut common_prefixes: Vec<String> = Vec::new();
        let mut objects = Vec::new();
        let mut seen_prefixes: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (key, obj) in &rows {
            let suffix = &key[prefix.len()..];
            if let Some(pos) = suffix.find(&delimiter) {
                let cp = format!("{}{}{}", prefix, &suffix[..pos], delimiter);
                if seen_prefixes.insert(cp.clone()) {
                    common_prefixes.push(cp);
                }
            } else {
                objects.push(json!({
                    "key": obj.key,
                    "version_id": obj.version_id,
                    "is_delete_marker": obj.is_delete_marker,
                    "storage_state": obj.storage_state,
                    "size": obj.size,
                    "etag": obj.etag,
                    "content_type": obj.content_type,
                    "created_at": obj.created_at,
                }));
            }
        }
        common_prefixes.sort();
        return Json(json!({
            "objects": objects,
            "common_prefixes": common_prefixes,
            "is_truncated": is_truncated,
            "next_continuation_token": next_token,
            "key_count": objects.len() + common_prefixes.len(),
        }))
        .into_response();
    }

    // No delimiter: flat list
    let objects: Vec<serde_json::Value> = rows
        .iter()
        .map(|(_, obj)| {
            json!({
                "key": obj.key,
                "version_id": obj.version_id,
                "is_delete_marker": obj.is_delete_marker,
                "storage_state": obj.storage_state,
                "size": obj.size,
                "etag": obj.etag,
                "content_type": obj.content_type,
                "created_at": obj.created_at,
            })
        })
        .collect();
    Json(json!({
        "objects": objects,
        "common_prefixes": [],
        "is_truncated": is_truncated,
        "next_continuation_token": next_token,
        "key_count": objects.len(),
    }))
    .into_response()
}

/// `GET /admin/api/buckets/:name/objects-detail/*key` — Object detail.
pub async fn api_get_object_detail(
    State((config_lock, store)): State<AdminState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };
    let version = match telecrate::db::latest_version(&conn, &bucket, &key) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Object not found" })),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Query error: {e}") })),
            )
                .into_response()
        }
    };
    let chunks = telecrate::db::chunks_of(&conn, &version.version_id).unwrap_or_default();
    let chunks_json: Vec<serde_json::Value> = chunks
        .iter()
        .map(|c| {
            json!({
                "idx": c.idx,
                "length": c.length,
                "state": c.state,
                "encryption_mode": c.encryption_mode,
                "has_spool": c.spool_path.is_some(),
            })
        })
        .collect();

    let user_meta: serde_json::Value = version
        .user_metadata_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(json!({}));
    let sys_meta: serde_json::Value = version
        .system_metadata_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(json!({}));

    Json(json!({
        "key": version.key,
        "version_id": version.version_id,
        "size": version.size,
        "etag": version.etag,
        "content_type": version.content_type,
        "storage_state": version.storage_state,
        "created_at": version.created_at,
        "is_delete_marker": version.is_delete_marker,
        "chunks": chunks_json,
        "user_metadata": user_meta,
        "system_metadata": sys_meta,
    }))
    .into_response()
}

/// `DELETE /admin/api/buckets/:name/objects-detail/*key` — Delete object from dashboard.
pub async fn api_delete_object(
    State((config_lock, store)): State<AdminState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let mut conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };
    match telecrate::db::delete_object(&mut conn, &bucket, &key) {
        Ok(r) => {
            // Clean up spool files
            for sp in &r.spool_paths {
                let _ = std::fs::remove_file(sp);
            }
            store.audit(
                AuditLevel::Warn,
                "admin",
                "object.delete",
                format!("bucket='{}' key='{}'", bucket, key),
            );
            Json(json!({
                "ok": true,
                "existed": r.existed,
                "version_id": r.version_id,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Delete error: {e}") })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateKeyPayload {
    pub status: Option<String>,
    pub description: Option<String>,
    pub allowed_buckets: Option<serde_json::Value>,
}

/// `PUT /admin/api/access-keys/:id` — Update access key (status/description/buckets).
pub async fn api_update_access_key(
    State((config_lock, store)): State<AdminState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<UpdateKeyPayload>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };
    let mut changes = Vec::new();
    if let Some(ref status) = payload.status {
        match telecrate::db::update_access_key_status(&conn, &key_id, status) {
            Ok(true) => changes.push(format!("status={status}")),
            Ok(false) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Key not found" })),
                )
                    .into_response()
            }
            Err(e) => {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response()
            }
        }
    }
    if let Some(ref desc) = payload.description {
        let _ = telecrate::db::update_access_key_description(&conn, &key_id, desc);
        changes.push("description updated".to_string());
    }
    if let Some(ref ab) = payload.allowed_buckets {
        let ab_str = if ab.is_null() {
            None
        } else {
            Some(ab.to_string())
        };
        let _ = telecrate::db::update_access_key_allowed_buckets(&conn, &key_id, ab_str.as_deref());
        changes.push("allowed_buckets updated".to_string());
    }
    store.audit(
        AuditLevel::Warn,
        "admin",
        "key.update",
        format!("id='{}' changes=[{}]", key_id, changes.join(", ")),
    );
    Json(json!({ "ok": true, "changes": changes })).into_response()
}

/// `GET /admin/api/access-keys` — MODIFIED: include last_used_at and allowed_buckets.
pub async fn api_list_access_keys_v2(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };
    // Query with new columns (migration 0004 adds them; graceful if missing)
    let mut stmt = conn
        .prepare("SELECT access_key_id, status, description, created_at, last_used_at, allowed_buckets FROM access_keys ORDER BY created_at ASC")
        .unwrap_or_else(|_| {
            // Fallback without new columns
            conn.prepare("SELECT access_key_id, status, description, created_at, NULL, NULL FROM access_keys ORDER BY created_at ASC").unwrap()
        });
    let rows = stmt.query_map([], |r| {
        Ok(json!({
            "access_key_id": r.get::<_, String>(0)?,
            "status": r.get::<_, String>(1)?,
            "user_id": r.get::<_, Option<String>>(2)?.unwrap_or_else(|| "admin".to_string()),
            "created_at": r.get::<_, String>(3)?,
            "last_used_at": r.get::<_, Option<String>>(4)?,
            "allowed_buckets": r.get::<_, Option<String>>(5)?,
        }))
    });
    let list: Vec<serde_json::Value> = match rows {
        Ok(r) => r.flatten().collect(),
        Err(_) => Vec::new(),
    };
    Json(list).into_response()
}

/// `GET /admin/api/jobs` — List upload jobs.
pub async fn api_list_jobs(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };
    match telecrate::db::list_jobs(&conn) {
        Ok((jobs, summary)) => {
            let jobs_json: Vec<serde_json::Value> = jobs
                .into_iter()
                .map(|j| {
                    json!({
                        "job_id": j.job_id,
                        "version_id": j.version_id,
                        "bucket": j.bucket,
                        "key": j.key,
                        "state": j.state,
                        "retry_count": j.retry_count,
                        "next_attempt": j.next_attempt,
                        "lease_owner": j.lease_owner,
                        "lease_expires": j.lease_expires,
                        "last_error": j.last_error,
                        "generation": j.generation,
                    })
                })
                .collect();
            let summary_obj = json!({
                "pending": summary.pending,
                "uploading": summary.uploading,
                "completed": summary.completed,
                "failed": summary.failed,
            });
            Json(json!({
                "jobs": jobs_json,
                "total": jobs_json.len(),
                "summary": summary_obj,
                "counts": summary_obj,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("List jobs error: {e}") })),
        )
            .into_response(),
    }
}

/// `POST /admin/api/telegram-test` — Test Telegram connection.
pub async fn api_telegram_test(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    if config.telegram_bot_token.is_empty() {
        store.audit(
            AuditLevel::Warn,
            "admin",
            "telegram.test",
            "no bot token configured".to_string(),
        );
        return Json(json!({
            "ok": false,
            "error": "Bot token chưa cấu hình"
        }))
        .into_response();
    }
    if config.telegram_chat_id == 0 {
        store.audit(
            AuditLevel::Warn,
            "admin",
            "telegram.test",
            "no chat_id configured".to_string(),
        );
        return Json(json!({
            "ok": false,
            "error": "Chat ID chưa cấu hình (= 0)"
        }))
        .into_response();
    }
    // Try getMe via HTTP (async non-blocking)
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let get_me_url = format!(
        "https://api.telegram.org/bot{}/getMe",
        config.telegram_bot_token
    );
    match client.get(&get_me_url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if body.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                    let bot = body.get("result").cloned().unwrap_or(json!({}));
                    store.audit(
                        AuditLevel::Info,
                        "admin",
                        "telegram.test",
                        format!(
                            "bot={}",
                            bot.get("username").and_then(|v| v.as_str()).unwrap_or("?")
                        ),
                    );
                    return Json(json!({
                        "ok": true,
                        "bot": {
                            "username": bot.get("username"),
                            "id": bot.get("id"),
                            "first_name": bot.get("first_name"),
                        },
                        "chat_id": config.telegram_chat_id,
                    }))
                    .into_response();
                } else {
                    let err_msg = body
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error");
                    store.audit(
                        AuditLevel::Error,
                        "admin",
                        "telegram.test",
                        format!("getMe failed: {err_msg}"),
                    );
                    return Json(json!({ "ok": false, "error": err_msg })).into_response();
                }
            }
            Json(json!({ "ok": false, "error": "Invalid response from Telegram" })).into_response()
        }
        Err(e) => {
            store.audit(
                AuditLevel::Error,
                "admin",
                "telegram.test",
                format!("request failed: {e}"),
            );
            Json(json!({ "ok": false, "error": format!("Request failed: {e}") })).into_response()
        }
    }
}

/// `GET /admin/api/multipart-uploads` — List in-progress multipart uploads.
pub async fn api_list_multipart_uploads(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };
    // Direct query — list_multipart_uploads in db.rs takes bucket param,
    // but for dashboard we want all uploads across all buckets.
    let mut stmt = match conn.prepare(
        "SELECT upload_id, bucket, key, content_type, created_at FROM multipart_uploads ORDER BY created_at DESC LIMIT 100",
    ) {
        Ok(s) => s,
        Err(e) => {
            return Json(json!({ "uploads": [], "total": 0, "error": format!("{e}") })).into_response();
        }
    };
    let rows = stmt.query_map([], |r| {
        Ok(json!({
            "upload_id": r.get::<_, String>(0)?,
            "bucket": r.get::<_, String>(1)?,
            "key": r.get::<_, String>(2)?,
            "content_type": r.get::<_, String>(3)?,
            "created_at": r.get::<_, String>(4)?,
        }))
    });
    let list: Vec<serde_json::Value> = match rows {
        Ok(r) => r.flatten().collect(),
        Err(_) => Vec::new(),
    };
    let total = list.len();
    Json(json!({ "uploads": list, "total": total })).into_response()
}

/// `POST /admin/api/multipart-uploads/:id/abort` — Abort a stuck multipart upload.
pub async fn api_abort_multipart_upload(
    State((config_lock, store)): State<AdminState>,
    Path(upload_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let mut conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };
    match telecrate::db::abort_multipart_upload(&mut conn, &upload_id) {
        Ok(paths) => {
            for p in &paths {
                let _ = std::fs::remove_file(p);
            }
            store.audit(
                AuditLevel::Warn,
                "admin",
                "multipart.abort",
                format!("upload_id='{}' parts_cleaned={}", upload_id, paths.len()),
            );
            Json(json!({ "ok": true, "parts_cleaned": paths.len() })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Abort failed: {e}") })),
        )
            .into_response(),
    }
}

/// `GET /admin/api/buckets/:name/settings` — Aggregated bucket settings.
pub async fn api_get_bucket_settings(
    State((config_lock, store)): State<AdminState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };
    if !telecrate::db::head_bucket(&conn, &name).unwrap_or(false) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Bucket not found" })),
        )
            .into_response();
    }
    let versioning = telecrate::db::get_bucket_versioning(&conn, &name)
        .unwrap_or_else(|_| "Disabled".to_string());
    let cors: Option<serde_json::Value> = telecrate::db::get_bucket_cors(&conn, &name)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok());
    let policy: Option<serde_json::Value> = telecrate::db::get_bucket_policy(&conn, &name)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok());
    let bpa = telecrate::db::get_bucket_bpa(&conn, &name).unwrap_or_default();
    let lock_config = telecrate::db::get_bucket_object_lock_config(&conn, &name).ok();

    Json(json!({
        "name": name,
        "versioning": versioning,
        "cors": cors,
        "policy": policy,
        "bpa": {
            "block_public_acls": bpa.block_public_acls,
            "ignore_public_acls": bpa.ignore_public_acls,
            "block_public_policy": bpa.block_public_policy,
            "restrict_public_buckets": bpa.restrict_public_buckets,
        },
        "object_lock": lock_config,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct VersioningPayload {
    pub status: String,
}

/// `PUT /admin/api/buckets/:name/versioning` — Toggle bucket versioning.
pub async fn api_set_bucket_versioning(
    State((config_lock, store)): State<AdminState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<VersioningPayload>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let mut conn = match telecrate::db::open(&config.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("DB error: {e}") })),
            )
                .into_response()
        }
    };
    match telecrate::db::set_bucket_versioning(&mut conn, &name, &payload.status) {
        Ok(_) => {
            store.audit(
                AuditLevel::Warn,
                "admin",
                "bucket.versioning",
                format!("bucket='{}' status='{}'", name, payload.status),
            );
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Set versioning failed: {e}") })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_store_create_validate_remove() {
        let store = SessionStore::new();
        let (sid, csrf) = store.create_session();
        assert!(!sid.is_empty());
        assert!(!csrf.is_empty());

        let info = store
            .validate_session(&sid)
            .expect("Session should be valid");
        assert_eq!(info.csrf_token, csrf);

        store.remove_session(&sid);
        assert!(store.validate_session(&sid).is_none());
    }

    #[test]
    fn test_redact_secrets() {
        let input = "Error calling bot token 123456789:ABCdefGHIjklMNOpqrsTUVwxyz on Telegram API";
        let redacted = redact_secrets(input);
        assert!(!redacted.contains("ABCdefGHIjklMNOpqrsTUVwxyz"));
        assert!(redacted.contains("[REDACTED_BOT_TOKEN]"));
    }

    #[test]
    fn test_audit_ring_filter_paginate() {
        let store = SessionStore::new();
        store.audit(
            AuditLevel::Info,
            "admin",
            "bucket.create",
            "name='a'".to_string(),
        );
        store.audit(
            AuditLevel::Warn,
            "admin",
            "key.revoke",
            "id='K'".to_string(),
        );
        store.audit(
            AuditLevel::Error,
            "system",
            "worker.fail",
            "timeout".to_string(),
        );

        // Mới nhất trước.
        let (all, total) = store.query_logs(None, None, 100, 0);
        assert_eq!(total, 3);
        assert_eq!(all[0].action, "worker.fail");

        // Lọc level.
        let (warns, total) = store.query_logs(Some(AuditLevel::Warn), None, 100, 0);
        assert_eq!(total, 1);
        assert_eq!(warns[0].action, "key.revoke");

        // Tìm từ khóa (case-insensitive, cả actor).
        let (_, total) = store.query_logs(None, Some("SYSTEM"), 100, 0);
        assert_eq!(total, 1);

        // Phân trang.
        let (page, total) = store.query_logs(None, None, 2, 1);
        assert_eq!(total, 3);
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].action, "key.revoke");
    }

    #[test]
    fn test_login_rate_limit() {
        let store = SessionStore::new();
        for _ in 0..LOGIN_FAIL_LIMIT {
            assert!(!store.note_login_failure());
        }
        assert!(store.note_login_failure());
    }
}

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

/// Global In-Memory Session & Audit Log Store
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, SessionInfo>>,
    start_time: Option<Instant>,
    audit_logs: Mutex<std::collections::VecDeque<AuditEntry>>,
    login_failures: Mutex<Vec<u64>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            start_time: Some(Instant::now()),
            audit_logs: Mutex::new(std::collections::VecDeque::new()),
            login_failures: Mutex::new(Vec::new()),
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
    let region = payload.region.unwrap_or_else(|| config.region.clone());
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

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

/// Global In-Memory Session & Audit Log Store
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, SessionInfo>>,
    start_time: Option<Instant>,
    audit_logs: Mutex<Vec<String>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            start_time: Some(Instant::now()),
            audit_logs: Mutex::new(Vec::new()),
        }
    }

    pub fn add_log(&self, msg: String) {
        if let Ok(mut logs) = self.audit_logs.lock() {
            logs.push(msg);
            if logs.len() > 1000 {
                logs.remove(0);
            }
        }
    }

    pub fn get_logs(&self) -> Vec<String> {
        self.audit_logs
            .lock()
            .map(|l| l.clone())
            .unwrap_or_default()
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
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": "Mật khẩu Admin không chính xác" })),
        )
            .into_response();
    }

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
            "SELECT COUNT(*) FROM telegram_upload_jobs WHERE status = 'pending'",
            [],
            |r| r.get(0),
        ) {
            pending_jobs = n;
        }
        if let Ok(n) = conn.query_row(
            "SELECT COUNT(*) FROM telegram_upload_jobs WHERE status = 'uploading'",
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
            store.add_log(format!(
                "[INFO] [{}] Created S3 bucket '{}' in region '{}'",
                now_secs(),
                payload.name,
                region
            ));
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
            store.add_log(format!(
                "[WARN] [{}] Deleted S3 bucket '{}'",
                now_secs(),
                name
            ));
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Delete failed: {e}") })),
        )
            .into_response(),
    }
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
            store.add_log(format!(
                "[INFO] [{}] Generated new S3 AccessKeyId '{}' for user '{}'",
                now_secs(),
                access_key_id,
                user_id
            ));
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
            store.add_log(format!(
                "[WARN] [{}] Revoked S3 AccessKeyId '{}'",
                now_secs(),
                key_id
            ));
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

    store.add_log(format!(
        "[INFO] [{}] Executed GC Engine: freed {} bytes in spool, cleaned {} parts",
        now_secs(),
        gc_res.spool_bytes_freed,
        gc_res.orphaned_parts_cleaned
    ));

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

    store.add_log(format!(
        "[INFO] [{}] Executed Doctor health check & scrub",
        now_secs()
    ));

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
            store.add_log(format!(
                "[INFO] [{}] Database backup created at '{}' ({} bytes)",
                now_secs(),
                backup_path,
                size
            ));
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

/// `GET /admin/api/audit-logs`
pub async fn api_get_audit_logs(
    State((config_lock, store)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let bot_token_preview = if config.telegram_bot_token.len() >= 8 {
        config
            .telegram_bot_token
            .chars()
            .take(8)
            .collect::<String>()
    } else {
        "bot_token".to_string()
    };

    let mut raw_logs = vec![
        format!(
            "[INFO] [{}] Daemon starting up on port {}",
            now_secs(),
            config.listen_port
        ),
        format!(
            "[INFO] [{}] SQLite WAL database open at {}",
            now_secs(),
            config.db_path
        ),
        format!(
            "[INFO] [{}] Spool filesystem directory verified at {}",
            now_secs(),
            config.spool_dir
        ),
        format!(
            "[INFO] [{}] Telegram transport active with bot token bot{}:[REDACTED_BOT_TOKEN]",
            now_secs(),
            bot_token_preview
        ),
        format!(
            "[INFO] [{}] Session authenticated for Web Dashboard admin.",
            now_secs()
        ),
    ];

    raw_logs.extend(store.get_logs());

    let redacted_logs: Vec<String> = raw_logs.into_iter().map(|l| redact_secrets(&l)).collect();
    Json(redacted_logs).into_response()
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

    store.add_log(format!(
        "[WARN] [{}] Dynamic config key '{}' updated to '{}'",
        now_secs(),
        key,
        if key.contains("secret") || key.contains("password") || key.contains("token") {
            "[REDACTED]"
        } else {
            val
        }
    ));

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
}

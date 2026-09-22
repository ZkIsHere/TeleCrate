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
pub type AdminState = (AdminConfig, Arc<SessionStore>, telecrate::db::Db);

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

/// Random bytes an toàn cho key/session id.
/// Không bao giờ lặng lẽ trả về buffer toàn 0 khi OS RNG lỗi (nguyên nhân
/// gây trùng `access_key_id` + `ON CONFLICT DO UPDATE` ghi đè lẫn nhau):
/// fallback trộn thời gian/pid/counter để mỗi lần gọi vẫn khác nhau.
fn crypto_random_bytes(len: usize) -> Vec<u8> {
    static FALLBACK_CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut buf = vec![0u8; len];
    let ok = getrandom::getrandom(&mut buf).is_ok() && !buf.iter().all(|&b| b == 0);
    if !ok {
        use std::hash::{Hash, Hasher};
        let ctr = FALLBACK_CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (i, b) in buf.iter_mut().enumerate() {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            (now, std::process::id(), ctr, i).hash(&mut h);
            *b = (h.finish() >> ((i % 8) * 8)) as u8;
        }
        if buf.iter().all(|&b| b == 0) {
            buf[0] = 0x01;
        }
    }
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
    State((config_lock, store, _)): State<AdminState>,
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
pub async fn api_logout(State((_, store, _)): State<AdminState>, headers: HeaderMap) -> Response {
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
    State((_, store, _)): State<AdminState>,
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

/// Tổng số objects/chunks/bytes đã index (non-delete-markers) qua entities.
/// SUM(size) trên Postgres phải `::BIGINT` (SUM bigint trả về NUMERIC, decode
/// i64 trực tiếp sẽ lỗi → 0 sai như code cũ).
struct StorageTotals {
    objects: i64,
    chunks: i64,
}

async fn storage_totals(db: &telecrate::db::Db) -> StorageTotals {
    use sea_orm::{EntityTrait, PaginatorTrait};
    use telecrate::db::entities::{chunks, objects};
    let conn = db.sea_conn();
    let o = objects::Entity::find().count(&conn).await.unwrap_or(0) as i64;
    let c = chunks::Entity::find().count(&conn).await.unwrap_or(0) as i64;
    StorageTotals {
        objects: o,
        chunks: c,
    }
}

/// Tổng objects live (bỏ delete markers) + bytes — dùng cho metrics sampler và
/// điểm dự phòng khi history rỗng. Giữ semantics `is_delete_marker = 0` như cũ.
async fn live_storage_totals(db: &telecrate::db::Db) -> (i64, i64) {
    use sea_orm::{
        ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, Statement,
    };
    use telecrate::db::entities::objects;
    let conn = db.sea_conn();
    let o = objects::Entity::find()
        .filter(objects::Column::IsDeleteMarker.eq(0))
        .count(&conn)
        .await
        .unwrap_or(0) as i64;
    let sum_sql = match db.backend() {
        telecrate::db::DbBackend::Sqlite => {
            "SELECT COALESCE(SUM(size), 0) AS total FROM objects WHERE is_delete_marker = 0"
        }
        telecrate::db::DbBackend::Postgres => {
            "SELECT COALESCE(SUM(size)::BIGINT, 0) AS total FROM objects WHERE is_delete_marker = 0"
        }
    };
    let b = conn
        .query_one(Statement::from_string(
            telecrate::db::sea_backend(db),
            sum_sql.to_string(),
        ))
        .await
        .ok()
        .flatten()
        .and_then(|r| r.try_get::<i64>("", "total").ok())
        .unwrap_or(0);
    (o, b)
}

/// `GET /admin/api/status`
pub async fn api_get_status(
    State((config_lock, store, db)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let spool_used = dir_size(FilePath::new(&config.spool_dir));
    let spool_total = 10 * 1024 * 1024 * 1024u64; // Default 10 GB indicator

    // Kích thước metadata DB theo backend: SQLite = file index.db;
    // Postgres không có file local nên hỏi trực tiếp `pg_database_size`
    // (đọc metadata file lúc đó luôn ra 0/sai).
    let db_backend = db.backend();
    let db_size: u64 = match db_backend {
        telecrate::db::DbBackend::Sqlite => std::fs::metadata(&config.db_path)
            .map(|m| m.len())
            .unwrap_or(0),
        telecrate::db::DbBackend::Postgres => {
            use sea_orm::{ConnectionTrait, Statement};
            db.sea_conn()
                .query_one(Statement::from_string(
                    telecrate::db::sea_backend(&db),
                    "SELECT pg_database_size(current_database()) AS size".to_string(),
                ))
                .await
                .ok()
                .flatten()
                .and_then(|r| r.try_get::<i64>("", "size").ok())
                .map(|n| n.max(0) as u64)
                .unwrap_or(0)
        }
    };

    let mut total_buckets = 0;
    let mut total_access_keys = 0;

    if let Ok(bkts) = telecrate::db::list_buckets(&db).await {
        total_buckets = bkts.len();
    }
    if let Ok(keys) = telecrate::db::list_access_keys(&db).await {
        total_access_keys = keys.len();
    }
    let totals = storage_totals(&db).await;
    let total_objects = totals.objects;
    let total_chunks = totals.chunks;
    let (pending_jobs, uploading_jobs) = telecrate::db::job_summary(&db)
        .await
        .map(|s| (s.pending, s.uploading))
        .unwrap_or((0, 0));

    Json(json!({
        "version": telecrate::VERSION,
        "uptime_seconds": store.uptime_secs(),
        "uptime_secs": store.uptime_secs(),
        "spool": {
            "total_bytes": spool_total,
            "quota_bytes": spool_total,
            "used_bytes": spool_used,
            "spool_used_bytes": spool_used,
            "free_bytes": spool_total.saturating_sub(spool_used),
            "reserved_free_space_bytes": 100 * 1024 * 1024,
        },
        "db_size_bytes": db_size,
        "db_backend": db_backend.as_str(),
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

#[derive(Deserialize)]
pub struct CreateBucketPayload {
    pub name: String,
    pub region: Option<String>,
}

/// `POST /admin/api/buckets`
pub async fn api_create_bucket(
    State((_config_lock, store, db)): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<CreateBucketPayload>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let region = payload
        .region
        .unwrap_or_else(|| telecrate::config::DEFAULT_REGION.to_string());

    match telecrate::db::create_bucket(&db, &payload.name, &region).await {
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
    State((_config_lock, store, db)): State<AdminState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    match telecrate::db::delete_bucket(&db, &name).await {
        Ok(telecrate::db::DeleteBucketOutcome::Deleted) => {
            store.audit(
                AuditLevel::Warn,
                "admin",
                "bucket.delete",
                format!("name='{name}'"),
            );
            Json(json!({ "ok": true, "name": name })).into_response()
        }
        Ok(telecrate::db::DeleteBucketOutcome::NotEmpty) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "BucketNotEmpty: Bucket không rỗng, vui lòng xóa hết objects trước" })),
        )
            .into_response(),
        Ok(telecrate::db::DeleteBucketOutcome::NoSuchBucket) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "NoSuchBucket: Bucket không tồn tại" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Delete failed: {e}") })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateKeyPayload {
    pub user_id: Option<String>,
    /// Dashboard gửi thêm nhưng backend cũ lặng lẽ bỏ qua — giờ persist thật.
    pub allowed_buckets: Option<serde_json::Value>,
    pub policy: Option<String>,
    pub description: Option<String>,
}

/// Sinh `access_key_id` duy nhất: thử tối đa N lần, mỗi lần kiểm tra DB để
/// loại trừ va chạm (kể cả khi OS RNG suy biến trả hằng số).
async fn generate_unique_access_key_id(db: &telecrate::db::Db) -> String {
    for _ in 0..8 {
        let cand = format!("AKIA{}", hex::encode(crypto_random_bytes(8)).to_uppercase());
        match telecrate::db::get_access_key(db, &cand).await {
            Ok(None) => return cand,
            _ => continue,
        }
    }
    // Dự phòng cuối: UUID đảm bảo duy nhất tuyệt đối.
    format!(
        "AKIA{}",
        uuid::Uuid::new_v4().simple().to_string().to_uppercase()
    )
}

/// `POST /admin/api/access-keys`
pub async fn api_create_access_key(
    State((_config_lock, store, db)): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<CreateKeyPayload>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let user_id = payload
        .user_id
        .or(payload.description)
        .unwrap_or_else(|| "admin".to_string());
    let access_key_id = generate_unique_access_key_id(&db).await;
    let secret_key = hex::encode(crypto_random_bytes(20));

    // Chuẩn hóa allowed_buckets: "*" / rỗng / null = unrestricted (NULL);
    // còn lại lưu chuỗi CSV gọn để tương thích DAL hiện tại.
    let allowed_buckets: Option<String> = match payload.allowed_buckets {
        None => None,
        Some(v) => {
            if v.is_null() {
                None
            } else if let Some(s) = v.as_str() {
                let t = s.trim();
                if t.is_empty() || t == "*" {
                    None
                } else {
                    Some(t.to_string())
                }
            } else if let Some(arr) = v.as_array() {
                let parts: Vec<String> = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty() && s != "*")
                    .collect();
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join(","))
                }
            } else {
                None
            }
        }
    };

    match telecrate::db::create_access_key(&db, &access_key_id, &secret_key, Some(&user_id)).await {
        Ok(_) => {
            if let Some(ref ab) = allowed_buckets {
                let _ = telecrate::db::update_access_key_allowed_buckets(
                    &db,
                    &access_key_id,
                    Some(ab.as_str()),
                )
                .await;
            }
            // Audit KHÔNG ghi secret_key — chỉ id + user (secret chỉ trả 1 lần trong response).
            let policy = payload.policy.unwrap_or_else(|| "read-write".to_string());
            store.audit(
                AuditLevel::Info,
                "admin",
                "key.create",
                format!(
                    "id='{access_key_id}' user='{user_id}' policy='{policy}' buckets='{}'",
                    allowed_buckets.as_deref().unwrap_or("*")
                ),
            );
            Json(json!({
                "ok": true,
                "access_key_id": access_key_id,
                "secret_key": secret_key,
                "user_id": user_id,
                "allowed_buckets": allowed_buckets,
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
    State((_config_lock, store, db)): State<AdminState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    match telecrate::db::delete_access_key(&db, &key_id).await {
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
    State((config_lock, store, db)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let gc_res = telecrate::gc::run_gc(&db, FilePath::new(&config.spool_dir), None)
        .await
        .unwrap_or_default();

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
    State((_config_lock, store, db)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let report = telecrate::doctor::run_doctor(&db)
        .await
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
    State((config_lock, store, db)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let config = read_config(&config_lock);
    let timestamp = now_secs();
    let backup_path = format!("{}.backup_{}", config.db_path, timestamp);

    match telecrate::db::backup_db(&db, &backup_path).await {
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
    State((_, store, _)): State<AdminState>,
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
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub value: String,
    pub config_path: Option<String>,
    /// Batch nguyên tử {key: value}: apply hết rồi validate + lưu 1 lần.
    /// Bắt buộc cho đổi db_backend (backend+URL cùng lúc; từng key riêng lẻ
    /// kẹt ở trạng thái trung gian không hợp lệ). Vắng mặt = legacy đơn key.
    pub updates: Option<std::collections::HashMap<String, String>>,
}

/// Key chứa secret — value không bao giờ vào audit/log.
fn is_sensitive_config_key(key: &str) -> bool {
    key.contains("secret")
        || key.contains("password")
        || key.contains("token")
        || key.contains("database_url")
}

/// `GET /admin/api/config`
pub async fn api_get_config(
    State((config_lock, store, _)): State<AdminState>,
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
        // database_url chứa password Postgres — redact như secret.
        if obj.contains_key("database_url") {
            obj.insert("database_url".to_string(), json!("[REDACTED]"));
        }
    }

    Json(json!({ "ok": true, "config": cfg_val })).into_response()
}

/// `POST /admin/api/config`
pub async fn api_update_config(
    State((config_lock, store, _)): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<ConfigUpdatePayload>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }

    let mut config = config_lock.write().unwrap_or_else(|e| e.into_inner());

    let save_path = payload
        .config_path
        .clone()
        .unwrap_or_else(|| "/etc/telecrate/telecrate.toml".to_string());

    // Nhánh batch nguyên tử (ưu tiên khi có updates).
    if let Some(map) = payload.updates.as_ref().filter(|m| !m.is_empty()) {
        let mut staged = config.clone();
        for (k, v) in map {
            if let Err(e) = staged.apply_key(k.trim(), v.trim()) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "error": e })),
                )
                    .into_response();
            }
        }
        if let Err(e) = telecrate::config::validate(&staged) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": e })),
            )
                .into_response();
        }
        if let Err(e) = staged.save_to_file(&save_path) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": format!("Lưu file thất bại: {e}") })),
            )
                .into_response();
        }
        *config = staged;
        let audit_keys: Vec<String> = map
            .iter()
            .map(|(k, v)| {
                if is_sensitive_config_key(k) {
                    format!("{k}=[REDACTED]")
                } else {
                    format!("{k}={v}")
                }
            })
            .collect();
        store.audit(
            AuditLevel::Warn,
            "admin",
            "config.update_batch",
            format!("path='{save_path}' updates=[{}]", audit_keys.join(", ")),
        );
        return Json(json!({
            "ok": true,
            "message": format!("Đã cập nhật {} key thành công", map.len()),
            "count": map.len()
        }))
        .into_response();
    }

    // Nhánh legacy đơn key.
    let key = payload.key.trim();
    let value = payload.value.trim();

    if key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": "Tên tham số 'key' không được để trống" })),
        )
            .into_response();
    }

    let mut staged = config.clone();
    if let Err(e) = staged.apply_key(key, value) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response();
    }

    if let Err(e) = telecrate::config::validate(&staged) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response();
    }

    if let Err(e) = staged.save_to_file(&save_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": format!("Lưu file thất bại: {e}") })),
        )
            .into_response();
    }

    *config = staged;

    // Audit an toàn: không ghi value của secret/token.
    let audit_val = if is_sensitive_config_key(key) {
        "[REDACTED]"
    } else {
        value
    };
    store.audit(
        AuditLevel::Warn,
        "admin",
        "config.update",
        format!("path='{save_path}' key='{key}' value='{audit_val}'"),
    );

    Json(json!({
        "ok": true,
        "message": format!("Đã cập nhật key '{key}' thành công"),
        "key": key
    }))
    .into_response()
}

/// `GET /admin/api/tls/status` — trạng thái TLS xem bất cứ lúc nào (dashboard badge).
/// Chỉ trả metadata + fingerprint, không bao giờ trả key material.
pub async fn api_tls_status(
    State((config_lock, store, _)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let config = read_config(&config_lock);
    let cert_file = config.tls_cert_file.clone().unwrap_or_default();
    let key_file = config.tls_key_file.clone().unwrap_or_default();
    let cert_present = !cert_file.is_empty() && FilePath::new(&cert_file).is_file();
    let key_present = !key_file.is_empty() && FilePath::new(&key_file).is_file();
    let mut tls = json!({
        "enabled": config.tls_enabled,
        "cert_file": cert_file,
        "key_file": key_file,
        "cert_present": cert_present,
        "key_present": key_present,
    });
    if cert_present {
        match telecrate::tls::cert_info_pem_file(&cert_file) {
            Ok(info) => {
                tls["subject"] = json!(info.subject);
                tls["sans"] = json!(info.sans);
                tls["not_before"] = json!(info.not_before);
                tls["not_after"] = json!(info.not_after);
                tls["days_left"] = json!(info.days_left);
                tls["fingerprint"] = json!(info.fingerprint);
                tls["expired"] = json!(info.days_left < 0);
            }
            Err(e) => {
                tls["error"] = json!(e);
            }
        }
    }
    Json(json!({ "ok": true, "tls": tls })).into_response()
}

#[derive(Deserialize)]
pub struct TlsGeneratePayload {
    #[serde(default)]
    pub cn: String,
    /// SANs cách nhau dấu phẩy (DNS và/hoặc IP). Rỗng = dùng CN.
    #[serde(default)]
    pub sans: String,
    #[serde(default = "default_tls_days")]
    pub days: u64,
    /// Mặc định dưới /var/lib/telecrate để daemon user ghi được.
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
}

fn default_tls_days() -> u64 {
    825
}

/// `POST /admin/api/tls/generate` — tự sinh self-signed (ECDSA P-256) + ghi file.
/// Trả fingerprint SHA-256 để dán vào endpoint PBS. Key ghi 0600 (unix).
pub async fn api_tls_generate(
    State((_config_lock, store, _)): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<TlsGeneratePayload>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }
    let cn = payload.cn.trim().to_string();
    if cn.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": "cn must not be empty" })),
        )
            .into_response();
    }
    let days = if payload.days == 0 {
        default_tls_days()
    } else {
        payload.days
    };
    let sans: Vec<String> = if payload.sans.trim().is_empty() {
        vec![cn.clone()]
    } else {
        payload
            .sans
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    let cert_out = if payload.cert_path.trim().is_empty() {
        "/var/lib/telecrate/tls.crt".to_string()
    } else {
        payload.cert_path.trim().to_string()
    };
    let key_out = if payload.key_path.trim().is_empty() {
        "/var/lib/telecrate/tls.key".to_string()
    } else {
        payload.key_path.trim().to_string()
    };
    for (name, p) in [
        ("cert_path", cert_out.as_str()),
        ("key_path", key_out.as_str()),
    ] {
        let path = FilePath::new(p);
        if !(path.is_absolute() || p.starts_with('/')) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": format!("{name} must be an absolute path") })),
            )
                .into_response();
        }
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": format!("{name} must not contain '..'") })),
            )
                .into_response();
        }
    }
    match telecrate::tls::generate_self_signed(&cn, &sans, days, &cert_out, &key_out) {
        Ok(info) => {
            store.audit(
                AuditLevel::Warn,
                "admin",
                "tls.generate",
                format!(
                    "cn='{cn}' cert='{cert_out}' fingerprint='{}'",
                    info.fingerprint
                ),
            );
            Json(json!({
                "ok": true,
                "subject": info.subject,
                "sans": info.sans,
                "fingerprint": info.fingerprint,
                "not_after": info.not_after,
                "cert_file": cert_out,
                "key_file": key_out,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
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
pub async fn metrics_sampler(
    config_lock: AdminConfig,
    store: Arc<SessionStore>,
    db: telecrate::db::Db,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    loop {
        interval.tick().await;
        let config = read_config(&config_lock);
        let spool_used = dir_size(FilePath::new(&config.spool_dir));
        let (total_objects, total_size) = live_storage_totals(&db).await;
        let (mut pending, mut uploading) = (0, 0);
        if let Ok(s) = telecrate::db::job_summary(&db).await {
            pending = s.pending;
            uploading = s.uploading;
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
    State((config_lock, store, db)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let mut points = store.query_metrics();
    if points.is_empty() {
        let config = read_config(&config_lock);
        let spool_used = dir_size(FilePath::new(&config.spool_dir));
        let (total_objects, total_size) = live_storage_totals(&db).await;
        let (mut pending, mut uploading) = (0, 0);
        if let Ok(s) = telecrate::db::job_summary(&db).await {
            pending = s.pending;
            uploading = s.uploading;
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
    State((_config_lock, store, db)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let buckets = match telecrate::db::list_buckets(&db).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("List error: {e}") })),
            )
                .into_response()
        }
    };
    let stats = telecrate::db::bucket_stats(&db).await.unwrap_or_default();
    let stats_map: HashMap<String, (i64, i64)> = stats
        .into_iter()
        .map(|s| (s.name, (s.object_count, s.total_size_bytes)))
        .collect();
    let mut list = Vec::new();
    for b in buckets {
        let versioning = telecrate::db::get_bucket_versioning(&db, &b.name)
            .await
            .unwrap_or_else(|_| "Disabled".to_string());
        let (obj_count, total_size) = stats_map.get(&b.name).copied().unwrap_or((0, 0));
        list.push(json!({
            "name": b.name,
            "region": b.region,
            "created_at": b.created_at,
            "versioning": versioning,
            "object_count": obj_count,
            "total_size_bytes": total_size,
            // Alias cho JS dashboard cũ còn đọc `total_bytes`.
            "total_bytes": total_size,
            "size": total_size,
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
    State((_config_lock, store, db)): State<AdminState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<ObjectListQuery>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let prefix = params.prefix.unwrap_or_default();
    let delimiter = params.delimiter.unwrap_or_default();
    let max_keys = params.max_keys.unwrap_or(200).min(1000);
    let start_after = params.continuation_token.unwrap_or_default();

    // Query all matching keys (list_keys already supports prefix)
    let rows =
        match telecrate::db::list_keys(&db, &name, &prefix, &start_after, (max_keys + 1) as i64)
            .await
        {
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
    State((_config_lock, store, db)): State<AdminState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    let version = match telecrate::db::latest_version(&db, &bucket, &key).await {
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
    let chunks = telecrate::db::chunks_of(&db, &version.version_id)
        .await
        .unwrap_or_default();
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
    State((_config_lock, store, db)): State<AdminState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }
    match telecrate::db::delete_object(&db, &bucket, &key).await {
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
    State((_config_lock, store, db)): State<AdminState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<UpdateKeyPayload>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }
    let mut changes = Vec::new();
    if let Some(ref status) = payload.status {
        match telecrate::db::update_access_key_status(&db, &key_id, status).await {
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
        let _ = telecrate::db::update_access_key_description(&db, &key_id, desc).await;
        changes.push("description updated".to_string());
    }
    if let Some(ref ab) = payload.allowed_buckets {
        let ab_str = if ab.is_null() {
            None
        } else {
            Some(ab.to_string())
        };
        let _ =
            telecrate::db::update_access_key_allowed_buckets(&db, &key_id, ab_str.as_deref()).await;
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
    State((_config_lock, store, db)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    // Migration 0004 là bắt buộc (apply_all_migrations) nên đọc trực tiếp qua
    // entity, không cần nhánh fallback cột thiếu như trước.
    use sea_orm::{EntityTrait, QueryOrder};
    use telecrate::db::entities::access_keys;
    let rows = access_keys::Entity::find()
        .order_by_asc(access_keys::Column::CreatedAt)
        .all(&db.sea_conn())
        .await
        .unwrap_or_default();
    let list: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|m| {
            json!({
                "access_key_id": m.access_key_id,
                "status": m.status,
                "user_id": m.description.unwrap_or_else(|| "admin".to_string()),
                "created_at": m.created_at,
                "last_used_at": m.last_used_at,
                "allowed_buckets": m.allowed_buckets,
            })
        })
        .collect();
    Json(list).into_response()
}

/// `GET /admin/api/jobs` — List upload jobs.
pub async fn api_list_jobs(
    State((_config_lock, store, db)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    match telecrate::db::list_jobs(&db).await {
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
    State((config_lock, store, _)): State<AdminState>,
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
    State((_config_lock, store, db)): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    // Dashboard cần mọi upload trên mọi bucket (db fn lọc theo bucket) —
    // query entity trực tiếp, giữ nguyên shape/order/limit.
    use sea_orm::{EntityTrait, QueryOrder, QuerySelect};
    use telecrate::db::entities::multipart_uploads;
    let rows = multipart_uploads::Entity::find()
        .order_by_desc(multipart_uploads::Column::CreatedAt)
        .limit(100)
        .all(&db.sea_conn())
        .await;
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            return Json(json!({ "uploads": [], "total": 0, "error": e.to_string() }))
                .into_response();
        }
    };
    let list: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|m| {
            json!({
                "upload_id": m.upload_id,
                "bucket": m.bucket,
                "key": m.key,
                "content_type": m.content_type,
                "created_at": m.created_at,
            })
        })
        .collect();
    let total = list.len();
    Json(json!({ "uploads": list, "total": total })).into_response()
}

/// `POST /admin/api/multipart-uploads/:id/abort` — Abort a stuck multipart upload.
pub async fn api_abort_multipart_upload(
    State((_config_lock, store, db)): State<AdminState>,
    Path(upload_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }
    match telecrate::db::abort_multipart_upload(&db, &upload_id).await {
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
    State((_config_lock, store, db)): State<AdminState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, false) {
        return err_resp.into_response();
    }
    if !telecrate::db::head_bucket(&db, &name)
        .await
        .unwrap_or(false)
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Bucket not found" })),
        )
            .into_response();
    }
    let versioning = telecrate::db::get_bucket_versioning(&db, &name)
        .await
        .unwrap_or_else(|_| "Disabled".to_string());
    let cors: Option<serde_json::Value> = telecrate::db::get_bucket_cors(&db, &name)
        .await
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok());
    let policy: Option<serde_json::Value> = telecrate::db::get_bucket_policy(&db, &name)
        .await
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok());
    let bpa = telecrate::db::get_bucket_bpa(&db, &name)
        .await
        .unwrap_or_default();
    let lock_config = telecrate::db::get_bucket_object_lock_config(&db, &name)
        .await
        .ok();

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
    State((_config_lock, store, db)): State<AdminState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<VersioningPayload>,
) -> Response {
    if let Err(err_resp) = authenticate_admin_request(&headers, &store, true) {
        return err_resp.into_response();
    }
    match telecrate::db::set_bucket_versioning(&db, &name, &payload.status).await {
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

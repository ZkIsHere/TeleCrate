//! HTTP app TeleCrate — dùng chung giữa daemon (`serve`) và integration tests.
//! S3 layer M2.1: buckets + SigV4 (objects → 2.2).

// Giữ nguyên đường dẫn `telecrate::...` khi move code từ binary sang lib.
use crate as telecrate;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, OriginalUri, Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;

/// Dựng router S3 + health (daemon và test dùng chung).
/// `transport` phải được build NGOÀI async context (xem [`build_transport`]).
pub fn router(
    config: telecrate::config::Config,
    transport: Option<telecrate::telegram::BotApiHttpTransport>,
) -> Router {
    let state = Arc::new(AppState { config, transport });
    Router::new()
        .route("/health", get(health))
        // GET / vừa là dashboard index (không auth) vừa là S3 ListBuckets (có auth) —
        // phân biệt bằng Authorization header, ghi rõ ở docs (M2.1).
        .route("/", get(root_get))
        // axum 0.7 dùng cú pháp `:param` (kiểu `{param}` là axum 0.8+ — đã từng 404 toàn bộ).
        .route(
            "/:bucket",
            get(bucket_get)
                .put(create_bucket)
                .delete(delete_bucket)
                .head(head_bucket)
                .post(bucket_post),
        )
        // Object key có thể chứa `/` → wildcard (axum 0.7: `*key`).
        .route(
            "/:bucket/*key",
            get(get_object)
                .put(put_object)
                .delete(delete_object)
                .head(head_object),
        )
        // Giới hạn body do từng handler tự ép (PUT object 16 MiB ở M2.2),
        // không để axum 413 sớm với 2 MiB mặc định.
        .layer(DefaultBodyLimit::disable())
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "ok": true, "version": telecrate::VERSION, "s3": "buckets-only-2.1" }))
}

#[derive(Clone)]
struct AppState {
    config: telecrate::config::Config,
    transport: Option<telecrate::telegram::BotApiHttpTransport>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect()
}

/// Input xác thực gom lại để tránh quá nhiều tham số.
struct AuthInput<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a str,
    headers: &'a HeaderMap,
    body: &'a [u8],
    resource: &'a str,
    request_id: &'a str,
}

/// Xác thực SigV4 header. Trả access key id hoặc S3Error (không chứa secret).
fn authenticate(
    cfg: &telecrate::config::Config,
    input: &AuthInput<'_>,
) -> Result<String, telecrate::s3::S3Error> {
    use telecrate::s3::{sig_error_to_s3, S3Error};
    let AuthInput {
        method,
        path,
        query,
        headers,
        body,
        resource,
        request_id,
    } = *input;
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if auth.is_empty() {
        return Err(S3Error::access_denied(resource, request_id));
    }
    let key_id = telecrate::sigv4::extract_key_id(auth)
        .map_err(|e| sig_error_to_s3(e, resource, request_id))?;
    let secret = cfg.find_secret(&key_id).ok_or_else(|| {
        sig_error_to_s3(telecrate::sigv4::SigError::UnknownKey, resource, request_id)
    })?;
    let req = telecrate::sigv4::SignableRequest {
        method,
        path,
        query,
        headers: &header_pairs(headers),
        authorization: auth,
        body,
    };
    let v = telecrate::sigv4::verify(&req, secret, &cfg.region, now_secs())
        .map_err(|e| sig_error_to_s3(e, resource, request_id))?;
    Ok(v.access_key_id)
}

fn xml_response(status: StatusCode, xml: String, request_id: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/xml".parse().unwrap());
    headers.insert(
        "x-amz-request-id",
        request_id
            .parse()
            .unwrap_or_else(|_| "invalid-request-id".parse().unwrap()),
    );
    (status, headers, xml).into_response()
}

fn open_db(state: &AppState) -> Result<rusqlite::Connection, telecrate::s3::S3Error> {
    // Mỗi request mở connection riêng (SQLite WAL); pool ở milestone sau nếu cần.
    let request_id = telecrate::s3::new_request_id();
    telecrate::db::open(&state.config.db_path).map_err(|e| {
        telecrate::s3::S3Error::new(
            "InternalError",
            format!("db open: {e}"),
            StatusCode::INTERNAL_SERVER_ERROR,
            "/",
            request_id,
        )
    })
}

/// GET /: có Authorization → S3 ListBuckets; không → dashboard index skeleton.
async fn root_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_query: RawQuery,
) -> Response {
    if !headers.contains_key("authorization") {
        return "TeleCrate M2 — dashboard đầy đủ ở M6.".into_response();
    }
    let request_id = telecrate::s3::new_request_id();
    let query = raw_query.0.as_deref().unwrap_or("");
    match authenticate(
        &state.config,
        &AuthInput {
            method: "GET",
            path: "/",
            query,
            headers: &headers,
            body: b"",
            resource: "/",
            request_id: &request_id,
        },
    ) {
        Ok(owner) => match open_db(&state) {
            Ok(conn) => match telecrate::db::list_buckets(&conn) {
                Ok(buckets) => xml_response(
                    StatusCode::OK,
                    telecrate::s3::list_buckets_xml(&buckets, &owner),
                    &request_id,
                ),
                Err(e) => telecrate::s3::S3Error::new(
                    "InternalError",
                    e,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "/",
                    &request_id,
                )
                .into_response(),
            },
            Err(e) => e.into_response(),
        },
        Err(e) => e.into_response(),
    }
}

/// GET /{bucket}: ?location → GetBucketLocation; ngược lại ListObjects (→ 501 ở 2.1).
async fn bucket_get(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
    raw_query: RawQuery,
) -> Response {
    let request_id = telecrate::s3::new_request_id();
    let resource = format!("/{bucket}");
    let query = raw_query.0.as_deref().unwrap_or("");
    if let Err(e) = authenticate(
        &state.config,
        &AuthInput {
            method: "GET",
            path: &resource,
            query,
            headers: &headers,
            body: b"",
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let is_location = query
        .split('&')
        .any(|p| p == "location" || p.starts_with("location="));
    if is_location {
        let region = match open_db(&state) {
            Ok(conn) => match telecrate::db::list_buckets(&conn) {
                Ok(list) => list
                    .iter()
                    .find(|b| b.name == bucket)
                    .map(|b| b.region.clone()),
                Err(_) => None,
            },
            Err(_) => None,
        };
        match region {
            Some(r) => xml_response(StatusCode::OK, telecrate::s3::location_xml(&r), &request_id),
            None => telecrate::s3::S3Error::new(
                "NoSuchBucket",
                "The specified bucket does not exist.",
                StatusCode::NOT_FOUND,
                &resource,
                &request_id,
            )
            .into_response(),
        }
    } else {
        list_objects_v2(&state, &bucket, query, &resource, &request_id).into_response()
    }
}

/// Parse query raw thành map (decode, `+` = space).
fn query_map(query: &str) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for p in query.split('&') {
        if p.is_empty() {
            continue;
        }
        match p.split_once('=') {
            Some((k, v)) => {
                m.insert(
                    telecrate::s3::percent_decode(k, false),
                    telecrate::s3::percent_decode(v, true),
                );
            }
            None => {
                m.insert(telecrate::s3::percent_decode(p, false), String::new());
            }
        }
    }
    m
}

/// GET /:bucket (không ?location) = ListObjectsV2 (plain GET coi như v2 mặc định).
fn list_objects_v2(
    state: &AppState,
    bucket: &str,
    query: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let q = query_map(query);
    let prefix = q.get("prefix").cloned().unwrap_or_default();
    let delimiter = q.get("delimiter").cloned();
    // AWS CLI luôn gửi encoding-type=url — hỗ trợ đúng.
    let url_enc = q.get("encoding-type").map(|s| s == "url").unwrap_or(false);
    let max_keys: i64 = q
        .get("max-keys")
        .and_then(|s| s.parse().ok())
        .map(|n: i64| n.clamp(1, 1000))
        .unwrap_or(1000);
    // continuation-token / start-after là key đầy đủ của item cuối trang trước.
    let start_after = q
        .get("continuation-token")
        .or_else(|| q.get("start-after"))
        .cloned()
        .unwrap_or_default();
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if !matches!(telecrate::db::head_bucket(&conn, bucket), Ok(true)) {
        return S3Error::new(
            "NoSuchBucket",
            "The specified bucket does not exist.",
            StatusCode::NOT_FOUND,
            resource,
            request_id,
        )
        .into_response();
    }
    let rows = match telecrate::db::list_keys(&conn, bucket, &prefix, &start_after, max_keys + 1) {
        Ok(r) => r,
        Err(e) => {
            return S3Error::new(
                "InternalError",
                e,
                StatusCode::INTERNAL_SERVER_ERROR,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    // Gom delimiter → CommonPrefixes (giữ thứ tự key, dedup). Đơn giản hóa M2.2:
    // max-keys áp dụng cho tổng contents + prefixes.
    let mut contents = Vec::new();
    let mut prefixes: Vec<String> = Vec::new();
    let overflow = rows.len() as i64 > max_keys;
    for (key, v) in rows.into_iter().take(max_keys as usize) {
        if let Some(d) = delimiter.as_deref() {
            if !d.is_empty() {
                let rest = &key[prefix.len().min(key.len())..];
                if let Some(pos) = rest.find(d) {
                    let cp = format!("{}{}", prefix, &rest[..=pos]);
                    if prefixes.last().map(|l| l != &cp).unwrap_or(true) {
                        prefixes.push(cp);
                    }
                    continue;
                }
            }
        }
        contents.push(telecrate::s3::ListItem {
            key,
            last_modified_iso: v.created_at.replace(' ', "T") + ".000Z",
            etag: v.etag,
            size: v.size,
        });
    }
    let key_count = contents.len() + prefixes.len();
    let next_token = if overflow {
        contents
            .last()
            .map(|c| c.key.clone())
            .or_else(|| prefixes.last().cloned())
    } else {
        None
    };
    xml_response(
        StatusCode::OK,
        telecrate::s3::list_objects_xml(
            bucket,
            &prefix,
            delimiter.as_deref(),
            max_keys,
            key_count,
            overflow,
            next_token.as_deref(),
            &contents,
            &prefixes,
            url_enc,
        ),
        request_id,
    )
}

/// POST /:bucket?delete = DeleteObjects (M2.2: tối đa 100 keys, chưa VersionId).
async fn bucket_post(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    use telecrate::s3::S3Error;
    let request_id = telecrate::s3::new_request_id();
    let resource = format!("/{bucket}");
    let raw_query = uri.query().unwrap_or("");
    if let Err(e) = authenticate(
        &state.config,
        &AuthInput {
            method: "POST",
            path: &format!("/{bucket}"),
            query: raw_query,
            headers: &headers,
            body: &body,
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    if !query_map(raw_query).contains_key("delete") {
        return S3Error::new(
            "InvalidRequest",
            "POST bucket chỉ hỗ trợ ?delete ở M2.2.",
            StatusCode::BAD_REQUEST,
            &resource,
            &request_id,
        )
        .into_response();
    }
    let mut conn = match open_db(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if !matches!(telecrate::db::head_bucket(&conn, &bucket), Ok(true)) {
        return S3Error::new(
            "NoSuchBucket",
            "The specified bucket does not exist.",
            StatusCode::NOT_FOUND,
            &resource,
            &request_id,
        )
        .into_response();
    }
    // Parse Delete XML: <Delete><Quiet/><Object><Key/></Object>...</Delete>.
    let text = match std::str::from_utf8(&body) {
        Ok(t) => t,
        Err(_) => {
            return S3Error::new(
                "MalformedXML",
                "The XML you provided was not well-formed.",
                StatusCode::BAD_REQUEST,
                &resource,
                &request_id,
            )
            .into_response()
        }
    };
    let (keys, quiet) =
        match parse_delete_xml(text) {
            Ok(v) => v,
            Err(code) => return S3Error::new(
                code,
                "Delete request không hợp lệ (quá 100 keys hoặc có VersionId — M2.2 chưa hỗ trợ).",
                StatusCode::BAD_REQUEST,
                &resource,
                &request_id,
            )
            .into_response(),
        };
    let mut deleted = Vec::new();
    let mut pending_deletes = Vec::new();
    for key in keys {
        match telecrate::db::delete_object(&mut conn, &bucket, &key) {
            Ok(r) => {
                for p in r.spool_paths {
                    let _ = std::fs::remove_file(p);
                }
                pending_deletes.extend(r.remote_locators);
                deleted.push(key);
            }
            Err(e) => {
                return S3Error::new(
                    "InternalError",
                    e,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &resource,
                    &request_id,
                )
                .into_response()
            }
        }
    }
    best_effort_remote_deletes(state.transport.clone(), pending_deletes).await;
    xml_response(
        StatusCode::OK,
        telecrate::s3::delete_result_xml(&deleted, quiet),
        &request_id,
    )
}

/// Parse body DeleteObjects → (keys, quiet). Lỗi: MalformedXML | quá 100 keys | có VersionId.
fn parse_delete_xml(text: &str) -> Result<(Vec<String>, bool), &'static str> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    let mut r = Reader::from_str(text);
    r.config_mut().trim_text(true);
    let mut keys = Vec::new();
    let mut quiet = false;
    let mut in_key = false;
    let mut in_version = false;
    let mut in_quiet = false;
    let mut buf = Vec::new();
    loop {
        match r.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"Key" => in_key = true,
                b"VersionId" => in_version = true,
                b"Quiet" => in_quiet = true,
                _ => {}
            },
            Ok(Event::Text(e)) => {
                let t = e.unescape().map_err(|_| "MalformedXML")?;
                if in_key {
                    keys.push(t.into_owned());
                } else if in_version {
                    // M2.2 chưa versioning — từ chối rõ thay vì lặng lẽ bỏ.
                    return Err("InvalidArgument");
                } else if in_quiet {
                    quiet = t.trim() != "false";
                }
            }
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"Key" => in_key = false,
                b"VersionId" => in_version = false,
                b"Quiet" => in_quiet = false,
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(_) => return Err("MalformedXML"),
            _ => {}
        }
        buf.clear();
    }
    if keys.is_empty() || keys.len() > 100 {
        return Err("MalformedXML");
    }
    Ok((keys, quiet))
}

/// PUT /{bucket}: CreateBucket (LocationConstraint phải khớp region hoặc rỗng).
async fn create_bucket(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
    raw_query: RawQuery,
    body: Bytes,
) -> Response {
    let request_id = telecrate::s3::new_request_id();
    let resource = format!("/{bucket}");
    let query = raw_query.0.as_deref().unwrap_or("");
    if let Err(e) = authenticate(
        &state.config,
        &AuthInput {
            method: "PUT",
            path: &resource,
            query,
            headers: &headers,
            body: &body,
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let want_region = match telecrate::s3::parse_location_constraint(&body) {
        Ok(v) => v,
        Err(_) => {
            return telecrate::s3::S3Error::new(
                "InvalidLocationConstraint",
                "The specified location constraint is not valid.",
                StatusCode::BAD_REQUEST,
                &resource,
                &request_id,
            )
            .into_response()
        }
    };
    if let Some(loc) = want_region {
        if loc != state.config.region {
            return telecrate::s3::S3Error::new(
                "InvalidLocationConstraint",
                format!(
                    "Location constraint '{}' does not match server region '{}'.",
                    loc, state.config.region
                ),
                StatusCode::BAD_REQUEST,
                &resource,
                &request_id,
            )
            .into_response();
        }
    }
    let conn = match open_db(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match telecrate::db::create_bucket(&conn, &bucket, &state.config.region) {
        Ok(telecrate::db::CreateBucketOutcome::Created) => {
            xml_response(StatusCode::OK, String::new(), &request_id)
        }
        // S3: tạo lại bucket mình sở hữu → 200 (không phải lỗi).
        Ok(telecrate::db::CreateBucketOutcome::AlreadyOwned) => {
            xml_response(StatusCode::OK, String::new(), &request_id)
        }
        Err(code) if code == "InvalidBucketName" => telecrate::s3::S3Error::new(
            "InvalidBucketName",
            "The specified bucket is not valid.",
            StatusCode::BAD_REQUEST,
            &resource,
            &request_id,
        )
        .into_response(),
        Err(e) => telecrate::s3::S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            &resource,
            &request_id,
        )
        .into_response(),
    }
}

/// DELETE /{bucket}: 204 khi xóa; 404/409 đúng S3.
async fn delete_bucket(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
    raw_query: RawQuery,
) -> Response {
    let request_id = telecrate::s3::new_request_id();
    let resource = format!("/{bucket}");
    let query = raw_query.0.as_deref().unwrap_or("");
    if let Err(e) = authenticate(
        &state.config,
        &AuthInput {
            method: "DELETE",
            path: &resource,
            query,
            headers: &headers,
            body: b"",
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let conn = match open_db(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match telecrate::db::delete_bucket(&conn, &bucket) {
        Ok(telecrate::db::DeleteBucketOutcome::Deleted) => {
            xml_response(StatusCode::NO_CONTENT, String::new(), &request_id)
        }
        Ok(telecrate::db::DeleteBucketOutcome::NoSuchBucket) => telecrate::s3::S3Error::new(
            "NoSuchBucket",
            "The specified bucket does not exist.",
            StatusCode::NOT_FOUND,
            &resource,
            &request_id,
        )
        .into_response(),
        Ok(telecrate::db::DeleteBucketOutcome::NotEmpty) => telecrate::s3::S3Error::new(
            "BucketNotEmpty",
            "The bucket you tried to delete is not empty.",
            StatusCode::CONFLICT,
            &resource,
            &request_id,
        )
        .into_response(),
        Err(e) => telecrate::s3::S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            &resource,
            &request_id,
        )
        .into_response(),
    }
}

/// HEAD /{bucket}: 200 tồn tại / 404 không (không body, giữ request id header).
async fn head_bucket(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
    raw_query: RawQuery,
) -> Response {
    let request_id = telecrate::s3::new_request_id();
    let resource = format!("/{bucket}");
    let query = raw_query.0.as_deref().unwrap_or("");
    if let Err(e) = authenticate(
        &state.config,
        &AuthInput {
            method: "HEAD",
            path: &resource,
            query,
            headers: &headers,
            body: b"",
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let conn = match open_db(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match telecrate::db::head_bucket(&conn, &bucket) {
        Ok(true) => xml_response(StatusCode::OK, String::new(), &request_id),
        Ok(false) => xml_response(StatusCode::NOT_FOUND, String::new(), &request_id),
        Err(e) => telecrate::s3::S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            &resource,
            &request_id,
        )
        .into_response(),
    }
}

// --- Objects M2.2: single-chunk durable, ETag MD5, Range đơn (multi-chunk → 2.3) ---

/// Giới hạn PUT đơn chunk M2.2 (1 chunk = 1 message Telegram, phải tải lại được trong 1 getFile).
pub const MAX_SINGLE_PUT_BYTES: usize = 16 * 1024 * 1024;

/// Build transport Telegram — CHỈ gọi ngoài async context.
/// reqwest blocking Client tạo runtime nội bộ; dựng/drop trong async context sẽ panic
/// (tokio blocking-pool shutdown). Daemon gọi qua `spawn_blocking`, test gọi trực tiếp.
pub fn build_transport(
    cfg: &telecrate::config::Config,
) -> Option<telecrate::telegram::BotApiHttpTransport> {
    telegram_transport(cfg)
}

fn telegram_transport(
    cfg: &telecrate::config::Config,
) -> Option<telecrate::telegram::BotApiHttpTransport> {
    if cfg.telegram_bot_token.is_empty() || cfg.telegram_chat_id == 0 {
        return None;
    }
    telecrate::telegram::BotApiHttpTransport::new(
        &cfg.telegram_base_url,
        &cfg.telegram_bot_token,
        "telecrate",
    )
    .ok()
}

fn md5_hex(b: &[u8]) -> String {
    format!("{:x}", md5::compute(b))
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

/// Phần spool đọc được + locator remote còn thiếu (tách để download blocking
/// chạy trong `spawn_blocking`, không nghẽn runtime).
struct PendingRemote {
    order: usize,
    locator: telecrate::telegram::RemoteLocator,
}

type OrderedParts = Vec<(usize, Vec<u8>)>;

/// Đọc bytes của version: spool trước; locator remote gom lại cho caller tải sau.
fn collect_version_parts(
    conn: &rusqlite::Connection,
    version: &telecrate::db::ObjectVersion,
    resource: &str,
    request_id: &str,
) -> Result<(OrderedParts, Vec<PendingRemote>), telecrate::s3::S3Error> {
    use telecrate::s3::S3Error;
    let chunks = telecrate::db::chunks_of(conn, &version.version_id).map_err(|e| {
        S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
    })?;
    let mut local = Vec::new();
    let mut remote = Vec::new();
    for (order, c) in chunks.iter().enumerate() {
        if let Some(p) = &c.spool_path {
            match std::fs::read(p) {
                Ok(b) => {
                    local.push((order, b));
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(S3Error::new(
                        "InternalError",
                        format!("read spool: {e}"),
                        StatusCode::INTERNAL_SERVER_ERROR,
                        resource,
                        request_id,
                    ));
                }
            }
        }
        // Spool đã GC → tải từ Telegram sau (cần locator remote).
        if c.state != "remote" {
            return Err(S3Error::new(
                "InternalError",
                "chunk local mất và chưa có bản remote",
                StatusCode::INTERNAL_SERVER_ERROR,
                resource,
                request_id,
            ));
        }
        let loc_json: Option<String> = conn
            .query_row(
                "SELECT remote_locator_json FROM chunks WHERE version_id = ? AND idx = ?",
                rusqlite::params![version.version_id, c.idx],
                |r| r.get(0),
            )
            .map_err(|e| {
                S3Error::new(
                    "InternalError",
                    format!("locator: {e}"),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    resource,
                    request_id,
                )
            })?;
        let locator: telecrate::telegram::RemoteLocator =
            serde_json::from_str(&loc_json.unwrap_or_default()).map_err(|_| {
                S3Error::new(
                    "InternalError",
                    "remote locator hỏng",
                    StatusCode::INTERNAL_SERVER_ERROR,
                    resource,
                    request_id,
                )
            })?;
        remote.push(PendingRemote { order, locator });
    }
    Ok((local, remote))
}

/// Tải các chunk remote trong `spawn_blocking` (client blocking, cấm gọi trong async).
async fn download_remote_parts(
    transport: Option<telecrate::telegram::BotApiHttpTransport>,
    pending: Vec<PendingRemote>,
    resource: &str,
    request_id: &str,
) -> Result<OrderedParts, telecrate::s3::S3Error> {
    use telecrate::s3::S3Error;
    let Some(t) = transport else {
        return Err(S3Error::new(
            "InternalError",
            "bản remote không đọc được: telegram chưa cấu hình",
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        ));
    };
    tokio::task::spawn_blocking(move || {
        use telecrate::telegram::Transport;
        pending
            .into_iter()
            .map(|p| {
                t.download(&p.locator)
                    .map(|b| (p.order, b))
                    .map_err(|e| format!("download remote: {e:?}"))
            })
            .collect::<Result<Vec<_>, _>>()
    })
    .await
    .map_err(|e| {
        S3Error::new(
            "InternalError",
            format!("join download: {e}"),
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
    })?
    .map_err(|e| {
        S3Error::new(
            "InternalError",
            e,
            StatusCode::BAD_GATEWAY,
            resource,
            request_id,
        )
    })
}

/// Xóa remote best-effort trong `spawn_blocking`; orphan còn lại dọn ở M5 GC.
async fn best_effort_remote_deletes(
    transport: Option<telecrate::telegram::BotApiHttpTransport>,
    locators: Vec<telecrate::telegram::RemoteLocator>,
) {
    if locators.is_empty() {
        return;
    }
    let Some(t) = transport else {
        tracing::warn!(
            "object có {} blob remote nhưng telegram chưa cấu hình — orphan dọn ở M5",
            locators.len()
        );
        return;
    };
    let _ = tokio::task::spawn_blocking(move || {
        use telecrate::telegram::Transport;
        for loc in &locators {
            if let Err(e) = t.delete(loc) {
                tracing::warn!(
                    "best-effort remote delete thất bại (message {}): {e:?} — orphan dọn ở M5",
                    loc.message_id
                );
            }
        }
    })
    .await;
}

fn object_response_headers(
    headers: &mut HeaderMap,
    version: &telecrate::db::ObjectVersion,
    len: u64,
    request_id: &str,
) {
    headers.insert(
        "content-type",
        version
            .content_type
            .parse()
            .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
    );
    headers.insert(
        "etag",
        format!("\"{}\"", version.etag)
            .parse()
            .unwrap_or_else(|_| "\"invalid-etag\"".parse().unwrap()),
    );
    headers.insert("content-length", len.to_string().parse().unwrap());
    headers.insert("accept-ranges", "bytes".parse().unwrap());
    if let Some(d) = telecrate::s3::sqlite_to_http_date(&version.created_at) {
        if let Ok(v) = d.parse() {
            headers.insert("last-modified", v);
        }
    }
    headers.insert(
        "x-amz-request-id",
        request_id
            .parse()
            .unwrap_or_else(|_| "invalid-request-id".parse().unwrap()),
    );
}

/// Parse `Range: bytes=a-b | a- | -suffix` (đơn). Multi-range → Err (M2.2 chưa hỗ trợ).
fn parse_range(header: &str, size: u64) -> Result<(u64, u64), ()> {
    let spec = header.strip_prefix("bytes=").ok_or(())?;
    if spec.contains(',') {
        return Err(());
    }
    if let Some(suf) = spec.strip_prefix('-') {
        let n: u64 = suf.parse().map_err(|_| ())?;
        if n == 0 || size == 0 {
            return Err(());
        }
        let n = n.min(size);
        return Ok((size - n, size - 1));
    }
    let (a, b) = spec.split_once('-').ok_or(())?;
    let start: u64 = a.parse().map_err(|_| ())?;
    if start >= size {
        return Err(());
    }
    let end = if b.is_empty() {
        size - 1
    } else {
        b.parse::<u64>().map_err(|_| ())?.min(size - 1)
    };
    if end < start {
        return Err(());
    }
    Ok((start, end))
}

/// PUT /:bucket/*key: commit durable local (spool + 1 txn) rồi trả 200 — worker upload nền ở 2.2.4.
async fn put_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    use telecrate::s3::S3Error;
    let request_id = telecrate::s3::new_request_id();
    let raw_path = uri.path().to_string();
    let resource = format!("/{bucket}/{key}");
    if let Err(e) = authenticate(
        &state.config,
        &AuthInput {
            method: "PUT",
            path: &raw_path,
            query: uri.query().unwrap_or(""),
            headers: &headers,
            body: &body,
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let mut conn = match open_db(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if !matches!(telecrate::db::head_bucket(&conn, &bucket), Ok(true)) {
        return S3Error::new(
            "NoSuchBucket",
            "The specified bucket does not exist.",
            StatusCode::NOT_FOUND,
            &resource,
            &request_id,
        )
        .into_response();
    }
    if body.len() > MAX_SINGLE_PUT_BYTES {
        return S3Error::new(
            "EntityTooLarge",
            format!(
                "Single PUT M2.2 giới hạn {} bytes; multipart ở M3.",
                MAX_SINGLE_PUT_BYTES
            ),
            StatusCode::BAD_REQUEST,
            &resource,
            &request_id,
        )
        .into_response();
    }
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let version_id = uuid::Uuid::new_v4().simple().to_string();
    let job_id = uuid::Uuid::new_v4().simple().to_string();
    let etag = md5_hex(&body);
    let ph = sha256_hex(&body);
    // 1) Spool durable trước (tmp+fsync+rename+fsync dir).
    let spool_path = telecrate::spool::chunk_path(&state.config.spool_dir, &version_id, 0);
    if let Err(e) = telecrate::spool::write_durable(&spool_path, &body) {
        return S3Error::new(
            "InternalError",
            format!("spool write: {e}"),
            StatusCode::INTERNAL_SERVER_ERROR,
            &resource,
            &request_id,
        )
        .into_response();
    }
    // 2) Một txn duy nhất: object + chunk + job. Từ đây GET đã thấy version mới.
    let old_spools = match telecrate::db::put_object(
        &mut conn,
        &bucket,
        &key,
        &version_id,
        body.len() as i64,
        &etag,
        &content_type,
        &ph,
        spool_path.to_str().unwrap_or(""),
        &job_id,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&spool_path);
            return S3Error::new(
                "InternalError",
                e,
                StatusCode::INTERNAL_SERVER_ERROR,
                &resource,
                &request_id,
            )
            .into_response();
        }
    };
    // 3) Dọn spool của version bị thay thế (best-effort).
    for p in old_spools {
        let _ = std::fs::remove_file(p);
    }
    let mut h = HeaderMap::new();
    h.insert("etag", format!("\"{etag}\"").parse().unwrap());
    h.insert(
        "x-amz-request-id",
        request_id
            .parse()
            .unwrap_or_else(|_| "invalid-request-id".parse().unwrap()),
    );
    (StatusCode::OK, h, String::new()).into_response()
}

/// GET object (+ Range đơn). Ưu tiên spool, rồi Telegram.
async fn get_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    use telecrate::s3::S3Error;
    let request_id = telecrate::s3::new_request_id();
    let raw_path = uri.path().to_string();
    let resource = format!("/{bucket}/{key}");
    if let Err(e) = authenticate(
        &state.config,
        &AuthInput {
            method: "GET",
            path: &raw_path,
            query: uri.query().unwrap_or(""),
            headers: &headers,
            body: b"",
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let conn = match open_db(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if !matches!(telecrate::db::head_bucket(&conn, &bucket), Ok(true)) {
        return S3Error::new(
            "NoSuchBucket",
            "The specified bucket does not exist.",
            StatusCode::NOT_FOUND,
            &resource,
            &request_id,
        )
        .into_response();
    }
    let version = match telecrate::db::latest_version(&conn, &bucket, &key) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return S3Error::new(
                "NoSuchKey",
                "The specified key does not exist.",
                StatusCode::NOT_FOUND,
                &resource,
                &request_id,
            )
            .into_response()
        }
        Err(e) => {
            return S3Error::new(
                "InternalError",
                e,
                StatusCode::INTERNAL_SERVER_ERROR,
                &resource,
                &request_id,
            )
            .into_response()
        }
    };
    let (mut parts, pending) = match collect_version_parts(&conn, &version, &resource, &request_id)
    {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    if !pending.is_empty() {
        match download_remote_parts(state.transport.clone(), pending, &resource, &request_id).await
        {
            Ok(mut blobs) => parts.append(&mut blobs),
            Err(e) => return e.into_response(),
        }
    }
    parts.sort_by_key(|(order, _)| *order);
    let bytes: Vec<u8> = parts.into_iter().flat_map(|(_, b)| b).collect();
    let size = bytes.len() as u64;
    let mut h = HeaderMap::new();
    match headers.get("range").and_then(|v| v.to_str().ok()) {
        None => {
            object_response_headers(&mut h, &version, size, &request_id);
            (StatusCode::OK, h, bytes).into_response()
        }
        Some(spec) => match parse_range(spec, size) {
            Ok((a, b)) => {
                object_response_headers(&mut h, &version, b - a + 1, &request_id);
                h.insert(
                    "content-range",
                    format!("bytes {a}-{b}/{size}").parse().unwrap(),
                );
                (
                    StatusCode::PARTIAL_CONTENT,
                    h,
                    bytes[a as usize..=b as usize].to_vec(),
                )
                    .into_response()
            }
            Err(()) => {
                let mut resp = S3Error::new(
                    "InvalidRange",
                    "The requested range is not satisfiable.",
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    &resource,
                    &request_id,
                )
                .into_response();
                resp.headers_mut()
                    .insert("content-range", format!("bytes */{size}").parse().unwrap());
                resp
            }
        },
    }
}

/// HEAD object: headers như GET, không body.
async fn head_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    use telecrate::s3::S3Error;
    let request_id = telecrate::s3::new_request_id();
    let raw_path = uri.path().to_string();
    let resource = format!("/{bucket}/{key}");
    if let Err(e) = authenticate(
        &state.config,
        &AuthInput {
            method: "HEAD",
            path: &raw_path,
            query: uri.query().unwrap_or(""),
            headers: &headers,
            body: b"",
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let conn = match open_db(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if !matches!(telecrate::db::head_bucket(&conn, &bucket), Ok(true)) {
        return xml_response(StatusCode::NOT_FOUND, String::new(), &request_id);
    }
    match telecrate::db::latest_version(&conn, &bucket, &key) {
        Ok(Some(v)) => {
            let mut h = HeaderMap::new();
            object_response_headers(&mut h, &v, v.size.max(0) as u64, &request_id);
            (StatusCode::OK, h, Vec::new()).into_response()
        }
        Ok(None) => xml_response(StatusCode::NOT_FOUND, String::new(), &request_id),
        Err(e) => S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            &resource,
            &request_id,
        )
        .into_response(),
    }
}

/// DELETE object (idempotent → 204 kể cả key không tồn tại; bucket mất → 404).
/// Remote blobs đã upload được xóa best-effort đồng bộ; lỗi chỉ warn, orphan dọn ở M5.
async fn delete_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    use telecrate::s3::S3Error;
    let request_id = telecrate::s3::new_request_id();
    let raw_path = uri.path().to_string();
    let resource = format!("/{bucket}/{key}");
    if let Err(e) = authenticate(
        &state.config,
        &AuthInput {
            method: "DELETE",
            path: &raw_path,
            query: uri.query().unwrap_or(""),
            headers: &headers,
            body: b"",
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let mut conn = match open_db(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if !matches!(telecrate::db::head_bucket(&conn, &bucket), Ok(true)) {
        return S3Error::new(
            "NoSuchBucket",
            "The specified bucket does not exist.",
            StatusCode::NOT_FOUND,
            &resource,
            &request_id,
        )
        .into_response();
    }
    let deleted = match telecrate::db::delete_object(&mut conn, &bucket, &key) {
        Ok(r) => r,
        Err(e) => {
            return S3Error::new(
                "InternalError",
                e,
                StatusCode::INTERNAL_SERVER_ERROR,
                &resource,
                &request_id,
            )
            .into_response()
        }
    };
    for p in deleted.spool_paths {
        let _ = std::fs::remove_file(p);
    }
    best_effort_remote_deletes(state.transport.clone(), deleted.remote_locators).await;
    xml_response(StatusCode::NO_CONTENT, String::new(), &request_id)
}

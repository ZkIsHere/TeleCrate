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
/// `transport`/`keys` phải được build NGOÀI async context (xem [`build_transport`]).
pub fn router(
    config: telecrate::config::Config,
    transport: Option<telecrate::telegram::BotApiHttpTransport>,
    keys: telecrate::crypto::KeyStore,
) -> Router {
    let session_store = Arc::new(telecrate::admin::SessionStore::new());
    let state = Arc::new(AppState {
        config: config.clone(),
        transport,
        keys,
        session_store: session_store.clone(),
    });

    let admin_state = (config, session_store);

    Router::new()
        .route("/health", get(health))
        .route(
            "/dashboard/style.css",
            get(telecrate::admin::get_dashboard_css),
        )
        .route("/dashboard/app.js", get(telecrate::admin::get_dashboard_js))
        .route(
            "/admin/api/login",
            axum::routing::post(telecrate::admin::api_login).with_state(admin_state.clone()),
        )
        .route(
            "/admin/api/logout",
            axum::routing::post(telecrate::admin::api_logout).with_state(admin_state.clone()),
        )
        .route(
            "/admin/api/session",
            get(telecrate::admin::api_session_status).with_state(admin_state.clone()),
        )
        .route(
            "/admin/api/status",
            get(telecrate::admin::api_get_status).with_state(admin_state.clone()),
        )
        .route(
            "/admin/api/buckets",
            get(telecrate::admin::api_list_buckets)
                .post(telecrate::admin::api_create_bucket)
                .with_state(admin_state.clone()),
        )
        .route(
            "/admin/api/buckets/:name",
            axum::routing::delete(telecrate::admin::api_delete_bucket)
                .with_state(admin_state.clone()),
        )
        .route(
            "/admin/api/access-keys",
            get(telecrate::admin::api_list_access_keys)
                .post(telecrate::admin::api_create_access_key)
                .with_state(admin_state.clone()),
        )
        .route(
            "/admin/api/access-keys/:id",
            axum::routing::delete(telecrate::admin::api_revoke_access_key)
                .with_state(admin_state.clone()),
        )
        .route(
            "/admin/api/gc",
            axum::routing::post(telecrate::admin::api_run_gc).with_state(admin_state.clone()),
        )
        .route(
            "/admin/api/doctor",
            axum::routing::post(telecrate::admin::api_run_doctor).with_state(admin_state.clone()),
        )
        .route(
            "/admin/api/backup",
            axum::routing::post(telecrate::admin::api_run_backup).with_state(admin_state.clone()),
        )
        .route(
            "/admin/api/audit-logs",
            get(telecrate::admin::api_get_audit_logs).with_state(admin_state.clone()),
        )
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
                .post(bucket_post)
                .options(bucket_options),
        )
        // Object key có thể chứa `/` → wildcard (axum 0.7: `*key`).
        .route(
            "/:bucket/*key",
            get(get_object)
                .put(put_object)
                .delete(delete_object)
                .head(head_object)
                .post(post_object)
                .options(object_options),
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
    /// KeyStore chỉ chứa key material trong RAM — không Debug/log.
    keys: telecrate::crypto::KeyStore,
    #[allow(dead_code)]
    session_store: Arc<telecrate::admin::SessionStore>,
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

fn find_secret_key(state: &AppState, key_id: &str) -> Option<String> {
    if let Some(s) = state.config.find_secret(key_id) {
        return Some(s.to_string());
    }
    if let Ok(conn) = telecrate::db::open(&state.config.db_path) {
        if let Ok(Some(k)) = telecrate::db::get_access_key(&conn, key_id) {
            if k.status == "Active" {
                return Some(k.secret_key);
            }
        }
    }
    None
}

/// Xác thực SigV4 header hoặc presigned query. Trả access key id hoặc S3Error.
fn authenticate(state: &AppState, input: &AuthInput<'_>) -> Result<String, telecrate::s3::S3Error> {
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

    if !auth.is_empty() {
        let key_id = telecrate::sigv4::extract_key_id(auth)
            .map_err(|e| sig_error_to_s3(e, resource, request_id))?;
        let secret = find_secret_key(state, &key_id).ok_or_else(|| {
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
        let v = telecrate::sigv4::verify(&req, &secret, &state.config.region, now_secs())
            .map_err(|e| sig_error_to_s3(e, resource, request_id))?;
        return Ok(v.access_key_id);
    }

    if query.contains("X-Amz-Algorithm") || query.contains("X-Amz-Credential") {
        let key_id = telecrate::sigv4::extract_key_id_from_query(query)
            .map_err(|e| sig_error_to_s3(e, resource, request_id))?;
        let secret = find_secret_key(state, &key_id).ok_or_else(|| {
            sig_error_to_s3(telecrate::sigv4::SigError::UnknownKey, resource, request_id)
        })?;
        let req = telecrate::sigv4::SignableRequest {
            method,
            path,
            query,
            headers: &header_pairs(headers),
            authorization: "",
            body,
        };
        let v = telecrate::sigv4::verify_presigned(&req, &secret, &state.config.region, now_secs())
            .map_err(|e| sig_error_to_s3(e, resource, request_id))?;
        return Ok(v.access_key_id);
    }

    Err(S3Error::access_denied(resource, request_id))
}

fn check_auth_with_policy(
    state: &AppState,
    action: &str,
    bucket: Option<&str>,
    key: Option<&str>,
    input: &AuthInput<'_>,
) -> Result<String, telecrate::s3::S3Error> {
    use telecrate::s3::S3Error;
    let auth_res = authenticate(state, input);

    if let Some(bkt) = bucket {
        if let Ok(conn) = telecrate::db::open(&state.config.db_path) {
            let policy_opt = telecrate::db::get_bucket_policy(&conn, bkt).ok().flatten();
            let bpa_opt = telecrate::db::get_bucket_bpa(&conn, bkt).ok();

            let user_id = match &auth_res {
                Ok(k) => k.as_str(),
                Err(_) => "anonymous",
            };

            if let Some(policy_json) = policy_opt {
                let eval_res = telecrate::policy::eval_policy(
                    &policy_json,
                    bkt,
                    key,
                    action,
                    user_id,
                    bpa_opt.as_ref(),
                );
                match eval_res {
                    telecrate::policy::PolicyEvalResult::Deny => {
                        return Err(S3Error::new(
                            "AccessDenied",
                            "Access Denied by Bucket Policy",
                            StatusCode::FORBIDDEN,
                            input.resource,
                            input.request_id,
                        ));
                    }
                    telecrate::policy::PolicyEvalResult::Allow => {
                        return Ok(user_id.to_string());
                    }
                    telecrate::policy::PolicyEvalResult::NoMatch => {
                        if user_id == "anonymous" {
                            return Err(auth_res.unwrap_err());
                        } else {
                            return Ok(user_id.to_string());
                        }
                    }
                }
            }
        }
    }

    auth_res
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

fn empty_ok_response(request_id: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-request-id",
        request_id
            .parse()
            .unwrap_or_else(|_| "invalid-request-id".parse().unwrap()),
    );
    (StatusCode::OK, headers, "").into_response()
}

fn no_content_response(request_id: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-request-id",
        request_id
            .parse()
            .unwrap_or_else(|_| "invalid-request-id".parse().unwrap()),
    );
    (StatusCode::NO_CONTENT, headers, "").into_response()
}

fn apply_cors_headers(
    mut resp: Response,
    state: &AppState,
    bucket: &str,
    headers: &HeaderMap,
    method: &str,
) -> Response {
    let origin = match headers.get("origin").and_then(|v| v.to_str().ok()) {
        Some(o) if !o.is_empty() => o,
        _ => return resp,
    };

    let conn = match telecrate::db::open(&state.config.db_path) {
        Ok(c) => c,
        Err(_) => return resp,
    };

    if let Ok(Some(cors_xml)) = telecrate::db::get_bucket_cors(&conn, bucket) {
        if let Ok(cors_cfg) = telecrate::cors::parse_cors_xml(&cors_xml) {
            let req_hdrs = headers
                .get("access-control-request-headers")
                .and_then(|v| v.to_str().ok());
            if let Some(c_match) =
                telecrate::cors::match_cors_rule(&cors_cfg, origin, method, req_hdrs)
            {
                let hdrs = resp.headers_mut();
                if let Ok(val) = c_match.allow_origin.parse() {
                    hdrs.insert("access-control-allow-origin", val);
                }
                if !c_match.expose_headers.is_empty() {
                    if let Ok(val) = c_match.expose_headers.parse() {
                        hdrs.insert("access-control-expose-headers", val);
                    }
                }
            }
        }
    }
    resp
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
        return telecrate::admin::get_dashboard_html().await;
    }
    let request_id = telecrate::s3::new_request_id();
    let query = raw_query.0.as_deref().unwrap_or("");
    match authenticate(
        &state,
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
    let qmap = query_map(query);

    let action = if qmap.contains_key("cors") {
        "s3:GetBucketCORS"
    } else if qmap.contains_key("policy") {
        "s3:GetBucketPolicy"
    } else if qmap.contains_key("publicAccessBlock") {
        "s3:GetBucketPublicAccessBlock"
    } else if qmap.contains_key("object-lock") {
        "s3:GetBucketObjectLockConfiguration"
    } else {
        "s3:ListBucket"
    };

    if let Err(e) = check_auth_with_policy(
        &state,
        action,
        Some(&bucket),
        None,
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

    let resp = if qmap.contains_key("cors") {
        get_bucket_cors_handler(&state, &bucket, &resource, &request_id)
    } else if qmap.contains_key("policy") {
        get_bucket_policy_handler(&state, &bucket, &resource, &request_id)
    } else if qmap.contains_key("publicAccessBlock") {
        get_bucket_bpa_handler(&state, &bucket, &resource, &request_id)
    } else if qmap.contains_key("object-lock") {
        get_bucket_lock_config_handler(&state, &bucket, &resource, &request_id)
    } else if qmap.contains_key("uploads") {
        list_multipart_uploads_handler(&state, &bucket, &resource, &request_id)
    } else if qmap.contains_key("versioning") {
        get_bucket_versioning_handler(&state, &bucket, &resource, &request_id)
    } else if qmap.contains_key("versions") {
        list_object_versions_handler(&state, &bucket, query, &resource, &request_id)
    } else if query
        .split('&')
        .any(|p| p == "location" || p.starts_with("location="))
    {
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
        list_objects_v2(&state, &bucket, query, &resource, &request_id)
    };

    apply_cors_headers(resp, &state, &bucket, &headers, "GET")
}

fn get_bucket_versioning_handler(
    state: &AppState,
    bucket: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
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
    let status = telecrate::db::get_bucket_versioning(&conn, bucket)
        .unwrap_or_else(|_| "Disabled".to_string());
    xml_response(
        StatusCode::OK,
        telecrate::s3::versioning_configuration_xml(&status),
        request_id,
    )
}

fn put_bucket_versioning_handler(
    state: &AppState,
    bucket: &str,
    body: &Bytes,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => {
            return S3Error::new(
                "MalformedXML",
                "Invalid XML in request body",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    let status = match telecrate::s3::parse_versioning_configuration_xml(text) {
        Ok(s) => s,
        Err(_) => {
            return S3Error::new(
                "MalformedXML",
                "Invalid VersioningConfiguration XML",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    let mut conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match telecrate::db::set_bucket_versioning(&mut conn, bucket, &status) {
        Ok(()) => xml_response(StatusCode::OK, String::new(), request_id),
        Err(e) if e == "NoSuchBucket" => S3Error::new(
            "NoSuchBucket",
            "The specified bucket does not exist.",
            StatusCode::NOT_FOUND,
            resource,
            request_id,
        )
        .into_response(),
        Err(e) => S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response(),
    }
}

fn list_object_versions_handler(
    state: &AppState,
    bucket: &str,
    query: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let q = query_map(query);
    let prefix = q.get("prefix").cloned().unwrap_or_default();
    let key_marker = q.get("key-marker").cloned().unwrap_or_default();
    let version_id_marker = q.get("version-id-marker").cloned().unwrap_or_default();
    let max_keys: i64 = q
        .get("max-keys")
        .and_then(|s| s.parse().ok())
        .map(|n: i64| n.clamp(1, 1000))
        .unwrap_or(1000);

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
    let versions = match telecrate::db::list_object_versions(
        &conn,
        bucket,
        &prefix,
        &key_marker,
        &version_id_marker,
        max_keys,
    ) {
        Ok(v) => v,
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
    let xml = telecrate::s3::list_object_versions_xml(
        bucket,
        &prefix,
        &key_marker,
        &version_id_marker,
        &versions,
    );
    xml_response(StatusCode::OK, xml, request_id)
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

struct FormField {
    pub name: String,
    pub filename: Option<String>,
    pub data: Vec<u8>,
}

fn parse_multipart_form_data(content_type: &str, body: &[u8]) -> Vec<FormField> {
    let mut fields = Vec::new();
    let boundary = match content_type.split(';').find_map(|p| {
        let p = p.trim();
        if p.starts_with("boundary=") {
            Some(p.trim_start_matches("boundary=").trim_matches('"'))
        } else {
            None
        }
    }) {
        Some(b) => b,
        None => return fields,
    };

    let delimiter = format!("--{boundary}");
    let delimiter_bytes = delimiter.as_bytes();

    let mut cursor = 0;
    while cursor < body.len() {
        let rest = &body[cursor..];
        let pos = match rest
            .windows(delimiter_bytes.len())
            .position(|w| w == delimiter_bytes)
        {
            Some(p) => p,
            None => break,
        };

        let part_start = cursor + pos + delimiter_bytes.len();
        cursor = part_start;

        if cursor + 2 <= body.len() && &body[cursor..cursor + 2] == b"--" {
            break;
        }

        if cursor + 2 <= body.len() && &body[cursor..cursor + 2] == b"\r\n" {
            cursor += 2;
        }

        let next_pos = match body[cursor..]
            .windows(delimiter_bytes.len())
            .position(|w| w == delimiter_bytes)
        {
            Some(p) => cursor + p,
            None => body.len(),
        };

        let part_bytes = &body[cursor..next_pos];
        cursor = next_pos;

        let header_end = match part_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(p) => p,
            None => continue,
        };

        let headers_str = String::from_utf8_lossy(&part_bytes[..header_end]);
        let mut payload = &part_bytes[header_end + 4..];
        if payload.ends_with(b"\r\n") {
            payload = &payload[..payload.len() - 2];
        }

        let mut name = String::new();
        let mut filename = None;

        for line in headers_str.lines() {
            if line
                .to_ascii_lowercase()
                .starts_with("content-disposition:")
            {
                for param in line.split(';') {
                    let param = param.trim();
                    if param.starts_with("name=") {
                        name = param
                            .trim_start_matches("name=")
                            .trim_matches('"')
                            .to_string();
                    } else if param.starts_with("filename=") {
                        filename = Some(
                            param
                                .trim_start_matches("filename=")
                                .trim_matches('"')
                                .to_string(),
                        );
                    }
                }
            }
        }

        if !name.is_empty() {
            fields.push(FormField {
                name,
                filename,
                data: payload.to_vec(),
            });
        }
    }

    fields
}

async fn post_policy_form_handler(
    state: &AppState,
    bucket: &str,
    headers: &HeaderMap,
    body: &[u8],
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let fields = parse_multipart_form_data(content_type, body);

    let find_field = |name: &str| -> Option<String> {
        fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| String::from_utf8_lossy(&f.data).to_string())
    };

    let key = match find_field("key") {
        Some(k) if !k.is_empty() => k,
        _ => {
            return S3Error::new(
                "InvalidArgument",
                "Form field 'key' is required",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    let file_field = match fields
        .iter()
        .find(|f| f.name == "file" || f.filename.is_some())
    {
        Some(f) => f,
        None => {
            return S3Error::new(
                "InvalidArgument",
                "Form field 'file' is required",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    let policy_b64 = match find_field("policy") {
        Some(p) => p,
        None => {
            return S3Error::new(
                "AccessDenied",
                "Form field 'policy' is required for POST upload",
                StatusCode::FORBIDDEN,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    let signature = match find_field("x-amz-signature").or_else(|| find_field("signature")) {
        Some(s) => s,
        None => {
            return S3Error::new(
                "AccessDenied",
                "Form field 'x-amz-signature' is required",
                StatusCode::FORBIDDEN,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    let credential = match find_field("x-amz-credential").or_else(|| find_field("credential")) {
        Some(c) => c,
        None => {
            return S3Error::new(
                "AccessDenied",
                "Form field 'x-amz-credential' is required",
                StatusCode::FORBIDDEN,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    let key_id = match credential.split('/').next() {
        Some(k) if !k.is_empty() => k,
        _ => {
            return S3Error::new(
                "InvalidAccessKeyId",
                "The AWS Access Key Id you provided does not exist in our records.",
                StatusCode::FORBIDDEN,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    let secret = match find_secret_key(state, key_id) {
        Some(s) => s,
        None => {
            return S3Error::new(
                "InvalidAccessKeyId",
                "The AWS Access Key Id you provided does not exist in our records.",
                StatusCode::FORBIDDEN,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    if let Err(e) = telecrate::sigv4::verify_post_policy(
        &policy_b64,
        &signature,
        &credential,
        &secret,
        &state.config.region,
    ) {
        return telecrate::s3::sig_error_to_s3(e, resource, request_id).into_response();
    }

    if let Err(code) = telecrate::s3::parse_and_validate_post_policy(
        &policy_b64,
        bucket,
        &key,
        file_field.data.len() as u64,
        now_secs(),
    ) {
        return S3Error::new(
            code,
            "Post Policy condition failed",
            StatusCode::BAD_REQUEST,
            resource,
            request_id,
        )
        .into_response();
    }

    let version_id = uuid::Uuid::new_v4().simple().to_string();
    let job_id = uuid::Uuid::new_v4().simple().to_string();
    let etag = md5_hex(&file_field.data);

    let chunk_path =
        std::path::Path::new(&state.config.spool_dir).join(format!("{version_id}_0.chunk"));
    let spool_str = chunk_path.to_str().unwrap().to_string();

    if let Err(e) = telecrate::spool::write_durable(&chunk_path, &file_field.data) {
        return S3Error::new(
            "InternalError",
            e.to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }

    let chunk_spec = telecrate::db::NewChunk {
        offset: 0,
        length: file_field.data.len() as i64,
        plaintext_sha256: sha256_hex(&file_field.data),
        ciphertext_sha256: sha256_hex(&file_field.data),
        spool_path: spool_str,
        mode: telecrate::crypto::MODE_NONE.to_string(),
        key_ref: None,
    };

    let mut conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let (old_spools, final_version_id) = match telecrate::db::put_object(
        &mut conn,
        bucket,
        &key,
        &version_id,
        file_field.data.len() as i64,
        &etag,
        "application/octet-stream",
        None,
        None,
        &[chunk_spec],
        &job_id,
    ) {
        Ok(res) => res,
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

    for p in old_spools {
        let _ = std::fs::remove_file(p);
    }

    let mut resp = xml_response(StatusCode::NO_CONTENT, String::new(), request_id);
    if let Ok(hv) = final_version_id.parse() {
        resp.headers_mut().insert("x-amz-version-id", hv);
    }
    resp.headers_mut().insert("etag", etag.parse().unwrap());
    resp
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

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.starts_with("multipart/form-data") {
        return post_policy_form_handler(&state, &bucket, &headers, &body, &resource, &request_id)
            .await;
    }

    if let Err(e) = authenticate(
        &state,
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
            "POST bucket chỉ hỗ trợ ?delete hoặc multipart/form-data policy upload.",
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
    let qmap = query_map(query);

    let action = if qmap.contains_key("cors") {
        "s3:PutBucketCORS"
    } else if qmap.contains_key("policy") {
        "s3:PutBucketPolicy"
    } else if qmap.contains_key("publicAccessBlock") {
        "s3:PutBucketPublicAccessBlock"
    } else if qmap.contains_key("object-lock") {
        "s3:PutBucketObjectLockConfiguration"
    } else {
        "s3:CreateBucket"
    };

    if let Err(e) = check_auth_with_policy(
        &state,
        action,
        Some(&bucket),
        None,
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

    let resp = if qmap.contains_key("cors") {
        put_bucket_cors_handler(&state, &bucket, &body, &resource, &request_id)
    } else if qmap.contains_key("policy") {
        put_bucket_policy_handler(&state, &bucket, &body, &resource, &request_id)
    } else if qmap.contains_key("publicAccessBlock") {
        put_bucket_bpa_handler(&state, &bucket, &body, &resource, &request_id)
    } else if qmap.contains_key("object-lock") {
        put_bucket_lock_config_handler(&state, &bucket, &body, &resource, &request_id)
    } else if qmap.contains_key("versioning") {
        put_bucket_versioning_handler(&state, &bucket, &body, &resource, &request_id)
    } else {
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
    };

    apply_cors_headers(resp, &state, &bucket, &headers, "PUT")
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
    let qmap = query_map(query);

    let action = if qmap.contains_key("cors") {
        "s3:PutBucketCORS"
    } else if qmap.contains_key("policy") {
        "s3:DeleteBucketPolicy"
    } else if qmap.contains_key("publicAccessBlock") {
        "s3:PutBucketPublicAccessBlock"
    } else {
        "s3:DeleteBucket"
    };

    if let Err(e) = check_auth_with_policy(
        &state,
        action,
        Some(&bucket),
        None,
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

    let resp = if qmap.contains_key("cors") {
        delete_bucket_cors_handler(&state, &bucket, &resource, &request_id)
    } else if qmap.contains_key("policy") {
        delete_bucket_policy_handler(&state, &bucket, &resource, &request_id)
    } else if qmap.contains_key("publicAccessBlock") {
        delete_bucket_bpa_handler(&state, &bucket, &resource, &request_id)
    } else {
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
    };

    apply_cors_headers(resp, &state, &bucket, &headers, "DELETE")
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
        &state,
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

// --- Objects M2.2-M2.3: durable, ETag MD5, Range đơn. M2.3 split multi-chunk. ---

/// Giới hạn object M2.3 (buffer trong RAM khi PUT — streaming ở milestone sau).
pub const MAX_OBJECT_BYTES: usize = 128 * 1024 * 1024;

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

fn extract_user_metadata(headers: &HeaderMap) -> Option<String> {
    let mut map = std::collections::HashMap::new();
    for (k, v) in headers {
        let key_str = k.as_str();
        if key_str.starts_with("x-amz-meta-") {
            if let Ok(val) = v.to_str() {
                let meta_key = key_str.strip_prefix("x-amz-meta-").unwrap();
                map.insert(meta_key.to_lowercase(), val.to_string());
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        serde_json::to_string(&map).ok()
    }
}

fn extract_system_metadata(headers: &HeaderMap) -> Option<String> {
    let mut map = std::collections::HashMap::new();
    for header_name in &[
        "content-disposition",
        "content-encoding",
        "cache-control",
        "expires",
        "x-amz-server-side-encryption",
        "x-amz-server-side-encryption-customer-algorithm",
        "x-amz-server-side-encryption-customer-key-md5",
    ] {
        if let Some(v) = headers.get(*header_name) {
            if let Ok(val) = v.to_str() {
                map.insert(header_name.to_string(), val.to_string());
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        serde_json::to_string(&map).ok()
    }
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
    if version.version_id != "null" && !version.version_id.is_empty() {
        if let Ok(v) = version.version_id.parse() {
            headers.insert("x-amz-version-id", v);
        }
    }
    if let Some(d) = telecrate::s3::sqlite_to_http_date(&version.created_at) {
        if let Ok(v) = d.parse() {
            headers.insert("last-modified", v);
        }
    }
    if let Some(user_meta_json) = &version.user_metadata_json {
        if let Ok(map) =
            serde_json::from_str::<std::collections::HashMap<String, String>>(user_meta_json)
        {
            for (k, v) in map {
                let header_name = format!("x-amz-meta-{k}");
                if let Ok(hv) = v.parse() {
                    if let Ok(hn) = axum::http::HeaderName::from_bytes(header_name.as_bytes()) {
                        headers.insert(hn, hv);
                    }
                }
            }
        }
    }
    if let Some(sys_meta_json) = &version.system_metadata_json {
        if let Ok(map) =
            serde_json::from_str::<std::collections::HashMap<String, String>>(sys_meta_json)
        {
            for (k, v) in map {
                if let Ok(hv) = v.parse() {
                    if let Ok(hn) = axum::http::HeaderName::from_bytes(k.as_bytes()) {
                        headers.insert(hn, hv);
                    }
                }
            }
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
    let raw_query = uri.query().unwrap_or("");
    if let Err(e) = check_auth_with_policy(
        &state,
        "s3:PutObject",
        Some(&bucket),
        Some(&key),
        &AuthInput {
            method: "PUT",
            path: &raw_path,
            query: raw_query,
            headers: &headers,
            body: &body,
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let _sse_cfg = match telecrate::crypto::parse_and_validate_sse_headers(&headers) {
        Ok(cfg) => cfg,
        Err((status, code, msg)) => {
            return S3Error::new(code, msg, status, &resource, &request_id).into_response();
        }
    };
    let qmap = query_map(raw_query);
    let vid = qmap.get("versionId").map(|s| s.as_str()).unwrap_or("null");
    if qmap.contains_key("retention") {
        return put_object_retention_handler(
            &state,
            &bucket,
            &key,
            vid,
            &body,
            &resource,
            &request_id,
        );
    }
    if qmap.contains_key("legal-hold") {
        return put_object_legal_hold_handler(
            &state,
            &bucket,
            &key,
            vid,
            &body,
            &resource,
            &request_id,
        );
    }
    if let (Some(upload_id), Some(part_num_str)) = (qmap.get("uploadId"), qmap.get("partNumber")) {
        return upload_part_handler(
            &state,
            &bucket,
            &key,
            upload_id,
            part_num_str,
            &resource,
            &request_id,
            &body,
        )
        .await
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
    if let Some(copy_src_header) = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
    {
        let copy_src = copy_src_header.trim_start_matches('/');
        let (src_bucket, src_key_raw) = match copy_src.split_once('/') {
            Some((b, k)) => (b, k),
            None => {
                return S3Error::new(
                    "InvalidArgument",
                    "Invalid x-amz-copy-source format (expected /bucket/key)",
                    StatusCode::BAD_REQUEST,
                    &resource,
                    &request_id,
                )
                .into_response()
            }
        };
        let src_key = telecrate::s3::percent_decode(src_key_raw, false);

        if let Ok(Some(src_ver)) = telecrate::db::latest_version(&conn, src_bucket, &src_key) {
            let outcome = telecrate::s3::eval_copy_source_conditional_headers(
                &src_ver.etag,
                &src_ver.created_at,
                &headers,
            );
            if outcome != telecrate::s3::ConditionalOutcome::Proceed {
                return S3Error::new(
                    "PreconditionFailed",
                    "At least one of the preconditions you specified did not hold.",
                    StatusCode::PRECONDITION_FAILED,
                    &resource,
                    &request_id,
                )
                .into_response();
            }
        }

        let metadata_directive = headers
            .get("x-amz-metadata-directive")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("COPY");

        let user_meta = extract_user_metadata(&headers);
        let sys_meta = extract_system_metadata(&headers);
        let content_type_opt = headers.get("content-type").and_then(|v| v.to_str().ok());

        let new_version_id = uuid::Uuid::new_v4().simple().to_string();
        let new_job_id = uuid::Uuid::new_v4().simple().to_string();

        let (old_spools, version) = match telecrate::db::copy_object_txn(
            &mut conn,
            src_bucket,
            &src_key,
            &bucket,
            &key,
            &new_version_id,
            &new_job_id,
            metadata_directive,
            content_type_opt,
            user_meta.as_deref(),
            sys_meta.as_deref(),
        ) {
            Ok(r) => r,
            Err(e) => {
                let code = if e == "NoSuchBucket" {
                    "NoSuchBucket"
                } else if e == "NoSuchKey" {
                    "NoSuchKey"
                } else {
                    "InternalError"
                };
                let status = if e == "NoSuchBucket" || e == "NoSuchKey" {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                return S3Error::new(code, e, status, &resource, &request_id).into_response();
            }
        };

        for p in old_spools {
            let _ = std::fs::remove_file(p);
        }

        let iso_date = version.created_at.replace(' ', "T") + ".000Z";
        return xml_response(
            StatusCode::OK,
            telecrate::s3::copy_object_xml(&version.etag, &iso_date),
            &request_id,
        );
    }
    let existing = telecrate::db::latest_version(&conn, &bucket, &key)
        .ok()
        .flatten();
    if let Some(ref v) = existing {
        let outcome =
            telecrate::s3::eval_conditional_headers("PUT", &v.etag, &v.created_at, &headers);
        if outcome != telecrate::s3::ConditionalOutcome::Proceed {
            return S3Error::new(
                "PreconditionFailed",
                "At least one of the preconditions you specified did not hold.",
                StatusCode::PRECONDITION_FAILED,
                &resource,
                &request_id,
            )
            .into_response();
        }
    } else if headers.contains_key("if-match") || headers.contains_key("if-unmodified-since") {
        return S3Error::new(
            "PreconditionFailed",
            "At least one of the preconditions you specified did not hold.",
            StatusCode::PRECONDITION_FAILED,
            &resource,
            &request_id,
        )
        .into_response();
    }
    if body.len() > MAX_OBJECT_BYTES {
        return S3Error::new(
            "EntityTooLarge",
            format!(
                "Object M2.3 giới hạn {} bytes (buffer RAM khi PUT; streaming ở milestone sau).",
                MAX_OBJECT_BYTES
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
    // Chế độ mã hóa của lần ghi này (toggle chỉ áp dụng ghi mới).
    let encrypting = state.config.encryption == "on";
    let write_key = if encrypting {
        match state.config.write_key_id() {
            Some(id) if state.keys.get(id).is_some() => Some(id.to_string()),
            _ => {
                return S3Error::new(
                    "InternalError",
                    "encryption=on nhưng content key ghi mới không nạp được",
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &resource,
                    &request_id,
                )
                .into_response()
            }
        }
    } else {
        None
    };
    // 1) Split multi-chunk + (mã hóa nếu bật) + spool durable từng chunk.
    // Khi bật: spool giữ ciphertext (nonce||ct), plaintext không chạm đĩa.
    let piece = state.config.chunk_size_bytes.max(1);
    let mut specs = Vec::new();
    let mut written = Vec::new();
    // Object rỗng vẫn có 0 chunk — hợp lệ (GET trả rỗng).
    for (idx, part) in body.chunks(piece).enumerate() {
        let stored: Vec<u8>;
        let (mode, key_ref, csha) = match write_key.as_deref() {
            Some(kid) => {
                let enc = match telecrate::crypto::encrypt_chunk(
                    &state.keys,
                    kid,
                    &version_id,
                    idx as u64,
                    part,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        for p in written {
                            let _ = std::fs::remove_file(p);
                        }
                        return S3Error::new(
                            "InternalError",
                            format!("encrypt: {e}"),
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &resource,
                            &request_id,
                        )
                        .into_response();
                    }
                };
                let h = sha256_hex(&enc);
                stored = enc;
                (
                    telecrate::crypto::MODE_AEAD_V1.to_string(),
                    Some(kid.to_string()),
                    h,
                )
            }
            None => {
                stored = part.to_vec();
                (
                    telecrate::crypto::MODE_NONE.to_string(),
                    None,
                    sha256_hex(part),
                )
            }
        };
        let path = telecrate::spool::chunk_path(&state.config.spool_dir, &version_id, idx as u64);
        if let Err(e) = telecrate::spool::write_durable(&path, &stored) {
            for p in written {
                let _ = std::fs::remove_file(p);
            }
            return S3Error::new(
                "InternalError",
                format!("spool write: {e}"),
                StatusCode::INTERNAL_SERVER_ERROR,
                &resource,
                &request_id,
            )
            .into_response();
        }
        written.push(path.clone());
        specs.push(telecrate::db::NewChunk {
            offset: (idx * piece) as i64,
            length: part.len() as i64,
            plaintext_sha256: sha256_hex(part),
            ciphertext_sha256: csha,
            spool_path: path.to_str().unwrap_or("").to_string(),
            mode,
            key_ref,
        });
    }
    let user_meta = extract_user_metadata(&headers);
    let sys_meta = extract_system_metadata(&headers);

    // 2) Một txn duy nhất: object + chunks + job. Từ đây GET đã thấy version mới.
    let (old_spools, created_vid) = match telecrate::db::put_object(
        &mut conn,
        &bucket,
        &key,
        &version_id,
        body.len() as i64,
        &etag,
        &content_type,
        user_meta.as_deref(),
        sys_meta.as_deref(),
        &specs,
        &job_id,
    ) {
        Ok(v) => v,
        Err(e) => {
            for p in written {
                let _ = std::fs::remove_file(p);
            }
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
    if created_vid != "null" && !created_vid.is_empty() {
        if let Ok(hv) = created_vid.parse() {
            h.insert("x-amz-version-id", hv);
        }
    }
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
    let raw_query = uri.query().unwrap_or("");
    if let Err(e) = check_auth_with_policy(
        &state,
        "s3:GetObject",
        Some(&bucket),
        Some(&key),
        &AuthInput {
            method: "GET",
            path: &raw_path,
            query: raw_query,
            headers: &headers,
            body: b"",
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let qmap = query_map(raw_query);
    let vid = qmap.get("versionId").map(|s| s.as_str()).unwrap_or("null");
    if qmap.contains_key("retention") {
        return get_object_retention_handler(&state, &bucket, &key, vid, &resource, &request_id);
    }
    if qmap.contains_key("legal-hold") {
        return get_object_legal_hold_handler(&state, &bucket, &key, vid, &resource, &request_id);
    }
    if let Some(upload_id) = qmap.get("uploadId") {
        return list_parts_handler(&state, &bucket, &key, upload_id, &resource, &request_id)
            .into_response();
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
    let vid_opt = qmap.get("versionId").map(|s| s.as_str());

    let version = match vid_opt {
        Some(vid) => match telecrate::db::get_version_by_id(&conn, &bucket, &key, vid) {
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
        },
        None => match telecrate::db::latest_version(&conn, &bucket, &key) {
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
        },
    };

    if version.is_delete_marker {
        let mut resp = S3Error::new(
            "NoSuchKey",
            "The specified key does not exist.",
            StatusCode::NOT_FOUND,
            &resource,
            &request_id,
        )
        .into_response();
        resp.headers_mut()
            .insert("x-amz-delete-marker", "true".parse().unwrap());
        if let Some(vid) = vid_opt {
            resp.headers_mut()
                .insert("x-amz-version-id", vid.parse().unwrap());
        }
        return resp;
    }

    if let Some(sys_meta_json) = &version.system_metadata_json {
        if sys_meta_json.contains("x-amz-server-side-encryption-customer-algorithm") {
            let req_sse = match telecrate::crypto::parse_and_validate_sse_headers(&headers) {
                Ok(cfg) => cfg,
                Err((status, code, msg)) => {
                    return S3Error::new(code, msg, status, &resource, &request_id).into_response();
                }
            };
            match req_sse {
                telecrate::crypto::SseConfig::SseC { key_md5_b64, .. } => {
                    if !sys_meta_json.contains(&key_md5_b64) {
                        return S3Error::new(
                            "AccessDenied",
                            "The calculated MD5 hash of the key does not match the stored MD5 hash.",
                            StatusCode::FORBIDDEN,
                            &resource,
                            &request_id,
                        ).into_response();
                    }
                }
                _ => {
                    return S3Error::new(
                        "InvalidArgument",
                        "The object was stored using SSE-C, but the request did not provide SSE-C headers.",
                        StatusCode::BAD_REQUEST,
                        &resource,
                        &request_id,
                    ).into_response();
                }
            }
        }
    }

    let outcome = telecrate::s3::eval_conditional_headers(
        "GET",
        &version.etag,
        &version.created_at,
        &headers,
    );
    match outcome {
        telecrate::s3::ConditionalOutcome::PreconditionFailed => {
            return S3Error::new(
                "PreconditionFailed",
                "At least one of the preconditions you specified did not hold.",
                StatusCode::PRECONDITION_FAILED,
                &resource,
                &request_id,
            )
            .into_response();
        }
        telecrate::s3::ConditionalOutcome::NotModified => {
            let mut h = HeaderMap::new();
            object_response_headers(&mut h, &version, version.size.max(0) as u64, &request_id);
            return (StatusCode::NOT_MODIFIED, h, Vec::new()).into_response();
        }
        telecrate::s3::ConditionalOutcome::Proceed => {}
    }
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
    // Giải mã từng chunk theo mode lưu trong DB (dữ liệu cũ giữ chế độ cũ).
    // Chunk mã hóa phải verify TOÀN đơn vị AEAD trước khi cắt Range (đúng secure).
    let metas = match telecrate::db::chunks_of(&conn, &version.version_id) {
        Ok(m) => m,
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
    let mut plain: Vec<u8> = Vec::with_capacity(version.size.max(0) as usize);
    for (order, stored) in parts {
        let meta = metas.iter().find(|c| c.idx as usize == order);
        let (mode, key_ref) = match meta {
            Some(m) => (m.encryption_mode.as_str(), m.key_ref.as_deref()),
            None => {
                return S3Error::new(
                    "InternalError",
                    "thiếu metadata chunk",
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &resource,
                    &request_id,
                )
                .into_response()
            }
        };
        if mode == telecrate::crypto::MODE_AEAD_V1 {
            let kid = key_ref.unwrap_or("");
            match telecrate::crypto::decrypt_chunk(
                &state.keys,
                kid,
                &version.version_id,
                order as u64,
                &stored,
            ) {
                Ok(p) => plain.extend_from_slice(&p),
                Err(_) => {
                    // Fail đóng, không lộ key id/key material trong message.
                    return S3Error::new(
                        "InternalError",
                        "cannot decrypt chunk (wrong key or tampered data)",
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &resource,
                        &request_id,
                    )
                    .into_response();
                }
            }
        } else {
            plain.extend_from_slice(&stored);
        }
    }
    let bytes = plain;
    let size = bytes.len() as u64;
    let mut h = HeaderMap::new();
    match headers.get("range").and_then(|v| v.to_str().ok()) {
        None => {
            object_response_headers(&mut h, &version, size, &request_id);
            (StatusCode::OK, h, bytes).into_response()
        }
        Some(spec) => {
            if !telecrate::s3::eval_if_range(&version.etag, &version.created_at, &headers) {
                object_response_headers(&mut h, &version, size, &request_id);
                (StatusCode::OK, h, bytes).into_response()
            } else {
                match parse_range(spec, size) {
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
                }
            }
        }
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
    let raw_query = uri.query().unwrap_or("");
    if let Err(e) = check_auth_with_policy(
        &state,
        "s3:GetObject",
        Some(&bucket),
        Some(&key),
        &AuthInput {
            method: "HEAD",
            path: &raw_path,
            query: raw_query,
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
    let qmap = query_map(raw_query);
    let vid_opt = qmap.get("versionId").map(|s| s.as_str());

    let version = match vid_opt {
        Some(vid) => match telecrate::db::get_version_by_id(&conn, &bucket, &key, vid) {
            Ok(Some(v)) => v,
            Ok(None) => return xml_response(StatusCode::NOT_FOUND, String::new(), &request_id),
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
        },
        None => match telecrate::db::latest_version(&conn, &bucket, &key) {
            Ok(Some(v)) => v,
            Ok(None) => return xml_response(StatusCode::NOT_FOUND, String::new(), &request_id),
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
        },
    };

    if version.is_delete_marker {
        let mut resp = xml_response(StatusCode::NOT_FOUND, String::new(), &request_id);
        resp.headers_mut()
            .insert("x-amz-delete-marker", "true".parse().unwrap());
        if let Some(vid) = vid_opt {
            resp.headers_mut()
                .insert("x-amz-version-id", vid.parse().unwrap());
        }
        return resp;
    }

    if let Some(sys_meta_json) = &version.system_metadata_json {
        if sys_meta_json.contains("x-amz-server-side-encryption-customer-algorithm") {
            let req_sse = match telecrate::crypto::parse_and_validate_sse_headers(&headers) {
                Ok(cfg) => cfg,
                Err((status, code, msg)) => {
                    return S3Error::new(code, msg, status, &resource, &request_id).into_response();
                }
            };
            match req_sse {
                telecrate::crypto::SseConfig::SseC { key_md5_b64, .. } => {
                    if !sys_meta_json.contains(&key_md5_b64) {
                        return S3Error::new(
                            "AccessDenied",
                            "The calculated MD5 hash of the key does not match the stored MD5 hash.",
                            StatusCode::FORBIDDEN,
                            &resource,
                            &request_id,
                        ).into_response();
                    }
                }
                _ => {
                    return S3Error::new(
                        "InvalidArgument",
                        "The object was stored using SSE-C, but the request did not provide SSE-C headers.",
                        StatusCode::BAD_REQUEST,
                        &resource,
                        &request_id,
                    ).into_response();
                }
            }
        }
    }

    let outcome = telecrate::s3::eval_conditional_headers(
        "HEAD",
        &version.etag,
        &version.created_at,
        &headers,
    );
    match outcome {
        telecrate::s3::ConditionalOutcome::PreconditionFailed => {
            return S3Error::new(
                "PreconditionFailed",
                "At least one of the preconditions you specified did not hold.",
                StatusCode::PRECONDITION_FAILED,
                &resource,
                &request_id,
            )
            .into_response();
        }
        telecrate::s3::ConditionalOutcome::NotModified => {
            let mut h = HeaderMap::new();
            object_response_headers(&mut h, &version, version.size.max(0) as u64, &request_id);
            return (StatusCode::NOT_MODIFIED, h, Vec::new()).into_response();
        }
        telecrate::s3::ConditionalOutcome::Proceed => {}
    }
    let mut h = HeaderMap::new();
    object_response_headers(&mut h, &version, version.size.max(0) as u64, &request_id);
    (StatusCode::OK, h, Vec::new()).into_response()
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
    let raw_query = uri.query().unwrap_or("");
    if let Err(e) = check_auth_with_policy(
        &state,
        "s3:DeleteObject",
        Some(&bucket),
        Some(&key),
        &AuthInput {
            method: "DELETE",
            path: &raw_path,
            query: raw_query,
            headers: &headers,
            body: b"",
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let qmap = query_map(raw_query);
    if let Some(upload_id) = qmap.get("uploadId") {
        return abort_multipart_upload_handler(
            &state,
            &bucket,
            &key,
            upload_id,
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

    let vid_opt = qmap.get("versionId").cloned();
    if let Err((status, code, msg)) = check_object_lock_for_delete(
        &conn,
        &bucket,
        &key,
        vid_opt.as_deref(),
        &headers,
        now_secs(),
    ) {
        return S3Error::new(code, msg, status, &resource, &request_id).into_response();
    }
    if let Some(ref vid) = vid_opt {
        let deleted = match telecrate::db::delete_object_version(&mut conn, &bucket, &key, vid) {
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
        let mut resp = xml_response(StatusCode::NO_CONTENT, String::new(), &request_id);
        if let Ok(hv) = vid.parse() {
            resp.headers_mut().insert("x-amz-version-id", hv);
        }
        if deleted.is_delete_marker {
            resp.headers_mut()
                .insert("x-amz-delete-marker", "true".parse().unwrap());
        }
        return resp;
    }

    let v_status = telecrate::db::get_bucket_versioning(&conn, &bucket)
        .unwrap_or_else(|_| "Disabled".to_string());
    if v_status == "Enabled" || v_status == "Suspended" {
        let dm_vid = match telecrate::db::create_delete_marker(&mut conn, &bucket, &key) {
            Ok(v) => v,
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
        let mut resp = xml_response(StatusCode::NO_CONTENT, String::new(), &request_id);
        resp.headers_mut()
            .insert("x-amz-delete-marker", "true".parse().unwrap());
        if dm_vid != "null" && !dm_vid.is_empty() {
            if let Ok(hv) = dm_vid.parse() {
                resp.headers_mut().insert("x-amz-version-id", hv);
            }
        }
        return resp;
    }

    let existing = telecrate::db::latest_version(&conn, &bucket, &key)
        .ok()
        .flatten();
    if let Some(ref v) = existing {
        let outcome =
            telecrate::s3::eval_conditional_headers("DELETE", &v.etag, &v.created_at, &headers);
        if outcome != telecrate::s3::ConditionalOutcome::Proceed {
            return S3Error::new(
                "PreconditionFailed",
                "At least one of the preconditions you specified did not hold.",
                StatusCode::PRECONDITION_FAILED,
                &resource,
                &request_id,
            )
            .into_response();
        }
    } else if headers.contains_key("if-match") || headers.contains_key("if-unmodified-since") {
        return S3Error::new(
            "PreconditionFailed",
            "At least one of the preconditions you specified did not hold.",
            StatusCode::PRECONDITION_FAILED,
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

/// POST /:bucket/*key: InitiateMultipartUpload (?uploads) hoặc CompleteMultipartUpload (?uploadId=...).
async fn post_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    use telecrate::s3::S3Error;
    let request_id = telecrate::s3::new_request_id();
    let resource = format!("/{bucket}/{key}");
    let raw_query = uri.query().unwrap_or("");
    if let Err(e) = check_auth_with_policy(
        &state,
        "s3:PutObject",
        Some(&bucket),
        Some(&key),
        &AuthInput {
            method: "POST",
            path: &resource,
            query: raw_query,
            headers: &headers,
            body: &body,
            resource: &resource,
            request_id: &request_id,
        },
    ) {
        return e.into_response();
    }
    let q = query_map(raw_query);
    if q.contains_key("uploads") {
        let content_type = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream");
        let conn = match open_db(&state) {
            Ok(c) => c,
            Err(e) => return e.into_response(),
        };
        let user_meta = extract_user_metadata(&headers);
        let upload_id = uuid::Uuid::new_v4().simple().to_string();
        if let Err(e) = telecrate::db::create_multipart_upload(
            &conn,
            &upload_id,
            &bucket,
            &key,
            content_type,
            user_meta.as_deref(),
        ) {
            let code = if e == "NoSuchBucket" {
                "NoSuchBucket"
            } else {
                "InternalError"
            };
            let status = if e == "NoSuchBucket" {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return S3Error::new(code, e, status, &resource, &request_id).into_response();
        }
        xml_response(
            StatusCode::OK,
            telecrate::s3::initiate_multipart_upload_xml(&bucket, &key, &upload_id),
            &request_id,
        )
    } else if let Some(upload_id) = q.get("uploadId") {
        let text = match std::str::from_utf8(&body) {
            Ok(t) => t,
            Err(_) => {
                return S3Error::new(
                    "MalformedXML",
                    "Invalid UTF-8 XML payload",
                    StatusCode::BAD_REQUEST,
                    &resource,
                    &request_id,
                )
                .into_response()
            }
        };
        let requested_parts = match telecrate::s3::parse_complete_multipart_xml(text) {
            Ok(p) => p,
            Err(code) => {
                return S3Error::new(
                    code,
                    "Failed to parse CompleteMultipartUpload XML",
                    StatusCode::BAD_REQUEST,
                    &resource,
                    &request_id,
                )
                .into_response()
            }
        };
        let mut conn = match open_db(&state) {
            Ok(c) => c,
            Err(e) => return e.into_response(),
        };
        let version_id = uuid::Uuid::new_v4().simple().to_string();
        let job_id = uuid::Uuid::new_v4().simple().to_string();
        let (old_spools, version) = match telecrate::db::complete_multipart_upload_txn(
            &mut conn,
            upload_id,
            &version_id,
            &requested_parts,
            &job_id,
        ) {
            Ok(r) => r,
            Err(e) => {
                let code = if e == "NoSuchUpload" {
                    "NoSuchUpload"
                } else if e == "InvalidPart" {
                    "InvalidPart"
                } else {
                    "InternalError"
                };
                let status = if e == "NoSuchUpload" {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::BAD_REQUEST
                };
                return S3Error::new(code, e, status, &resource, &request_id).into_response();
            }
        };
        for p in old_spools {
            let _ = std::fs::remove_file(p);
        }
        xml_response(
            StatusCode::OK,
            telecrate::s3::complete_multipart_upload_xml(&bucket, &key, &version.etag),
            &request_id,
        )
    } else {
        S3Error::new(
            "InvalidRequest",
            "Unsupported POST operation on object.",
            StatusCode::BAD_REQUEST,
            &resource,
            &request_id,
        )
        .into_response()
    }
}

#[allow(clippy::too_many_arguments)]
async fn upload_part_handler(
    state: &AppState,
    _bucket: &str,
    _key: &str,
    upload_id: &str,
    part_num_str: &str,
    resource: &str,
    request_id: &str,
    body: &[u8],
) -> Response {
    use telecrate::s3::S3Error;
    let part_number: i32 = match part_num_str.parse() {
        Ok(n) if (1..=10000).contains(&n) => n,
        _ => {
            return S3Error::new(
                "InvalidArgument",
                "Part number must be between 1 and 10000",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if matches!(
        telecrate::db::get_multipart_upload(&conn, upload_id),
        Ok(None)
    ) {
        return S3Error::new(
            "NoSuchUpload",
            "The specified upload does not exist.",
            StatusCode::NOT_FOUND,
            resource,
            request_id,
        )
        .into_response();
    }
    let chunk_path = std::path::Path::new(&state.config.spool_dir)
        .join(format!("{upload_id}_p{part_number}.chunk"));
    let spool_str = chunk_path.to_str().unwrap().to_string();
    if let Err(e) = telecrate::spool::write_durable(&chunk_path, body) {
        return S3Error::new(
            "InternalError",
            e.to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }
    let etag_raw = md5_hex(body);
    let etag_quoted = format!("\"{etag_raw}\"");
    let sha256_hex = sha256_hex(body);
    if let Err(e) = telecrate::db::save_multipart_part(
        &conn,
        upload_id,
        part_number,
        body.len() as i64,
        &etag_quoted,
        &sha256_hex,
        &sha256_hex,
        Some(&spool_str),
    ) {
        return S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }
    let mut headers = HeaderMap::new();
    headers.insert("etag", etag_quoted.parse().unwrap());
    headers.insert(
        "x-amz-request-id",
        request_id
            .parse()
            .unwrap_or_else(|_| "invalid-request-id".parse().unwrap()),
    );
    (StatusCode::OK, headers, String::new()).into_response()
}

fn list_parts_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    upload_id: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if matches!(
        telecrate::db::get_multipart_upload(&conn, upload_id),
        Ok(None)
    ) {
        return S3Error::new(
            "NoSuchUpload",
            "The specified upload does not exist.",
            StatusCode::NOT_FOUND,
            resource,
            request_id,
        )
        .into_response();
    }
    let parts = match telecrate::db::list_multipart_parts(&conn, upload_id) {
        Ok(p) => p,
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
    xml_response(
        StatusCode::OK,
        telecrate::s3::list_parts_xml(bucket, key, upload_id, &parts),
        request_id,
    )
}

fn abort_multipart_upload_handler(
    state: &AppState,
    _bucket: &str,
    _key: &str,
    upload_id: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let mut conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let spool_paths = match telecrate::db::abort_multipart_upload(&mut conn, upload_id) {
        Ok(p) => p,
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
    for p in spool_paths {
        let _ = std::fs::remove_file(p);
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-request-id",
        request_id
            .parse()
            .unwrap_or_else(|_| "invalid-request-id".parse().unwrap()),
    );
    (StatusCode::NO_CONTENT, headers, String::new()).into_response()
}

fn list_multipart_uploads_handler(
    state: &AppState,
    bucket: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
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
    let uploads = match telecrate::db::list_multipart_uploads(&conn, bucket) {
        Ok(u) => u,
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
    xml_response(
        StatusCode::OK,
        telecrate::s3::list_multipart_uploads_xml(bucket, &uploads),
        request_id,
    )
}

async fn bucket_options(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_preflight(&state, &bucket, &headers)
}

async fn object_options(
    State(state): State<Arc<AppState>>,
    Path((bucket, _key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    handle_preflight(&state, &bucket, &headers)
}

fn handle_preflight(state: &AppState, bucket: &str, headers: &HeaderMap) -> Response {
    use telecrate::s3::S3Error;
    let request_id = telecrate::s3::new_request_id();
    let resource = format!("/{bucket}");

    let origin = match headers.get("origin").and_then(|v| v.to_str().ok()) {
        Some(o) if !o.is_empty() => o,
        _ => {
            return S3Error::new(
                "InvalidRequest",
                "Missing Origin header",
                StatusCode::BAD_REQUEST,
                &resource,
                &request_id,
            )
            .into_response()
        }
    };
    let method = match headers
        .get("access-control-request-method")
        .and_then(|v| v.to_str().ok())
    {
        Some(m) if !m.is_empty() => m,
        _ => {
            return S3Error::new(
                "InvalidRequest",
                "Missing Access-Control-Request-Method header",
                StatusCode::BAD_REQUEST,
                &resource,
                &request_id,
            )
            .into_response()
        }
    };
    let req_hdrs = headers
        .get("access-control-request-headers")
        .and_then(|v| v.to_str().ok());

    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let cors_xml = match telecrate::db::get_bucket_cors(&conn, bucket) {
        Ok(Some(xml)) => xml,
        _ => {
            return S3Error::new(
                "AccessDenied",
                "CORS not configured on bucket",
                StatusCode::FORBIDDEN,
                &resource,
                &request_id,
            )
            .into_response()
        }
    };

    let cors_cfg = match telecrate::cors::parse_cors_xml(&cors_xml) {
        Ok(cfg) => cfg,
        Err(_) => {
            return S3Error::new(
                "InternalError",
                "Corrupted CORS config",
                StatusCode::INTERNAL_SERVER_ERROR,
                &resource,
                &request_id,
            )
            .into_response()
        }
    };

    let c_match = match telecrate::cors::match_cors_rule(&cors_cfg, origin, method, req_hdrs) {
        Some(m) => m,
        None => {
            return S3Error::new(
                "AccessDenied",
                "CORS rule match failed",
                StatusCode::FORBIDDEN,
                &resource,
                &request_id,
            )
            .into_response()
        }
    };

    let mut res_headers = HeaderMap::new();
    res_headers.insert(
        "access-control-allow-origin",
        c_match.allow_origin.parse().unwrap(),
    );
    res_headers.insert(
        "access-control-allow-methods",
        c_match.allow_methods.parse().unwrap(),
    );
    if !c_match.allow_headers.is_empty() {
        if let Ok(v) = c_match.allow_headers.parse() {
            res_headers.insert("access-control-allow-headers", v);
        }
    }
    if let Some(max_age) = c_match.max_age_seconds {
        res_headers.insert(
            "access-control-max-age",
            max_age.to_string().parse().unwrap(),
        );
    }
    if !c_match.expose_headers.is_empty() {
        if let Ok(v) = c_match.expose_headers.parse() {
            res_headers.insert("access-control-expose-headers", v);
        }
    }
    res_headers.insert("x-amz-request-id", request_id.parse().unwrap());

    (StatusCode::OK, res_headers, "").into_response()
}

fn get_bucket_cors_handler(
    state: &AppState,
    bucket: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match telecrate::db::get_bucket_cors(&conn, bucket) {
        Ok(Some(cors_xml)) => xml_response(StatusCode::OK, cors_xml, request_id),
        Ok(None) => S3Error::new(
            "NoSuchCORSConfiguration",
            "The CORS configuration does not exist.",
            StatusCode::NOT_FOUND,
            resource,
            request_id,
        )
        .into_response(),
        Err(e) => S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response(),
    }
}

fn put_bucket_cors_handler(
    state: &AppState,
    bucket: &str,
    body: &[u8],
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => {
            return S3Error::new(
                "MalformedXML",
                "Invalid UTF-8 body",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    if let Err(e) = telecrate::cors::parse_cors_xml(text) {
        return S3Error::new(
            "MalformedXML",
            e,
            StatusCode::BAD_REQUEST,
            resource,
            request_id,
        )
        .into_response();
    }
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = telecrate::db::set_bucket_cors(&conn, bucket, text) {
        return S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }
    empty_ok_response(request_id)
}

fn delete_bucket_cors_handler(
    state: &AppState,
    bucket: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = telecrate::db::delete_bucket_cors(&conn, bucket) {
        return S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }
    no_content_response(request_id)
}

fn get_bucket_policy_handler(
    state: &AppState,
    bucket: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match telecrate::db::get_bucket_policy(&conn, bucket) {
        Ok(Some(policy_json)) => {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", "application/json".parse().unwrap());
            headers.insert("x-amz-request-id", request_id.parse().unwrap());
            (StatusCode::OK, headers, policy_json).into_response()
        }
        Ok(None) => S3Error::new(
            "NoSuchBucketPolicy",
            "The bucket policy does not exist.",
            StatusCode::NOT_FOUND,
            resource,
            request_id,
        )
        .into_response(),
        Err(e) => S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response(),
    }
}

fn put_bucket_policy_handler(
    state: &AppState,
    bucket: &str,
    body: &[u8],
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => {
            return S3Error::new(
                "MalformedPolicy",
                "Invalid UTF-8 body",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    let doc: telecrate::policy::PolicyDocument = match serde_json::from_str(text) {
        Ok(d) => d,
        Err(e) => {
            return S3Error::new(
                "MalformedPolicy",
                format!("Invalid policy JSON: {e}"),
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    if let Ok(bpa) = telecrate::db::get_bucket_bpa(&conn, bucket) {
        if (bpa.block_public_policy || bpa.restrict_public_buckets) && doc.is_public() {
            return S3Error::new(
                "InvalidPolicy",
                "Bucket and object access to this bucket is restricted by Block Public Access settings.",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response();
        }
    }

    if let Err(e) = telecrate::db::set_bucket_policy(&conn, bucket, text) {
        return S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }
    empty_ok_response(request_id)
}

fn delete_bucket_policy_handler(
    state: &AppState,
    bucket: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = telecrate::db::delete_bucket_policy(&conn, bucket) {
        return S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }
    no_content_response(request_id)
}

fn get_bucket_bpa_handler(
    state: &AppState,
    bucket: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match telecrate::db::get_bucket_bpa(&conn, bucket) {
        Ok(bpa) => match telecrate::policy::serialize_bpa_xml(&bpa) {
            Ok(xml) => xml_response(StatusCode::OK, xml, request_id),
            Err(e) => S3Error::new(
                "InternalError",
                e,
                StatusCode::INTERNAL_SERVER_ERROR,
                resource,
                request_id,
            )
            .into_response(),
        },
        Err(e) if e == "NoSuchBucket" => S3Error::new(
            "NoSuchBucket",
            "The specified bucket does not exist.",
            StatusCode::NOT_FOUND,
            resource,
            request_id,
        )
        .into_response(),
        Err(e) => S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response(),
    }
}

fn put_bucket_bpa_handler(
    state: &AppState,
    bucket: &str,
    body: &[u8],
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => {
            return S3Error::new(
                "MalformedXML",
                "Invalid UTF-8 body",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    let bpa = match telecrate::policy::parse_bpa_xml(text) {
        Ok(b) => b,
        Err(e) => {
            return S3Error::new(
                "MalformedXML",
                e,
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = telecrate::db::set_bucket_bpa(&conn, bucket, &bpa) {
        return S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }
    empty_ok_response(request_id)
}

fn delete_bucket_bpa_handler(
    state: &AppState,
    bucket: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = telecrate::db::delete_bucket_bpa(&conn, bucket) {
        return S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }
    no_content_response(request_id)
}

fn check_object_lock_for_delete(
    conn: &rusqlite::Connection,
    bucket: &str,
    key: &str,
    vid_opt: Option<&str>,
    headers: &HeaderMap,
    now: u64,
) -> Result<(), (StatusCode, &'static str, String)> {
    let version = match vid_opt {
        Some(vid) if vid != "null" && !vid.is_empty() => {
            telecrate::db::get_version_by_id(conn, bucket, key, vid)
                .ok()
                .flatten()
        }
        _ => telecrate::db::latest_version(conn, bucket, key)
            .ok()
            .flatten(),
    };
    let v = match version {
        Some(v) => v,
        None => return Ok(()),
    };
    let version_id = &v.version_id;

    if let Ok(on) = telecrate::db::get_object_legal_hold(conn, bucket, key, version_id) {
        if on {
            return Err((
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "Object is locked under Legal Hold.".to_string(),
            ));
        }
    }

    if let Ok(Some(retention)) = telecrate::db::get_object_retention(conn, bucket, key, version_id)
    {
        if let Some(until_secs) = telecrate::s3::parse_iso_date(&retention.retain_until_date) {
            if until_secs > now {
                if retention.mode == "COMPLIANCE" {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "AccessDenied",
                        format!(
                            "Object is locked under COMPLIANCE retention until {}.",
                            retention.retain_until_date
                        ),
                    ));
                } else if retention.mode == "GOVERNANCE" {
                    let bypass = headers
                        .get("x-amz-bypass-governance-retention")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.trim().eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    if !bypass {
                        return Err((
                            StatusCode::FORBIDDEN,
                            "AccessDenied",
                            format!(
                                "Object is locked under GOVERNANCE retention until {}.",
                                retention.retain_until_date
                            ),
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

fn get_bucket_lock_config_handler(
    state: &AppState,
    bucket: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match telecrate::db::get_bucket_object_lock_config(&conn, bucket) {
        Ok(Some(cfg)) => {
            let mode = cfg
                .default_retention_mode
                .as_deref()
                .unwrap_or("GOVERNANCE");
            let days = cfg.default_retention_days.unwrap_or(30);
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ObjectLockEnabled>{}</ObjectLockEnabled><Rule><DefaultRetention><Mode>{}</Mode><Days>{}</Days></DefaultRetention></Rule></ObjectLockConfiguration>",
                telecrate::s3::xml_escape(&cfg.status),
                telecrate::s3::xml_escape(mode),
                days
            );
            xml_response(StatusCode::OK, xml, request_id)
        }
        Ok(None) => S3Error::new(
            "ObjectLockConfigurationNotFoundError",
            "Object Lock configuration does not exist for this bucket.",
            StatusCode::NOT_FOUND,
            resource,
            request_id,
        )
        .into_response(),
        Err(e) if e == "NoSuchBucket" => S3Error::new(
            "NoSuchBucket",
            "The specified bucket does not exist.",
            StatusCode::NOT_FOUND,
            resource,
            request_id,
        )
        .into_response(),
        Err(e) => S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response(),
    }
}

fn put_bucket_lock_config_handler(
    state: &AppState,
    bucket: &str,
    body: &[u8],
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => {
            return S3Error::new(
                "MalformedXML",
                "Invalid UTF-8 body",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    let mode = if text.contains("<Mode>COMPLIANCE</Mode>") {
        Some("COMPLIANCE".to_string())
    } else if text.contains("<Mode>GOVERNANCE</Mode>") {
        Some("GOVERNANCE".to_string())
    } else {
        None
    };
    let days = if let Some(start) = text.find("<Days>") {
        let sub = &text[start + 6..];
        sub.find("</Days>")
            .and_then(|end| sub[..end].trim().parse::<i32>().ok())
    } else {
        None
    };
    let status = if text.contains("<ObjectLockEnabled>Enabled</ObjectLockEnabled>") {
        "Enabled".to_string()
    } else {
        "Disabled".to_string()
    };

    let cfg = telecrate::db::ObjectLockConfig {
        status,
        default_retention_mode: mode,
        default_retention_days: days,
    };

    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    if let Err(e) = telecrate::db::set_bucket_object_lock_config(&conn, bucket, &cfg) {
        return S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }
    empty_ok_response(request_id)
}

fn get_object_retention_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    vid_param: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let version = if vid_param != "null" && !vid_param.is_empty() {
        telecrate::db::get_version_by_id(&conn, bucket, key, vid_param)
            .ok()
            .flatten()
    } else {
        telecrate::db::latest_version(&conn, bucket, key)
            .ok()
            .flatten()
    };
    let v = match version {
        Some(v) => v,
        None => {
            return S3Error::new(
                "NoSuchKey",
                "The specified key does not exist.",
                StatusCode::NOT_FOUND,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    match telecrate::db::get_object_retention(&conn, bucket, key, &v.version_id) {
        Ok(Some(retention)) => {
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Mode>{}</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>",
                telecrate::s3::xml_escape(&retention.mode),
                telecrate::s3::xml_escape(&retention.retain_until_date)
            );
            xml_response(StatusCode::OK, xml, request_id)
        }
        _ => S3Error::new(
            "NoSuchObjectLockConfiguration",
            "The specified object does not have a ObjectLock configuration.",
            StatusCode::NOT_FOUND,
            resource,
            request_id,
        )
        .into_response(),
    }
}

fn put_object_retention_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    vid_param: &str,
    body: &[u8],
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => {
            return S3Error::new(
                "MalformedXML",
                "Invalid UTF-8 body",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    let mode = if text.contains("<Mode>COMPLIANCE</Mode>")
        || text.contains("<Mode>compliance</Mode>")
    {
        "COMPLIANCE"
    } else if text.contains("<Mode>GOVERNANCE</Mode>") || text.contains("<Mode>governance</Mode>") {
        "GOVERNANCE"
    } else {
        return S3Error::new(
            "MalformedXML",
            "Invalid Mode in Retention XML",
            StatusCode::BAD_REQUEST,
            resource,
            request_id,
        )
        .into_response();
    };

    let start = match text.find("<RetainUntilDate>") {
        Some(pos) => pos + "<RetainUntilDate>".len(),
        None => {
            return S3Error::new(
                "MalformedXML",
                "Missing RetainUntilDate",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    let end = match text[start..].find("</RetainUntilDate>") {
        Some(pos) => start + pos,
        None => {
            return S3Error::new(
                "MalformedXML",
                "Malformed RetainUntilDate tag",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    let until_date = text[start..end].trim();

    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let version = if vid_param != "null" && !vid_param.is_empty() {
        telecrate::db::get_version_by_id(&conn, bucket, key, vid_param)
            .ok()
            .flatten()
    } else {
        telecrate::db::latest_version(&conn, bucket, key)
            .ok()
            .flatten()
    };
    let v = match version {
        Some(v) => v,
        None => {
            return S3Error::new(
                "NoSuchKey",
                "The specified key does not exist.",
                StatusCode::NOT_FOUND,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    if let Err(e) =
        telecrate::db::set_object_retention(&conn, bucket, key, &v.version_id, mode, until_date)
    {
        return S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }
    empty_ok_response(request_id)
}

fn get_object_legal_hold_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    vid_param: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let version = if vid_param != "null" && !vid_param.is_empty() {
        telecrate::db::get_version_by_id(&conn, bucket, key, vid_param)
            .ok()
            .flatten()
    } else {
        telecrate::db::latest_version(&conn, bucket, key)
            .ok()
            .flatten()
    };
    let v = match version {
        Some(v) => v,
        None => {
            return S3Error::new(
                "NoSuchKey",
                "The specified key does not exist.",
                StatusCode::NOT_FOUND,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    let on =
        telecrate::db::get_object_legal_hold(&conn, bucket, key, &v.version_id).unwrap_or(false);
    let status_str = if on { "ON" } else { "OFF" };
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LegalHold xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>{}</Status></LegalHold>",
        status_str
    );
    xml_response(StatusCode::OK, xml, request_id)
}

fn put_object_legal_hold_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    vid_param: &str,
    body: &[u8],
    resource: &str,
    request_id: &str,
) -> Response {
    use telecrate::s3::S3Error;
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => {
            return S3Error::new(
                "MalformedXML",
                "Invalid UTF-8 body",
                StatusCode::BAD_REQUEST,
                resource,
                request_id,
            )
            .into_response()
        }
    };
    let on = if text.contains("<Status>ON</Status>") || text.contains("<Status>on</Status>") {
        true
    } else if text.contains("<Status>OFF</Status>") || text.contains("<Status>off</Status>") {
        false
    } else {
        return S3Error::new(
            "MalformedXML",
            "Invalid Status in LegalHold XML",
            StatusCode::BAD_REQUEST,
            resource,
            request_id,
        )
        .into_response();
    };

    let conn = match open_db(state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let version = if vid_param != "null" && !vid_param.is_empty() {
        telecrate::db::get_version_by_id(&conn, bucket, key, vid_param)
            .ok()
            .flatten()
    } else {
        telecrate::db::latest_version(&conn, bucket, key)
            .ok()
            .flatten()
    };
    let v = match version {
        Some(v) => v,
        None => {
            return S3Error::new(
                "NoSuchKey",
                "The specified key does not exist.",
                StatusCode::NOT_FOUND,
                resource,
                request_id,
            )
            .into_response()
        }
    };

    if let Err(e) = telecrate::db::set_object_legal_hold(&conn, bucket, key, &v.version_id, on) {
        return S3Error::new(
            "InternalError",
            e,
            StatusCode::INTERNAL_SERVER_ERROR,
            resource,
            request_id,
        )
        .into_response();
    }
    empty_ok_response(request_id)
}

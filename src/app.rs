//! HTTP app TeleCrate — dùng chung giữa daemon (`serve`) và integration tests.
//! S3 layer M2.1: buckets + SigV4 (objects → 2.2).

// Giữ nguyên đường dẫn `telecrate::...` khi move code từ binary sang lib.
use crate as telecrate;

use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;

/// Dựng router S3 + health từ config (daemon và test dùng chung).
pub fn router(config: telecrate::config::Config) -> Router {
    let state = Arc::new(AppState { config });
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
                .head(head_bucket),
        )
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "ok": true, "version": telecrate::VERSION, "s3": "buckets-only-2.1" }))
}

#[derive(Clone)]
struct AppState {
    config: telecrate::config::Config,
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
        // ListObjects (v1/v2) thuộc 2.2 — 501 trung thực, không mock 200.
        telecrate::s3::S3Error::new(
            "NotImplemented",
            "ListObjects is planned in milestone 2.2.",
            StatusCode::NOT_IMPLEMENTED,
            &resource,
            &request_id,
        )
        .into_response()
    }
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

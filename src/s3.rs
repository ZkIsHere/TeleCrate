//! S3 HTTP semantics M2.1: error XML chuẩn, request id, LocationConstraint parse.
//!
//! Mọi lỗi S3 trả XML `Error` + header `x-amz-request-id`. Không mock 200 cho op chưa làm:
//! op chưa tới milestone trả 501 `NotImplemented`.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

/// Lỗi S3: mã chuẩn + message + HTTP status đúng spec.
pub struct S3Error {
    pub code: &'static str,
    pub message: String,
    pub status: StatusCode,
    pub resource: String,
    pub request_id: String,
}

impl S3Error {
    pub fn new(
        code: &'static str,
        message: impl Into<String>,
        status: StatusCode,
        resource: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            status,
            resource: resource.into(),
            request_id: request_id.into(),
        }
    }

    pub fn access_denied(resource: &str, request_id: &str) -> Self {
        Self::new(
            "AccessDenied",
            "Anonymous access is disabled; valid SigV4 Authorization required.",
            StatusCode::FORBIDDEN,
            resource,
            request_id,
        )
    }
}

pub fn new_request_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn xml_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            _ => o.push(c),
        }
    }
    o
}

pub fn error_xml(code: &str, message: &str, resource: &str, request_id: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource><RequestId>{}</RequestId></Error>",
        xml_escape(code),
        xml_escape(message),
        xml_escape(resource),
        xml_escape(request_id)
    )
}

impl IntoResponse for S3Error {
    fn into_response(self) -> Response {
        let body = error_xml(self.code, &self.message, &self.resource, &self.request_id);
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/xml".parse().unwrap());
        headers.insert(
            "x-amz-request-id",
            self.request_id
                .parse()
                .unwrap_or_else(|_| "invalid-request-id".parse().unwrap()),
        );
        (self.status, headers, body).into_response()
    }
}

/// Map lỗi SigV4 → S3 error đúng spec.
pub fn sig_error_to_s3(e: crate::sigv4::SigError, resource: &str, request_id: &str) -> S3Error {
    use crate::sigv4::SigError::*;
    match e {
        MissingAuth => S3Error::access_denied(resource, request_id),
        UnknownKey => S3Error::new(
            "InvalidAccessKeyId",
            "The AWS Access Key Id you provided does not exist in our records.",
            StatusCode::FORBIDDEN,
            resource,
            request_id,
        ),
        BadSignature => S3Error::new(
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided.",
            StatusCode::FORBIDDEN,
            resource,
            request_id,
        ),
        Expired => S3Error::new(
            "RequestTimeTooSkewed",
            "The difference between the request time and the server time is too large.",
            StatusCode::FORBIDDEN,
            resource,
            request_id,
        ),
        BadScope | MalformedAuth => S3Error::new(
            "AuthorizationHeaderMalformed",
            "The authorization header is malformed.",
            StatusCode::BAD_REQUEST,
            resource,
            request_id,
        ),
    }
}

/// Parse `CreateBucketConfiguration` — body rỗng → None (dùng region mặc định).
/// Trả `Some(location)` hoặc lỗi `InvalidLocationConstraint`.
pub fn parse_location_constraint(body: &[u8]) -> Result<Option<String>, &'static str> {
    if body.is_empty() {
        return Ok(None);
    }
    use quick_xml::de::from_str;
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(rename = "CreateBucketConfiguration")]
    struct Cfg {
        #[serde(rename = "LocationConstraint", default)]
        location: Option<String>,
    }
    let text = std::str::from_utf8(body).map_err(|_| "InvalidLocationConstraint")?;
    let cfg: Cfg = from_str(text).map_err(|_| "InvalidLocationConstraint")?;
    Ok(cfg.location)
}

pub fn list_buckets_xml(buckets: &[crate::db::Bucket], owner: &str) -> String {
    let mut o = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>",
    );
    o.push_str(&xml_escape(owner));
    o.push_str("</ID></Owner><Buckets>");
    for b in buckets {
        o.push_str("<Bucket><Name>");
        o.push_str(&xml_escape(&b.name));
        o.push_str("</Name><CreationDate>");
        o.push_str(&xml_escape(&b.created_at));
        o.push_str("</CreationDate></Bucket>");
    }
    o.push_str("</Buckets></ListAllMyBucketsResult>");
    o
}

pub fn location_xml(region: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{}</LocationConstraint>",
        xml_escape(region)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_xml_escapes_and_carries_request_id() {
        let e = S3Error::new(
            "NoSuchBucket",
            "a<b>&\"q\"",
            StatusCode::NOT_FOUND,
            "/b",
            "req123",
        );
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(resp.headers()["x-amz-request-id"], "req123");
    }

    #[test]
    fn location_constraint_parse() {
        assert_eq!(parse_location_constraint(b"").unwrap(), None);
        let body = br#"<?xml version="1.0" encoding="UTF-8"?><CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>telecrate-1</LocationConstraint></CreateBucketConfiguration>"#;
        assert_eq!(
            parse_location_constraint(body).unwrap(),
            Some("telecrate-1".to_string())
        );
        assert!(parse_location_constraint(b"<oops>").is_err());
    }

    #[test]
    fn list_buckets_xml_shape() {
        let xml = list_buckets_xml(
            &[crate::db::Bucket {
                name: "b&1".to_string(),
                region: "r".to_string(),
                created_at: "2026-09-15T00:00:00".to_string(),
            }],
            "owner",
        );
        assert!(xml.contains("<Name>b&amp;1</Name>"));
        assert!(xml.contains("ListAllMyBucketsResult"));
    }
}

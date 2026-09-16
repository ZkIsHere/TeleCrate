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

/// Item cho ListBucketResult.
pub struct ListItem {
    pub key: String,
    pub last_modified_iso: String,
    pub etag: String,
    pub size: i64,
}

/// XML ListBucketResult (v2). `url_encode_keys` khi client gửi encoding-type=url.
#[allow(clippy::too_many_arguments)]
pub fn list_objects_xml(
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    max_keys: i64,
    key_count: usize,
    truncated: bool,
    next_token: Option<&str>,
    contents: &[ListItem],
    prefixes: &[String],
    url_encode_keys: bool,
) -> String {
    let enc = |s: &str| {
        if url_encode_keys {
            xml_escape(&url_encode(s))
        } else {
            xml_escape(s)
        }
    };
    let mut o = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>",
    );
    o.push_str(&xml_escape(bucket));
    o.push_str("</Name><Prefix>");
    o.push_str(&enc(prefix));
    o.push_str("</Prefix>");
    if let Some(d) = delimiter {
        o.push_str("<Delimiter>");
        o.push_str(&enc(d));
        o.push_str("</Delimiter>");
    }
    if url_encode_keys {
        o.push_str("<EncodingType>url</EncodingType>");
    }
    o.push_str(&format!(
        "<KeyCount>{key_count}</KeyCount><MaxKeys>{max_keys}</MaxKeys><IsTruncated>{}</IsTruncated>",
        if truncated { "true" } else { "false" }
    ));
    for c in contents {
        o.push_str("<Contents><Key>");
        o.push_str(&enc(&c.key));
        o.push_str("</Key><LastModified>");
        o.push_str(&xml_escape(&c.last_modified_iso));
        o.push_str("</LastModified><ETag>\"");
        o.push_str(&xml_escape(&c.etag));
        o.push_str("\"</ETag><Size>");
        o.push_str(&c.size.to_string());
        o.push_str("</Size><StorageClass>STANDARD</StorageClass></Contents>");
    }
    for p in prefixes {
        o.push_str("<CommonPrefixes><Prefix>");
        o.push_str(&enc(p));
        o.push_str("</Prefix></CommonPrefixes>");
    }
    if let Some(t) = next_token {
        o.push_str("<NextContinuationToken>");
        o.push_str(&enc(t));
        o.push_str("</NextContinuationToken>");
    }
    o.push_str("</ListBucketResult>");
    o
}

/// XML DeleteResult cho DeleteObjects (quiet → chỉ Errors, ở đây luôn trả Deleted trừ khi quiet).
pub fn delete_result_xml(deleted: &[String], quiet: bool) -> String {
    let mut o = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    if !quiet {
        for k in deleted {
            o.push_str("<Deleted><Key>");
            o.push_str(&xml_escape(k));
            o.push_str("</Key></Deleted>");
        }
    }
    o.push_str("</DeleteResult>");
    o
}

/// Percent-decode query/path params (dấu `+` trong query nghĩa là space).
pub fn percent_decode(s: &str, plus_as_space: bool) -> String {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        if plus_as_space && b[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(b[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-encode cho `encoding-type=url`: encode mọi byte ngoài unreserved
/// (kể cả `/`); client chuẩn decode lại đúng key gốc.
pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// SQLite `datetime('now')` (`YYYY-MM-DD HH:MM:SS`, UTC) → HTTP-date (RFC 1123 GMT).
pub fn sqlite_to_http_date(s: &str) -> Option<String> {
    let (d, t) = s.split_once(' ')?;
    let mut di = d.split('-');
    let (y, mo, day): (i64, i64, i64) = (
        di.next()?.parse().ok()?,
        di.next()?.parse().ok()?,
        di.next()?.parse().ok()?,
    );
    let mut ti = t.split(':');
    let (h, mi, se): (u64, u64, u64) = (
        ti.next()?.parse().ok()?,
        ti.next()?.parse().ok()?,
        ti.next()?.parse().ok()?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&day) || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    // days_from_civil; 1970-01-01 là Thursday (index 4 khi Sunday=0).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (mo + 9).rem_euclid(12);
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let wday = ((days + 4).rem_euclid(7)) as usize;
    Some(format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS[wday],
        day,
        MONTHS[(mo - 1) as usize],
        if mo <= 2 { y + 1 } else { y },
        h,
        mi,
        se
    ))
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

    #[test]
    fn sqlite_date_to_http_date() {
        // 2026-09-16 là Thứ Tư (ngày 259 của năm, 01-01 là Thứ Năm).
        assert_eq!(
            sqlite_to_http_date("2026-09-16 05:50:00").as_deref(),
            Some("Wed, 16 Sep 2026 05:50:00 GMT")
        );
        assert_eq!(
            sqlite_to_http_date("1970-01-01 00:00:00").as_deref(),
            Some("Thu, 01 Jan 1970 00:00:00 GMT")
        );
        assert!(sqlite_to_http_date("not-a-date").is_none());
    }
}

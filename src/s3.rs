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

pub fn xml_escape(s: &str) -> String {
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

pub fn sqlite_date_to_epoch(s: &str) -> Option<u64> {
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
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let mp = ((mo + 9).rem_euclid(12)) as u64;
    let doy = (153 * mp + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146097 + doe as i64 - 719468) as u64;
    Some(days * 86400 + h * 3600 + mi * 60 + se)
}

pub fn http_date_to_epoch(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let (day_str, month_str, year_str, time_str) = if parts.len() >= 5 {
        (parts[1], parts[2], parts[3], parts[4])
    } else {
        (parts[0], parts[1], parts[2], parts[3])
    };
    let day: u64 = day_str.parse().ok()?;
    let year: i64 = year_str.parse().ok()?;
    let month: i64 = match month_str.to_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let mut ti = time_str.split(':');
    let (h, mi, se): (u64, u64, u64) = (
        ti.next()?.parse().ok()?,
        ti.next()?.parse().ok()?,
        ti.next()?.parse().ok()?,
    );
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let mp = ((month + 9).rem_euclid(12)) as u64;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146097 + doe as i64 - 719468) as u64;
    Some(days * 86400 + h * 3600 + mi * 60 + se)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionalOutcome {
    Proceed,
    NotModified,
    PreconditionFailed,
}

fn etag_matches(req_etag_spec: &str, target_etag: &str) -> bool {
    let target_norm = target_etag.trim_matches('"').trim().to_lowercase();
    for item in req_etag_spec.split(',') {
        let trimmed = item.trim();
        if trimmed == "*" {
            return true;
        }
        let norm = trimmed.trim_matches('"').trim().to_lowercase();
        if norm == target_norm {
            return true;
        }
    }
    false
}

pub fn eval_conditional_headers(
    method: &str,
    target_etag: &str,
    target_created_at_sqlite: &str,
    headers: &HeaderMap,
) -> ConditionalOutcome {
    let is_get_or_head = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD");

    if let Some(if_match) = headers.get("if-match").and_then(|v| v.to_str().ok()) {
        if !etag_matches(if_match, target_etag) {
            return ConditionalOutcome::PreconditionFailed;
        }
    } else if let Some(if_unmod) = headers
        .get("if-unmodified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let (Some(req_t), Some(target_t)) = (
            http_date_to_epoch(if_unmod),
            sqlite_date_to_epoch(target_created_at_sqlite),
        ) {
            if target_t > req_t {
                return ConditionalOutcome::PreconditionFailed;
            }
        }
    }

    if let Some(if_none_match) = headers.get("if-none-match").and_then(|v| v.to_str().ok()) {
        if etag_matches(if_none_match, target_etag) {
            if is_get_or_head {
                return ConditionalOutcome::NotModified;
            } else {
                return ConditionalOutcome::PreconditionFailed;
            }
        }
    } else if is_get_or_head {
        if let Some(if_mod) = headers
            .get("if-modified-since")
            .and_then(|v| v.to_str().ok())
        {
            if let (Some(req_t), Some(target_t)) = (
                http_date_to_epoch(if_mod),
                sqlite_date_to_epoch(target_created_at_sqlite),
            ) {
                if target_t <= req_t {
                    return ConditionalOutcome::NotModified;
                }
            }
        }
    }

    ConditionalOutcome::Proceed
}

pub fn eval_if_range(
    target_etag: &str,
    target_created_at_sqlite: &str,
    headers: &HeaderMap,
) -> bool {
    let if_range = match headers.get("if-range").and_then(|v| v.to_str().ok()) {
        Some(v) => v.trim(),
        None => return true,
    };
    if if_range.starts_with('"') || if_range.starts_with("W/\"") {
        etag_matches(if_range, target_etag)
    } else if let Some(req_t) = http_date_to_epoch(if_range) {
        if let Some(target_t) = sqlite_date_to_epoch(target_created_at_sqlite) {
            target_t <= req_t
        } else {
            false
        }
    } else {
        etag_matches(if_range, target_etag)
    }
}

pub fn eval_copy_source_conditional_headers(
    target_etag: &str,
    target_created_at_sqlite: &str,
    headers: &HeaderMap,
) -> ConditionalOutcome {
    let mut mapped = HeaderMap::new();
    if let Some(v) = headers.get("x-amz-copy-source-if-match") {
        mapped.insert("if-match", v.clone());
    }
    if let Some(v) = headers.get("x-amz-copy-source-if-none-match") {
        mapped.insert("if-none-match", v.clone());
    }
    if let Some(v) = headers.get("x-amz-copy-source-if-modified-since") {
        mapped.insert("if-modified-since", v.clone());
    }
    if let Some(v) = headers.get("x-amz-copy-source-if-unmodified-since") {
        mapped.insert("if-unmodified-since", v.clone());
    }
    eval_conditional_headers("GET", target_etag, target_created_at_sqlite, &mapped)
}

pub fn initiate_multipart_upload_xml(bucket: &str, key: &str, upload_id: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>",
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(upload_id)
    )
}

pub fn list_parts_xml(
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[crate::db::MultipartPart],
) -> String {
    let mut parts_xml = String::new();
    for p in parts {
        let etag_quoted = if p.etag.starts_with('"') {
            xml_escape(&p.etag)
        } else {
            xml_escape(&format!("\"{}\"", p.etag))
        };
        let last_mod = p.created_at.replace(' ', "T") + ".000Z";
        parts_xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size></Part>",
            p.part_number, last_mod, etag_quoted, p.size
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><StorageClass>STANDARD</StorageClass><PartNumberMarker>0</PartNumberMarker><NextPartNumberMarker>0</NextPartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated>{}</ListPartsResult>",
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(upload_id),
        parts_xml
    )
}

pub fn complete_multipart_upload_xml(bucket: &str, key: &str, etag: &str) -> String {
    let etag_quoted = if etag.starts_with('"') {
        xml_escape(etag)
    } else {
        xml_escape(&format!("\"{etag}\""))
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Location>/{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></CompleteMultipartUploadResult>",
        xml_escape(&format!("{bucket}/{key}")),
        xml_escape(bucket),
        xml_escape(key),
        etag_quoted
    )
}

pub fn list_multipart_uploads_xml(bucket: &str, uploads: &[crate::db::MultipartUpload]) -> String {
    let mut uploads_xml = String::new();
    for u in uploads {
        let init_iso = u.created_at.replace(' ', "T") + ".000Z";
        uploads_xml.push_str(&format!(
            "<Upload><Key>{}</Key><UploadId>{}</UploadId><Initiated>{}</Initiated></Upload>",
            xml_escape(&u.key),
            xml_escape(&u.upload_id),
            init_iso
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><IsTruncated>false</IsTruncated>{}</ListMultipartUploadsResult>",
        xml_escape(bucket),
        uploads_xml
    )
}

pub fn copy_object_xml(etag: &str, last_modified_iso: &str) -> String {
    let etag_quoted = if etag.starts_with('"') {
        xml_escape(etag)
    } else {
        xml_escape(&format!("\"{etag}\""))
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CopyObjectResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LastModified>{}</LastModified><ETag>{}</ETag></CopyObjectResult>",
        xml_escape(last_modified_iso),
        etag_quoted
    )
}

/// Parse Body CompleteMultipartUpload -> Vec<(part_number, etag)>.
pub fn parse_complete_multipart_xml(text: &str) -> Result<Vec<(i32, String)>, &'static str> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);

    let mut parts = Vec::new();
    let mut current_tag = String::new();
    let mut in_part = false;
    let mut current_part_num: Option<i32> = None;
    let mut current_etag: Option<String> = None;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let qname = e.name();
                let name = std::str::from_utf8(qname.as_ref()).map_err(|_| "MalformedXML")?;
                if name.eq_ignore_ascii_case("Part") {
                    in_part = true;
                    current_part_num = None;
                    current_etag = None;
                }
                current_tag = name.to_string();
            }
            Ok(Event::Text(e)) => {
                if in_part {
                    let val = e.unescape().map_err(|_| "MalformedXML")?.into_owned();
                    if current_tag.eq_ignore_ascii_case("PartNumber") {
                        current_part_num = val.parse().ok();
                    } else if current_tag.eq_ignore_ascii_case("ETag") {
                        current_etag = Some(val.trim_matches('"').trim().to_string());
                    }
                }
            }
            Ok(Event::End(e)) => {
                let qname = e.name();
                let name = std::str::from_utf8(qname.as_ref()).map_err(|_| "MalformedXML")?;
                if name.eq_ignore_ascii_case("Part") {
                    in_part = false;
                    if let (Some(p), Some(etag)) = (current_part_num, current_etag.take()) {
                        parts.push((p, etag));
                    }
                }
                current_tag.clear();
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err("MalformedXML"),
            _ => {}
        }
        buf.clear();
    }

    Ok(parts)
}

pub fn versioning_configuration_xml(status: &str) -> String {
    if status == "Enabled" || status == "Suspended" {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>{}</Status></VersioningConfiguration>",
            xml_escape(status)
        )
    } else {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>".to_string()
    }
}

pub fn parse_versioning_configuration_xml(xml_body: &str) -> Result<String, &'static str> {
    if xml_body.contains("<Status>Enabled</Status>")
        || xml_body.contains("<Status>enabled</Status>")
    {
        Ok("Enabled".to_string())
    } else if xml_body.contains("<Status>Suspended</Status>")
        || xml_body.contains("<Status>suspended</Status>")
    {
        Ok("Suspended".to_string())
    } else {
        Err("MalformedXML")
    }
}

pub fn list_object_versions_xml(
    bucket: &str,
    prefix: &str,
    key_marker: &str,
    version_id_marker: &str,
    versions: &[crate::db::VersionListItem],
) -> String {
    let mut items_xml = String::new();
    for v in versions {
        let last_mod = v.created_at.replace(' ', "T") + ".000Z";
        let is_latest_str = if v.is_latest { "true" } else { "false" };
        if v.is_delete_marker {
            items_xml.push_str(&format!(
                "<DeleteMarker><Key>{}</Key><VersionId>{}</VersionId><IsLatest>{}</IsLatest><LastModified>{}</LastModified><Owner><ID>telecrate</ID><DisplayName>telecrate</DisplayName></Owner></DeleteMarker>",
                xml_escape(&v.key),
                xml_escape(&v.version_id),
                is_latest_str,
                last_mod,
            ));
        } else {
            let etag_quoted = if v.etag.starts_with('"') {
                xml_escape(&v.etag)
            } else {
                xml_escape(&format!("\"{}\"", v.etag))
            };
            items_xml.push_str(&format!(
                "<Version><Key>{}</Key><VersionId>{}</VersionId><IsLatest>{}</IsLatest><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size><Owner><ID>telecrate</ID><DisplayName>telecrate</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Version>",
                xml_escape(&v.key),
                xml_escape(&v.version_id),
                is_latest_str,
                last_mod,
                etag_quoted,
                v.size,
            ));
        }
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{}</Name><Prefix>{}</Prefix><KeyMarker>{}</KeyMarker><VersionIdMarker>{}</VersionIdMarker><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>{}</ListVersionsResult>",
        xml_escape(bucket),
        xml_escape(prefix),
        xml_escape(key_marker),
        xml_escape(version_id_marker),
        items_xml,
    )
}

pub fn parse_iso_date(s: &str) -> Option<u64> {
    let clean = s.replace(['-', ':'], "").replace(".000", "");
    if clean.len() >= 15 && clean.as_bytes()[8] == b'T' {
        let num = |a: usize, b: usize| clean[a..b].parse::<u64>().ok();
        let (y, mo, d) = (num(0, 4)?, num(4, 6)?, num(6, 8)?);
        let (h, mi, se) = (num(9, 11)?, num(11, 13)?, num(13, 15)?);
        if (1..=12).contains(&mo) && (1..=31).contains(&d) && h <= 23 && mi <= 59 && se <= 59 {
            let y = if mo <= 2 { y - 1 } else { y } as i64;
            let era = y.div_euclid(400);
            let yoe = y.rem_euclid(400) as u64;
            let mp = ((mo as i64 + 9).rem_euclid(12)) as u64;
            let doy = (153 * mp + 2) / 5 + d - 1;
            let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            let days = era as u64 * 146097 + doe - 719468;
            return Some(days * 86400 + h * 3600 + mi * 60 + se);
        }
    }
    None
}

pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.trim();
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut map = [255u8; 256];
    for (i, &b) in table.iter().enumerate() {
        map[b as usize] = i as u8;
    }
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' || bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let b1 = map[bytes[i] as usize];
        if b1 == 255 {
            return None;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b'=' {
            break;
        }
        let b2 = map[bytes[i] as usize];
        if b2 == 255 {
            return None;
        }
        i += 1;
        out.push((b1 << 2) | (b2 >> 4));

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b'=' {
            break;
        }
        let b3 = map[bytes[i] as usize];
        if b3 == 255 {
            return None;
        }
        i += 1;
        out.push(((b2 & 0x0F) << 4) | (b3 >> 2));

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b'=' {
            break;
        }
        let b4 = map[bytes[i] as usize];
        if b4 == 255 {
            return None;
        }
        i += 1;
        out.push(((b3 & 0x03) << 6) | b4);
    }
    Some(out)
}

pub fn base64_encode(input: &[u8]) -> String {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(table[((triple >> 18) & 0x3F) as usize] as char);
        out.push(table[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(table[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(table[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn parse_and_validate_post_policy(
    policy_b64: &str,
    bucket: &str,
    key: &str,
    body_len: u64,
    now_secs: u64,
) -> Result<(), &'static str> {
    let bytes = base64_decode(policy_b64).ok_or("MalformedPolicy")?;
    let val: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| "MalformedPolicy")?;

    if let Some(exp_str) = val.get("expiration").and_then(|v| v.as_str()) {
        if let Some(exp_secs) = parse_iso_date(exp_str) {
            if now_secs > exp_secs {
                return Err("PolicyExpired");
            }
        }
    }

    if let Some(conditions) = val.get("conditions").and_then(|v| v.as_array()) {
        for cond in conditions {
            if let Some(obj) = cond.as_object() {
                if let Some(b) = obj.get("bucket").and_then(|v| v.as_str()) {
                    if b != bucket {
                        return Err("PolicyConditionFailed");
                    }
                }
                if let Some(k) = obj.get("key").and_then(|v| v.as_str()) {
                    if k != key {
                        return Err("PolicyConditionFailed");
                    }
                }
            } else if let Some(arr) = cond.as_array() {
                if arr.len() >= 3 {
                    let op = arr[0].as_str().unwrap_or("");
                    let var = arr[1].as_str().unwrap_or("");
                    if op == "content-length-range" {
                        let min_len = arr[1].as_u64().unwrap_or(0);
                        let max_len = arr[2].as_u64().unwrap_or(u64::MAX);
                        if body_len < min_len || body_len > max_len {
                            return Err("EntityTooLarge");
                        }
                    } else if op == "eq" {
                        let val_str = arr[2].as_str().unwrap_or("");
                        if (var == "$bucket" && val_str != bucket)
                            || (var == "$key" && val_str != key)
                        {
                            return Err("PolicyConditionFailed");
                        }
                    } else if op == "starts-with" {
                        let val_str = arr[2].as_str().unwrap_or("");
                        if (var == "$key" && !key.starts_with(val_str))
                            || (var == "$bucket" && !bucket.starts_with(val_str))
                        {
                            return Err("PolicyConditionFailed");
                        }
                    }
                }
            }
        }
    }

    Ok(())
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
                versioning_status: "Disabled".to_string(),
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

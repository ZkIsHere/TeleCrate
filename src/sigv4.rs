//! SigV4 header-auth verify (M2.1) — đúng AWS spec cho `service = s3`.
//!
//! Phạm vi: `Authorization: AWS4-HMAC-SHA256 ...` (presigned query → M4).
//! Quyết định (xem ADR 0003): chấp nhận literal `UNSIGNED-PAYLOAD` khi client gửi
//! (theo đúng API), region cố định từ config, clock skew ±15 phút.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Sai số đồng hồ cho phép (giây) — S3 dùng 15 phút.
pub const MAX_SKEW_SECS: u64 = 15 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub access_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigError {
    MissingAuth,
    MalformedAuth,
    UnknownKey,
    BadScope,
    Expired,
    BadSignature,
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Không bao giờ chứa secret — chỉ mã lỗi.
        write!(f, "{self:?}")
    }
}

/// Request tối thiểu cần để verify (trích từ HTTP request thật ở tầng routes).
pub struct SignableRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    /// Query raw (phần sau `?`, chưa decode).
    pub query: &'a str,
    /// Headers (name, value) — name giữ nguyên case, sẽ lowercase khi canonicalize.
    pub headers: &'a [(String, String)],
    /// Authorization header value.
    pub authorization: &'a str,
    /// Body bytes (để hash khi không phải UNSIGNED-PAYLOAD).
    pub body: &'a [u8],
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// Percent-encode theo SigV4 (RFC3986, UTF-8 từng byte). `keep_slash` cho URI path.
fn encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        if is_unreserved(*b) || (keep_slash && *b == b'/') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Parse query raw thành cặp (name, value) chưa decode, sort theo encoded name/value.
fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (
                encode(&percent_decode(k), false),
                encode(&percent_decode(v), false),
            ),
            None => (encode(&percent_decode(p), false), String::new()),
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Tìm header không phân biệt hoa thường.
fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Canonical headers + signed headers list từ danh sách signed names.
fn canonical_headers(
    headers: &[(String, String)],
    signed: &[&str],
) -> Result<(String, String), SigError> {
    let mut names: Vec<&str> = signed.to_vec();
    names.sort_unstable();
    let mut canon = String::new();
    let mut list = Vec::new();
    for n in names {
        let v = find_header(headers, n).ok_or(SigError::MalformedAuth)?;
        let norm: String = v.split_whitespace().collect::<Vec<_>>().join(" ");
        canon.push_str(&format!("{}:{}\n", n.to_ascii_lowercase(), norm));
        list.push(n.to_ascii_lowercase());
    }
    Ok((canon, list.join(";")))
}

pub struct AuthParams<'a> {
    pub access_key_id: &'a str,
    pub date: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    pub signed_headers: Vec<&'a str>,
    pub signature: &'a str,
}

/// Parse `AWS4-HMAC-SHA256 Credential=.../date/region/service/aws4_request, SignedHeaders=..., Signature=...`.
fn parse_auth(auth: &str) -> Result<AuthParams<'_>, SigError> {
    let rest = auth
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or(SigError::MissingAuth)?;
    let mut cred = None;
    let mut signed = None;
    let mut sig = None;
    // Tách theo `,` + trim: chấp nhận cả `, ` (AWS docs) lẫn `,` (PBS S3 client).
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("Credential=") {
            cred = Some(v);
        } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
            signed = Some(v);
        } else if let Some(v) = part.strip_prefix("Signature=") {
            sig = Some(v);
        }
    }
    let (cred, signed, sig) = (cred, signed, sig);
    let (Some(cred), Some(signed), Some(sig)) = (cred, signed, sig) else {
        return Err(SigError::MalformedAuth);
    };
    let c: Vec<&str> = cred.split('/').collect();
    if c.len() != 5 || c[4] != "aws4_request" {
        return Err(SigError::MalformedAuth);
    }
    Ok(AuthParams {
        access_key_id: c[0],
        date: c[1],
        region: c[2],
        service: c[3],
        signed_headers: signed.split(';').collect(),
        signature: sig,
    })
}

/// Lấy access key id từ Authorization header (để tra secret trước khi verify).
pub fn extract_key_id(authorization: &str) -> Result<String, SigError> {
    Ok(parse_auth(authorization)?.access_key_id.to_string())
}

/// Dựng canonical request. Trả về (canonical, amzdate, payload_hash_used).
pub fn canonical_request(
    req: &SignableRequest<'_>,
    signed: &[&str],
) -> Result<(String, String, String), SigError> {
    let amzdate = find_header(req.headers, "x-amz-date")
        .map(|s| s.to_string())
        .or_else(|| {
            for part in req.query.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    if k.eq_ignore_ascii_case("X-Amz-Date") {
                        return Some(percent_decode(v));
                    }
                }
            }
            None
        })
        .ok_or(SigError::MalformedAuth)?;
    let payload_hash = match find_header(req.headers, "x-amz-content-sha256") {
        Some("UNSIGNED-PAYLOAD") => "UNSIGNED-PAYLOAD".to_string(),
        Some(h) if h.len() == 64 => {
            // Client khai báo hash — tin theo spec (không recompute để khỏi ép buffer vô hạn ở M2).
            h.to_string()
        }
        _ => sha256_hex(req.body),
    };
    let (canon_headers, signed_list) = canonical_headers(req.headers, signed)?;
    // Path dùng NGUYÊN BẢN như trên request line (đã percent-encoded bởi client).
    // Tự encode lại sẽ double-encode (%20 -> %2520) và lệch chữ ký với key có ký tự đặc biệt.
    let c = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method,
        req.path,
        canonical_query(req.query),
        canon_headers,
        signed_list,
        payload_hash
    );
    Ok((c, amzdate.to_string(), payload_hash))
}

pub fn string_to_sign(canonical: &str, amzdate: &str, scope: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    )
}

pub fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Parse `YYYYMMDDTHHMMSSZ` → epoch seconds (thuần std, không thêm dep chrono).
fn parse_amzdate(s: &str) -> Option<u64> {
    if s.len() != 16 || !s.ends_with('Z') || s.as_bytes()[8] != b'T' {
        return None;
    }
    let num = |a: usize, b: usize| s[a..b].parse::<u64>().ok();
    let (y, mo, d) = (num(0, 4)?, num(4, 6)?, num(6, 8)?);
    let (h, mi, se) = (num(9, 11)?, num(11, 13)?, num(13, 15)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    // days_from_civil (Howard Hinnant).
    let y = if mo <= 2 { y - 1 } else { y } as i64;
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let mp = ((mo as i64 + 9).rem_euclid(12)) as u64;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era as u64 * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + se)
}

/// Verify request với secret tra từ config. `now_secs` truyền vào để test được.
/// Auto-region: chấp nhận mọi region trong credential scope (single instance, path-style).
pub fn verify(
    req: &SignableRequest<'_>,
    secret: &str,
    now_secs: u64,
) -> Result<Verified, SigError> {
    let p = parse_auth(req.authorization)?;
    if p.service != "s3" || p.region.is_empty() {
        return Err(SigError::BadScope);
    }
    if p.date.len() != 8 || p.date.parse::<u32>().is_err() {
        return Err(SigError::MalformedAuth);
    }
    let (canon, amzdate, _) = canonical_request(req, &p.signed_headers)?;
    if !amzdate.starts_with(p.date) {
        return Err(SigError::MalformedAuth);
    }
    let t = parse_amzdate(&amzdate).ok_or(SigError::MalformedAuth)?;
    if t.abs_diff(now_secs) > MAX_SKEW_SECS {
        return Err(SigError::Expired);
    }
    let scope = format!("{}/{}/s3/aws4_request", p.date, p.region);
    let sts = string_to_sign(&canon, &amzdate, &scope);
    let key = derive_signing_key(secret, p.date, p.region, "s3");
    let expect = hex::encode(hmac_sha256(&key, sts.as_bytes()));
    // So sánh hằng thời gian thủ công (tránh thêm dep subtle ở M2).
    if expect.len() != p.signature.len()
        || expect
            .bytes()
            .zip(p.signature.bytes())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            != 0
    {
        return Err(SigError::BadSignature);
    }
    Ok(Verified {
        access_key_id: p.access_key_id.to_string(),
    })
}

pub fn extract_key_id_from_query(query: &str) -> Result<String, SigError> {
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k.eq_ignore_ascii_case("X-Amz-Credential") {
                let decoded = percent_decode(v);
                let c: Vec<&str> = decoded.split('/').collect();
                if !c.is_empty() && !c[0].is_empty() {
                    return Ok(c[0].to_string());
                }
            }
        }
    }
    Err(SigError::MissingAuth)
}

fn canonical_query_presigned(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = match p.split_once('=') {
                Some((k, v)) => (k, v),
                None => (p, ""),
            };
            if k.eq_ignore_ascii_case("X-Amz-Signature") {
                None
            } else {
                Some((
                    encode(&percent_decode(k), false),
                    encode(&percent_decode(v), false),
                ))
            }
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn verify_presigned(
    req: &SignableRequest<'_>,
    secret: &str,
    now_secs: u64,
) -> Result<Verified, SigError> {
    let mut algo = None;
    let mut cred = None;
    let mut date = None;
    let mut expires = None;
    let mut signed = None;
    let mut sig = None;

    for part in req.query.split('&') {
        if part.is_empty() {
            continue;
        }
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k, v),
            None => (part, ""),
        };
        if k.eq_ignore_ascii_case("X-Amz-Algorithm") {
            algo = Some(percent_decode(v));
        } else if k.eq_ignore_ascii_case("X-Amz-Credential") {
            cred = Some(percent_decode(v));
        } else if k.eq_ignore_ascii_case("X-Amz-Date") {
            date = Some(percent_decode(v));
        } else if k.eq_ignore_ascii_case("X-Amz-Expires") {
            expires = v.parse::<u64>().ok();
        } else if k.eq_ignore_ascii_case("X-Amz-SignedHeaders") {
            signed = Some(percent_decode(v));
        } else if k.eq_ignore_ascii_case("X-Amz-Signature") {
            sig = Some(percent_decode(v));
        }
    }

    let (Some(algo), Some(cred), Some(amzdate), Some(exp), Some(signed_str), Some(signature)) =
        (algo, cred, date, expires, signed, sig)
    else {
        return Err(SigError::MalformedAuth);
    };

    if algo != "AWS4-HMAC-SHA256" {
        return Err(SigError::MalformedAuth);
    }

    let c: Vec<&str> = cred.split('/').collect();
    if c.len() != 5 || c[4] != "aws4_request" {
        return Err(SigError::MalformedAuth);
    }
    let (access_key_id, date_stamp, region, service) = (c[0], c[1], c[2], c[3]);
    if service != "s3" || region.is_empty() {
        return Err(SigError::BadScope);
    }

    let t = parse_amzdate(&amzdate).ok_or(SigError::MalformedAuth)?;
    if now_secs > t + exp {
        return Err(SigError::Expired);
    }
    if t > now_secs + MAX_SKEW_SECS {
        return Err(SigError::Expired);
    }

    let signed_headers_list: Vec<&str> = signed_str.split(';').collect();
    let (canon_headers, signed_list) = canonical_headers(req.headers, &signed_headers_list)?;
    let canon_query = canonical_query_presigned(req.query);
    let canon = format!(
        "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
        req.method,
        encode(req.path, true),
        canon_query,
        canon_headers,
        signed_list
    );

    let scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let sts = string_to_sign(&canon, &amzdate, &scope);
    let key = derive_signing_key(secret, date_stamp, region, "s3");
    let expect = hex::encode(hmac_sha256(&key, sts.as_bytes()));

    if expect.len() != signature.len()
        || expect
            .bytes()
            .zip(signature.bytes())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            != 0
    {
        return Err(SigError::BadSignature);
    }

    Ok(Verified {
        access_key_id: access_key_id.to_string(),
    })
}

pub fn verify_post_policy(
    policy_b64: &str,
    signature: &str,
    credential: &str,
    secret: &str,
) -> Result<Verified, SigError> {
    let c: Vec<&str> = credential.split('/').collect();
    if c.len() != 5 || c[4] != "aws4_request" {
        return Err(SigError::MalformedAuth);
    }
    let (access_key_id, date, region, service) = (c[0], c[1], c[2], c[3]);
    if service != "s3" || region.is_empty() {
        return Err(SigError::BadScope);
    }

    let key = derive_signing_key(secret, date, region, "s3");
    let expect = hex::encode(hmac_sha256(&key, policy_b64.as_bytes()));

    if expect.len() != signature.len()
        || expect
            .bytes()
            .zip(signature.bytes())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            != 0
    {
        return Err(SigError::BadSignature);
    }

    Ok(Verified {
        access_key_id: access_key_id.to_string(),
    })
}

/// Ký request (dùng cho integration test + tài liệu client). `payload_hash`: hex sha256 body
/// hoặc literal `UNSIGNED-PAYLOAD`.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    signed: &[&str],
    body: &[u8],
    access_key_id: &str,
    secret: &str,
    region: &str,
    amzdate: &str,
    payload_hash: &str,
) -> String {
    let mut hdrs: Vec<(String, String)> = headers.to_vec();
    // Đảm bảo headers ký tồn tại (client thật luôn gửi).
    let mut with = |k: &str, v: String| {
        if find_header(&hdrs, k).is_none() {
            hdrs.push((k.to_string(), v));
        }
    };
    with("x-amz-date", amzdate.to_string());
    with("x-amz-content-sha256", payload_hash.to_string());
    let req = SignableRequest {
        method,
        path,
        query,
        headers: &hdrs,
        authorization: "",
        body,
    };
    let (canon, _, _) = canonical_request(&req, signed).expect("sign canonical");
    let scope = format!("{}/{region}/s3/aws4_request", &amzdate[..8]);
    let sts = string_to_sign(&canon, amzdate, &scope);
    let key = derive_signing_key(secret, &amzdate[..8], region, "s3");
    let sig = hex::encode(hmac_sha256(&key, sts.as_bytes()));
    let mut names: Vec<&str> = signed.to_vec();
    names.sort_unstable();
    let list = names
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(";");
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={list}, Signature={sig}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(k: &str, v: impl Into<String>) -> (String, String) {
        (k.to_string(), v.into())
    }

    /// Vector từ AWS SigV4 test suite `get-vanilla` (docs chính thức).
    #[test]
    fn canonical_matches_aws_get_vanilla() {
        let headers = vec![
            h("host", "example.amazonaws.com"),
            h("x-amz-date", "20150830T123600Z"),
        ];
        let req = SignableRequest {
            method: "GET",
            path: "/",
            query: "",
            headers: &headers,
            authorization: "",
            body: b"",
        };
        let (canon, amzdate, _) = canonical_request(&req, &["host", "x-amz-date"]).unwrap();
        assert_eq!(amzdate, "20150830T123600Z");
        assert_eq!(
            canon,
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn roundtrip_sign_verify_and_tamper() {
        let secret = "test-secret-key";
        let headers = vec![
            h("host", "localhost:7070"),
            h("x-amz-content-sha256", sha256_hex(b"")),
        ];
        let amzdate = "20260915T120000Z";
        let now = parse_amzdate(amzdate).unwrap();
        let signed = ["host", "x-amz-content-sha256", "x-amz-date"];
        let auth = sign(
            "PUT",
            "/my-bucket",
            "",
            &headers,
            &signed,
            b"",
            "AKID",
            secret,
            "telecrate-1",
            amzdate,
            &sha256_hex(b""),
        );
        let full = vec![
            h("host", "localhost:7070"),
            h("x-amz-content-sha256", sha256_hex(b"")),
            h("x-amz-date", amzdate),
        ];
        let req = SignableRequest {
            method: "PUT",
            path: "/my-bucket",
            query: "",
            headers: &full,
            authorization: &auth,
            body: b"",
        };
        let v = verify(&req, secret, now).unwrap();
        assert_eq!(v.access_key_id, "AKID");
        // Sai secret → BadSignature.
        assert_eq!(
            verify(&req, "wrong", now).unwrap_err(),
            SigError::BadSignature
        );
        // Auto-region: region nào trong scope cũng chấp nhận (ký bằng region khác vẫn pass).
        let auth_eu = sign(
            "PUT",
            "/my-bucket",
            "",
            &headers,
            &signed,
            b"",
            "AKID",
            secret,
            "eu-west-1",
            amzdate,
            &sha256_hex(b""),
        );
        let req_eu = SignableRequest {
            method: "PUT",
            path: "/my-bucket",
            query: "",
            headers: &full,
            authorization: &auth_eu,
            body: b"",
        };
        assert_eq!(verify(&req_eu, secret, now).unwrap().access_key_id, "AKID");
        // Hết hạn → Expired.
        assert_eq!(
            verify(&req, secret, now + MAX_SKEW_SECS + 1).unwrap_err(),
            SigError::Expired
        );
        // Đổi method sau khi ký → BadSignature.
        let tampered = SignableRequest {
            method: "DELETE",
            ..req
        };
        assert_eq!(
            verify(&tampered, secret, now).unwrap_err(),
            SigError::BadSignature
        );
    }

    /// PBS S3 client gửi `Credential=...,SignedHeaders=...,Signature=...`
    /// (phẩy không space) — parser phải chấp nhận cả 2 format.
    #[test]
    fn auth_header_accepts_comma_without_space() {
        let secret = "test-secret-key";
        let headers = vec![
            h("host", "172.16.0.16:7070"),
            h("content-length", "0"),
            h("x-amz-content-sha256", sha256_hex(b"")),
        ];
        let amzdate = "20260920T120000Z";
        let now = parse_amzdate(amzdate).unwrap();
        let signed = [
            "host",
            "content-length",
            "x-amz-content-sha256",
            "x-amz-date",
        ];
        let auth = sign(
            "GET",
            "/",
            "",
            &headers,
            &signed,
            b"",
            "AKID",
            secret,
            "us-east-1",
            amzdate,
            &sha256_hex(b""),
        );
        assert!(auth.contains(", "));
        let full = vec![
            h("host", "172.16.0.16:7070"),
            h("content-length", "0"),
            h("x-amz-content-sha256", sha256_hex(b"")),
            h("x-amz-date", amzdate),
        ];
        // Format PBS: bỏ space sau phẩy — vẫn verify được.
        let pbs_style = auth.replace(", ", ",");
        assert!(!pbs_style.contains(", "));
        let req = SignableRequest {
            method: "GET",
            path: "/",
            query: "",
            headers: &full,
            authorization: &pbs_style,
            body: b"",
        };
        assert_eq!(extract_key_id(&pbs_style).unwrap(), "AKID");
        assert_eq!(verify(&req, secret, now).unwrap().access_key_id, "AKID");
    }

    #[test]
    fn encoded_path_used_verbatim_no_double_encode() {
        // Path trên request line đã encoded — canonical giữ nguyên, không encode lại.
        // Encode lại sẽ biến %20 thành %2520 và lệch chữ ký với AWS CLI thật.
        let headers = vec![h("host", "x"), h("x-amz-date", "20260915T120000Z")];
        let req = SignableRequest {
            method: "GET",
            path: "/b/c%C3%A0-ph%C3%AA/a%20b%2B100%25.txt",
            query: "prefix=a/b&max-keys=2",
            headers: &headers,
            authorization: "",
            body: b"",
        };
        let (canon, _, _) = canonical_request(&req, &["host", "x-amz-date"]).unwrap();
        assert!(
            canon.contains("/b/c%C3%A0-ph%C3%AA/a%20b%2B100%25.txt"),
            "{canon}"
        );
        assert!(!canon.contains("%252"), "double-encode: {canon}");
        assert!(canon.contains("max-keys=2&prefix=a%2Fb"), "{canon}");
    }

    #[test]
    fn unsigned_payload_accepted_per_spec() {
        let headers = vec![
            h("host", "x"),
            h("x-amz-date", "20260915T120000Z"),
            h("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ];
        let req = SignableRequest {
            method: "PUT",
            path: "/b",
            query: "",
            headers: &headers,
            authorization: "",
            body: b"whatever-bytes",
        };
        let (canon, _, _) =
            canonical_request(&req, &["host", "x-amz-content-sha256", "x-amz-date"]).unwrap();
        assert!(canon.ends_with("\nUNSIGNED-PAYLOAD"), "{canon}");
    }
}

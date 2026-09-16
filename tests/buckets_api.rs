//! Integration M2.1: bucket lifecycle qua HTTP thật, ký SigV4 thật.
//! Chạy trên cả local và CI (`cargo test`), không cần secrets.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use telecrate::config::{AccessKey, Config};

const KEY: &str = "TESTKEY123";
const SECRET: &str = "test-secret-key-123";
const REGION: &str = "telecrate-1";

/// epoch secs → `YYYYMMDDTHHMMSSZ` (thuần std).
fn amzdate(now: u64) -> String {
    let days = (now / 86400) as i64;
    let secs = now % 86400;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u64;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u64;
    let y = if m <= 2 { y + 1 } else { y } as u64;
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Dựng server test trên port ephemeral, trả base URL. Giữ TempDir sống suốt test.
fn spawn_server() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        db_path: dir.path().join("index.db").to_str().unwrap().to_string(),
        spool_dir: dir.path().join("spool").to_str().unwrap().to_string(),
        listen_port: 1,
        encryption: "off".to_string(),
        region: REGION.to_string(),
        access_keys: vec![AccessKey {
            access_key_id: KEY.to_string(),
            secret_key: SECRET.to_string(),
        }],
        ..Default::default()
    };
    // init DB như CLI init.
    std::fs::create_dir_all(&cfg.spool_dir).unwrap();
    let mut conn = telecrate::db::open(&cfg.db_path).unwrap();
    telecrate::db::apply_migration(&mut conn, 1, telecrate::db::MIGRATION_001).unwrap();
    drop(conn);

    let (tx, rx) = mpsc::channel();
    // Router dựng ngoài async context; test này không cấu hình telegram → transport None.
    let app = telecrate::app::router(cfg, None);
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = l.local_addr().unwrap().port();
            tx.send(port).unwrap();
            axum::serve(l, app).await.unwrap();
        });
    });
    let port: u16 = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let base = format!("http://127.0.0.1:{port}");
    // Chờ health.
    let client = reqwest::blocking::Client::new();
    for _ in 0..50 {
        if client.get(format!("{base}/health")).send().is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    (dir, base)
}

fn sha_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

/// Gửi request đã ký SigV4. Trả (status, body, request_id header).
#[allow(clippy::too_many_arguments)]
fn signed(
    client: &reqwest::blocking::Client,
    method: &str,
    base: &str,
    path_query: &str,
    body: &[u8],
    key: &str,
    secret: &str,
    amzdate: &str,
) -> (u16, String, Option<String>) {
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_query, ""),
    };
    let payload = sha_hex(body);
    let host = base.trim_start_matches("http://").to_string();
    let headers = vec![
        ("host".to_string(), host),
        ("x-amz-content-sha256".to_string(), payload.clone()),
    ];
    let signed = ["host", "x-amz-content-sha256", "x-amz-date"];
    let auth = telecrate::sigv4::sign(
        method, path, query, &headers, &signed, body, key, secret, REGION, amzdate, &payload,
    );
    let url = format!("{base}{path_query}");
    let req = match method {
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        _ => client.get(&url),
    };
    let resp = req
        .header("x-amz-date", amzdate)
        .header("x-amz-content-sha256", payload)
        .header("authorization", auth)
        .body(body.to_vec())
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    let rid = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let text = resp.text().unwrap_or_default();
    (status, text, rid)
}

#[test]
fn bucket_lifecycle_signed() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();
    let now = amzdate(now_secs());

    // PUT create → 200 + request id.
    let (s, body0, rid) = signed(
        &client,
        "PUT",
        &base,
        "/test-bucket",
        b"",
        KEY,
        SECRET,
        &now,
    );
    assert_eq!(s, 200, "body was: {body0}");
    assert!(rid.is_some());
    // Tạo lại → 200 (AlreadyOwned).
    let (s, _, _) = signed(
        &client,
        "PUT",
        &base,
        "/test-bucket",
        b"",
        KEY,
        SECRET,
        &now,
    );
    assert_eq!(s, 200);
    // HEAD tồn tại/không.
    let (s, _, _) = signed(
        &client,
        "HEAD",
        &base,
        "/test-bucket",
        b"",
        KEY,
        SECRET,
        &now,
    );
    assert_eq!(s, 200);
    let (s, _, _) = signed(&client, "HEAD", &base, "/ghost", b"", KEY, SECRET, &now);
    assert_eq!(s, 404);
    // ListBuckets thấy bucket.
    let (s, body, _) = signed(&client, "GET", &base, "/", b"", KEY, SECRET, &now);
    assert_eq!(s, 200);
    assert!(body.contains("<Name>test-bucket</Name>"), "{body}");
    // GetBucketLocation.
    let (s, body, _) = signed(
        &client,
        "GET",
        &base,
        "/test-bucket?location",
        b"",
        KEY,
        SECRET,
        &now,
    );
    assert_eq!(s, 200);
    assert!(body.contains(REGION), "{body}");
    let (s, body, rid) = signed(
        &client,
        "GET",
        &base,
        "/ghost?location",
        b"",
        KEY,
        SECRET,
        &now,
    );
    assert_eq!(s, 404);
    assert!(body.contains("NoSuchBucket"), "{body}");
    assert!(rid.is_some());
    // GET bucket không ?location → 501 trung thực (2.2).
    let (s, body, _) = signed(
        &client,
        "GET",
        &base,
        "/test-bucket",
        b"",
        KEY,
        SECRET,
        &now,
    );
    // GET bucket không ?location = ListObjectsV2 (bucket rỗng).
    assert_eq!(s, 200);
    assert!(body.contains("<ListBucketResult"), "{body}");
    assert!(body.contains("<IsTruncated>false</IsTruncated>"), "{body}");
    // DELETE ghost → 404; DELETE thật → 204; HEAD sau xóa → 404.
    let (s, _, _) = signed(&client, "DELETE", &base, "/ghost", b"", KEY, SECRET, &now);
    assert_eq!(s, 404);
    let (s, _, _) = signed(
        &client,
        "DELETE",
        &base,
        "/test-bucket",
        b"",
        KEY,
        SECRET,
        &now,
    );
    assert_eq!(s, 204);
    let (s, _, _) = signed(
        &client,
        "HEAD",
        &base,
        "/test-bucket",
        b"",
        KEY,
        SECRET,
        &now,
    );
    assert_eq!(s, 404);
}

#[test]
fn auth_failures_map_to_s3_errors() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();
    let now = amzdate(now_secs());

    // Không auth → 403 AccessDenied.
    let resp = client.put(format!("{base}/b")).send().unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    let t = resp.text().unwrap();
    assert!(t.contains("AccessDenied"), "{t}");

    // Sai secret → 403 SignatureDoesNotMatch.
    let (s, body, _) = signed(&client, "PUT", &base, "/b", b"", KEY, "wrong-secret", &now);
    assert_eq!(s, 403);
    assert!(body.contains("SignatureDoesNotMatch"), "{body}");

    // Key lạ → 403 InvalidAccessKeyId.
    let (s, body, _) = signed(&client, "PUT", &base, "/b", b"", "NOPE", SECRET, &now);
    assert_eq!(s, 403);
    assert!(body.contains("InvalidAccessKeyId"), "{body}");

    // Hết hạn (lệch 1h) → 403 RequestTimeTooSkewed.
    let old = amzdate(now_secs() - 3600);
    let (s, body, _) = signed(&client, "PUT", &base, "/b", b"", KEY, SECRET, &old);
    assert_eq!(s, 403);
    assert!(body.contains("RequestTimeTooSkewed"), "{body}");

    // Tên bucket sai → 400 InvalidBucketName (đã qua auth).
    let (s, body, _) = signed(&client, "PUT", &base, "/AB", b"", KEY, SECRET, &now);
    assert_eq!(s, 400);
    assert!(body.contains("InvalidBucketName"), "{body}");

    // LocationConstraint khác region → 400.
    let xml = "<CreateBucketConfiguration><LocationConstraint>other-region</LocationConstraint></CreateBucketConfiguration>";
    let (s, body, _) = signed(
        &client,
        "PUT",
        &base,
        "/loc-bucket",
        xml.as_bytes(),
        KEY,
        SECRET,
        &now,
    );
    assert_eq!(s, 400);
    assert!(body.contains("InvalidLocationConstraint"), "{body}");

    // LocationConstraint đúng region → 200.
    let xml = format!(
        r#"<CreateBucketConfiguration><LocationConstraint>{REGION}</LocationConstraint></CreateBucketConfiguration>"#
    );
    let (s, _, _) = signed(
        &client,
        "PUT",
        &base,
        "/loc-bucket",
        xml.as_bytes(),
        KEY,
        SECRET,
        &now,
    );
    assert_eq!(s, 200);
}

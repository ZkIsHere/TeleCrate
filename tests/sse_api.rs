//! Integration M4.4: Server-Side Encryption (SSE) Strict Semantics (SSE-S3 & SSE-C).

use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use telecrate::config::{AccessKey, Config};

const KEY: &str = "TESTKEY123";
const SECRET: &str = "test-secret-key-123";
const REGION: &str = "telecrate-1";

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
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let y = y + if m <= 2 { 1 } else { 0 };
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

fn sha_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

fn spawn_server() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        db_path: dir.path().join("index.db").to_str().unwrap().to_string(),
        spool_dir: dir.path().join("spool").to_str().unwrap().to_string(),
        listen_port: 0,
        encryption: "off".to_string(),
        region: REGION.to_string(),
        access_keys: vec![AccessKey {
            access_key_id: KEY.to_string(),
            secret_key: SECRET.to_string(),
        }],
        ..Default::default()
    };
    std::fs::create_dir_all(&cfg.spool_dir).unwrap();
    let mut conn = telecrate::db::open(&cfg.db_path).unwrap();
    telecrate::db::apply_all_migrations(&mut conn).unwrap();
    drop(conn);

    let (tx, rx) = mpsc::channel();
    let cfg_thread = cfg.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(format!("http://{addr}")).unwrap();
            let keys = cfg_thread.load_keystore().unwrap();
            axum::serve(listener, telecrate::app::router(cfg_thread, None, keys))
                .await
                .unwrap();
        });
    });

    let base = rx.recv().unwrap();
    (dir, base)
}

struct SimpleResp {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

fn req(
    client: &reqwest::blocking::Client,
    method: &str,
    base: &str,
    path_and_query: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> SimpleResp {
    let url = format!("{base}{path_and_query}");
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_and_query, ""),
    };
    let now = now_secs();
    let date = amzdate(now);
    let payload_hash = sha_hex(body);

    let mut hdrs = vec![
        (
            "host".to_string(),
            base.trim_start_matches("http://").to_string(),
        ),
        ("x-amz-date".to_string(), date.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
    ];
    for (k, v) in extra_headers {
        hdrs.push((k.to_string(), v.to_string()));
    }
    let auth = telecrate::sigv4::sign(
        method,
        path,
        query,
        &hdrs,
        &["host", "x-amz-content-sha256", "x-amz-date"],
        body,
        KEY,
        SECRET,
        REGION,
        &date,
        &payload_hash,
    );

    let mut builder = match method {
        "GET" => client.get(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        "POST" => client.post(&url),
        _ => panic!("unsupported method"),
    };

    builder = builder
        .header("Authorization", auth)
        .header("x-amz-date", date)
        .header("x-amz-content-sha256", payload_hash);
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    if !body.is_empty() {
        builder = builder.body(body.to_vec());
    }

    let resp = builder.send().unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body_bytes = resp.bytes().unwrap().to_vec();
    SimpleResp {
        status,
        headers,
        body: body_bytes,
    }
}

#[test]
fn test_sse_s3_and_ssec_lifecycle() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();

    // 1. Create bucket
    let r = req(&client, "PUT", &base, "/sse-bucket", b"", &[]);
    assert_eq!(r.status, 200);

    // 2. PUT object with SSE-S3 (x-amz-server-side-encryption: AES256)
    let r = req(
        &client,
        "PUT",
        &base,
        "/sse-bucket/s3-obj.txt",
        b"encrypted with s3 key",
        &[("x-amz-server-side-encryption", "AES256")],
    );
    assert_eq!(r.status, 200);

    // GET object -> response header has x-amz-server-side-encryption: AES256
    let r = req(&client, "GET", &base, "/sse-bucket/s3-obj.txt", b"", &[]);
    assert_eq!(r.status, 200);
    assert_eq!(
        r.headers
            .get("x-amz-server-side-encryption")
            .unwrap()
            .to_str()
            .unwrap(),
        "AES256"
    );

    // 3. PUT object with invalid SSE algorithm -> 400 InvalidEncryptionAlgorithmError
    let r = req(
        &client,
        "PUT",
        &base,
        "/sse-bucket/bad.txt",
        b"data",
        &[("x-amz-server-side-encryption", "INVALID_ALGO")],
    );
    assert_eq!(r.status, 400);

    // 4. SSE-C setup (32 bytes key)
    let raw_key = [42u8; 32];
    let key_b64 = telecrate::s3::base64_encode(&raw_key);
    let key_md5 = md5::compute(&raw_key);
    let key_md5_b64 = telecrate::s3::base64_encode(key_md5.as_ref());

    // PUT object with SSE-C
    let ssec_headers = [
        ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
        ("x-amz-server-side-encryption-customer-key", &key_b64),
        (
            "x-amz-server-side-encryption-customer-key-md5",
            &key_md5_b64,
        ),
    ];
    let r = req(
        &client,
        "PUT",
        &base,
        "/sse-bucket/ssec-obj.txt",
        b"customer encrypted data",
        &ssec_headers,
    );
    assert_eq!(r.status, 200);

    // GET SSE-C object WITHOUT headers -> 400 InvalidArgument
    let r = req(&client, "GET", &base, "/sse-bucket/ssec-obj.txt", b"", &[]);
    assert_eq!(r.status, 400);

    // GET SSE-C object with WRONG key MD5 -> 400 or 403
    let wrong_md5_headers = [
        ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
        ("x-amz-server-side-encryption-customer-key", &key_b64),
        (
            "x-amz-server-side-encryption-customer-key-md5",
            "wrongmd5base64==",
        ),
    ];
    let r = req(
        &client,
        "GET",
        &base,
        "/sse-bucket/ssec-obj.txt",
        b"",
        &wrong_md5_headers,
    );
    assert_eq!(r.status, 400);

    // GET SSE-C object with CORRECT headers -> 200 OK
    let r = req(
        &client,
        "GET",
        &base,
        "/sse-bucket/ssec-obj.txt",
        b"",
        &ssec_headers,
    );
    assert_eq!(r.status, 200);
    assert_eq!(
        String::from_utf8(r.body).unwrap(),
        "customer encrypted data"
    );
    assert_eq!(
        r.headers
            .get("x-amz-server-side-encryption-customer-algorithm")
            .unwrap()
            .to_str()
            .unwrap(),
        "AES256"
    );
    assert_eq!(
        r.headers
            .get("x-amz-server-side-encryption-customer-key-md5")
            .unwrap()
            .to_str()
            .unwrap(),
        key_md5_b64
    );
}

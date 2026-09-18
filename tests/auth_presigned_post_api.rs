//! Integration M4.2: Auth Complete — Presigned URLs, POST Policy Form Upload, Multi-Access Keys & Clock Skew.

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
        access_keys: vec![AccessKey {
            access_key_id: KEY.to_string(),
            secret_key: SECRET.to_string(),
        }],
        ..Default::default()
    };
    std::fs::create_dir_all(&cfg.spool_dir).unwrap();

    let (tx, rx) = mpsc::channel();
    let cfg_thread = cfg.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let db = telecrate::db::Db::open_sqlite(&cfg_thread.db_path)
                .await
                .unwrap();
            telecrate::db::apply_all_migrations(&db).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tx.send(format!("http://{addr}")).unwrap();
            let keys = cfg_thread.load_keystore().unwrap();
            axum::serve(listener, telecrate::app::router(cfg_thread, db, None, keys))
                .await
                .unwrap();
        });
    });

    let base = rx.recv().unwrap();
    (dir, base)
}

struct SimpleResp {
    status: u16,
    _headers: reqwest::header::HeaderMap,
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
    if !body.is_empty() || method == "PUT" || method == "POST" {
        builder = builder.body(body.to_vec());
    }

    let resp = builder.send().unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body_bytes = resp.bytes().unwrap().to_vec();
    SimpleResp {
        status,
        _headers: headers,
        body: body_bytes,
    }
}

#[test]
fn test_multi_access_keys_and_presigned_urls() {
    let (dir, base) = spawn_server();
    let client = reqwest::blocking::Client::builder().build().unwrap();
    let db_path = dir.path().join("index.db").to_str().unwrap().to_string();

    // 1. Create a bucket
    let r = req(&client, "PUT", &base, "/auth-bkt", b"", &[]);
    assert_eq!(r.status, 200);

    // 2. Insert new access key into DB via DAL
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let conn = rt
        .block_on(telecrate::db::Db::open_sqlite(&db_path))
        .unwrap();
    rt.block_on(telecrate::db::create_access_key(
        &conn,
        "NEWKEY888",
        "new-secret-888",
        Some("Dynamic key"),
    ))
    .unwrap();

    // 3. Put object using the new DB Access Key!
    let date = amzdate(now_secs());
    let payload_hash = sha_hex(b"hello from db key");
    let hdrs = vec![
        (
            "host".to_string(),
            base.trim_start_matches("http://").to_string(),
        ),
        ("x-amz-date".to_string(), date.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
    ];
    let auth = telecrate::sigv4::sign(
        "PUT",
        "/auth-bkt/db-item.txt",
        "",
        &hdrs,
        &["host", "x-amz-content-sha256", "x-amz-date"],
        b"hello from db key",
        "NEWKEY888",
        "new-secret-888",
        REGION,
        &date,
        &payload_hash,
    );
    let resp = client
        .put(format!("{base}/auth-bkt/db-item.txt"))
        .header("Authorization", auth)
        .header("x-amz-date", date)
        .header("x-amz-content-sha256", payload_hash)
        .body("hello from db key")
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // 4. Test Presigned GET URL
    let now = now_secs();
    let date_iso = amzdate(now);
    let date_stamp = &date_iso[..8];
    let cred = format!("NEWKEY888/{date_stamp}/{REGION}/s3/aws4_request");
    let cred_enc = cred.replace('/', "%2F");
    let signed_headers = "host";
    let expires = "3600";

    // Canonical request for presigned GET
    let canon_query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={cred_enc}&X-Amz-Date={date_iso}&X-Amz-Expires={expires}&X-Amz-SignedHeaders={signed_headers}"
    );
    let req_signable = telecrate::sigv4::SignableRequest {
        method: "GET",
        path: "/auth-bkt/db-item.txt",
        query: &canon_query,
        headers: &[
            (
                "host".to_string(),
                base.trim_start_matches("http://").to_string(),
            ),
            (
                "x-amz-content-sha256".to_string(),
                "UNSIGNED-PAYLOAD".to_string(),
            ),
        ],
        authorization: "",
        body: b"",
    };
    let (canon, _, _) = telecrate::sigv4::canonical_request(&req_signable, &["host"]).unwrap();
    let scope = format!("{date_stamp}/{REGION}/s3/aws4_request");
    let sts = telecrate::sigv4::string_to_sign(&canon, &date_iso, &scope);
    let key_bytes =
        telecrate::sigv4::derive_signing_key("new-secret-888", date_stamp, REGION, "s3");
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes).unwrap();
    mac.update(sts.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    let presigned_url = format!("{base}/auth-bkt/db-item.txt?{canon_query}&X-Amz-Signature={sig}");
    let get_resp = client.get(&presigned_url).send().unwrap();
    assert_eq!(get_resp.status().as_u16(), 200);
    assert_eq!(get_resp.bytes().unwrap().as_ref(), b"hello from db key");
}

fn base64_encode(bytes: &[u8]) -> String {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() {
            bytes[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < bytes.len() {
            bytes[i + 2] as u32
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(table[((triple >> 18) & 0x3F) as usize] as char);
        out.push(table[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < bytes.len() {
            out.push(table[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        if i + 2 < bytes.len() {
            out.push(table[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        i += 3;
    }
    out
}

#[test]
fn test_post_policy_form_upload() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::builder().build().unwrap();

    let r = req(&client, "PUT", &base, "/post-bkt", b"", &[]);
    assert_eq!(r.status, 200);

    // Create Base64 Policy
    let now = now_secs();
    let date_iso = amzdate(now);
    let date_stamp = &date_iso[..8];
    let cred = format!("{KEY}/{date_stamp}/{REGION}/s3/aws4_request");

    let policy_json = r#"{"expiration":"2030-01-01T00:00:00Z","conditions":[{"bucket":"post-bkt"},["starts-with","$key","user/"]]}"#;
    let policy_b64 = base64_encode(policy_json.as_bytes());

    // Compute POST signature
    let key_bytes = telecrate::sigv4::derive_signing_key(SECRET, date_stamp, REGION, "s3");
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes).unwrap();
    mac.update(policy_b64.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    // Send multipart/form-data POST request
    let form = reqwest::blocking::multipart::Form::new()
        .text("key", "user/uploaded.txt")
        .text("policy", policy_b64)
        .text("x-amz-credential", cred)
        .text("x-amz-date", date_iso)
        .text("x-amz-algorithm", "AWS4-HMAC-SHA256")
        .text("x-amz-signature", sig)
        .part(
            "file",
            reqwest::blocking::multipart::Part::bytes(b"posted form content".to_vec())
                .file_name("uploaded.txt"),
        );

    let res = client
        .post(format!("{base}/post-bkt"))
        .multipart(form)
        .send()
        .unwrap();

    assert_eq!(res.status().as_u16(), 204);

    // Read back object via GET
    let r_get = req(
        &client,
        "GET",
        &base,
        "/post-bkt/user/uploaded.txt",
        b"",
        &[],
    );
    assert_eq!(r_get.status, 200);
    assert_eq!(r_get.body, b"posted form content");
}

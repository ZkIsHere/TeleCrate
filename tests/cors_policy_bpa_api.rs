//! Integration M4.3: CORS Engine, Bucket Policy Engine & Block Public Access (BPA).

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
    if !body.is_empty() {
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
fn test_cors_api_and_preflight() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();

    // 1. Create bucket
    let r = req(&client, "PUT", &base, "/cors-bucket", b"", &[]);
    assert_eq!(r.status, 200);

    // 2. GET ?cors before setting -> 404 NoSuchCORSConfiguration
    let r = req(&client, "GET", &base, "/cors-bucket?cors", b"", &[]);
    assert_eq!(r.status, 404);

    // 3. PUT ?cors with valid XML
    let cors_xml = r#"<?xml version="1.0" encoding="UTF-8"?><CORSConfiguration><CORSRule><AllowedOrigin>https://app.example.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedHeader>*</AllowedHeader><MaxAgeSeconds>3600</MaxAgeSeconds><ExposeHeader>ETag</ExposeHeader></CORSRule></CORSConfiguration>"#;
    let r = req(
        &client,
        "PUT",
        &base,
        "/cors-bucket?cors",
        cors_xml.as_bytes(),
        &[("content-type", "application/xml")],
    );
    assert_eq!(r.status, 200);

    // 4. GET ?cors -> returns CORS XML
    let r = req(&client, "GET", &base, "/cors-bucket?cors", b"", &[]);
    assert_eq!(r.status, 200);
    let body_text = String::from_utf8(r.body).unwrap();
    assert!(body_text.contains("app.example.com"));

    // 5. Preflight OPTIONS request
    let preflight = client
        .request(
            reqwest::Method::OPTIONS,
            &format!("{base}/cors-bucket/myobject"),
        )
        .header("Origin", "https://app.example.com")
        .header("Access-Control-Request-Method", "PUT")
        .header("Access-Control-Request-Headers", "content-type")
        .send()
        .unwrap();
    assert_eq!(preflight.status().as_u16(), 200);
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "https://app.example.com"
    );
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-methods")
            .unwrap()
            .to_str()
            .unwrap(),
        "GET, PUT"
    );
    assert_eq!(
        preflight
            .headers()
            .get("access-control-max-age")
            .unwrap()
            .to_str()
            .unwrap(),
        "3600"
    );

    // 6. Preflight with forbidden Origin -> 403 AccessDenied
    let forbidden_preflight = client
        .request(
            reqwest::Method::OPTIONS,
            &format!("{base}/cors-bucket/myobject"),
        )
        .header("Origin", "https://evil.com")
        .header("Access-Control-Request-Method", "PUT")
        .send()
        .unwrap();
    assert_eq!(forbidden_preflight.status().as_u16(), 403);

    // 7. DELETE ?cors -> 204
    let r = req(&client, "DELETE", &base, "/cors-bucket?cors", b"", &[]);
    assert_eq!(r.status, 204);

    // 8. GET ?cors -> 404
    let r = req(&client, "GET", &base, "/cors-bucket?cors", b"", &[]);
    assert_eq!(r.status, 404);
}

#[test]
fn test_bucket_policy_and_bpa() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();

    // 1. Create bucket
    let r = req(&client, "PUT", &base, "/policy-bucket", b"", &[]);
    assert_eq!(r.status, 200);

    // 2. Put object hello.txt & secret.txt
    let r = req(
        &client,
        "PUT",
        &base,
        "/policy-bucket/hello.txt",
        b"hello world",
        &[],
    );
    assert_eq!(r.status, 200);
    let r = req(
        &client,
        "PUT",
        &base,
        "/policy-bucket/secret.txt",
        b"super secret",
        &[],
    );
    assert_eq!(r.status, 200);

    // 3. Anonymous GET hello.txt without policy -> 403 AccessDenied
    let anon_r = client
        .get(&format!("{base}/policy-bucket/hello.txt"))
        .send()
        .unwrap();
    assert_eq!(anon_r.status().as_u16(), 403);

    // 4. Set Bucket Policy: Public Allow GET on policy-bucket/*, Deny GET on policy-bucket/secret.txt
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::policy-bucket/*"
            },
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::policy-bucket/secret.txt"
            }
        ]
    }"#;

    let r = req(
        &client,
        "PUT",
        &base,
        "/policy-bucket?policy",
        policy_json.as_bytes(),
        &[("content-type", "application/json")],
    );
    assert_eq!(r.status, 200);

    // 5. GET ?policy -> returns policy JSON
    let r = req(&client, "GET", &base, "/policy-bucket?policy", b"", &[]);
    assert_eq!(r.status, 200);
    let body_text = String::from_utf8(r.body).unwrap();
    assert!(body_text.contains("policy-bucket/*"));

    // 6. Anonymous GET hello.txt -> SUCCEEDS (200 OK)!
    let anon_hello = client
        .get(&format!("{base}/policy-bucket/hello.txt"))
        .send()
        .unwrap();
    assert_eq!(anon_hello.status().as_u16(), 200);
    assert_eq!(anon_hello.text().unwrap(), "hello world");

    // 7. Anonymous GET secret.txt -> DENIED (403 Forbidden)!
    let anon_secret = client
        .get(&format!("{base}/policy-bucket/secret.txt"))
        .send()
        .unwrap();
    assert_eq!(anon_secret.status().as_u16(), 403);

    // 8. Test BPA (Block Public Access)
    // Put BPA: BlockPublicPolicy = true
    let bpa_xml = r#"<?xml version="1.0" encoding="UTF-8"?><PublicAccessBlockConfiguration><BlockPublicAcls>false</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>"#;
    let r = req(
        &client,
        "PUT",
        &base,
        "/policy-bucket?publicAccessBlock",
        bpa_xml.as_bytes(),
        &[("content-type", "application/xml")],
    );
    assert_eq!(r.status, 200);

    // GET ?publicAccessBlock -> returns BPA XML
    let r = req(
        &client,
        "GET",
        &base,
        "/policy-bucket?publicAccessBlock",
        b"",
        &[],
    );
    assert_eq!(r.status, 200);
    let body_text = String::from_utf8(r.body).unwrap();
    assert!(body_text.contains("<BlockPublicPolicy>true</BlockPublicPolicy>"));

    // Now try to PUT a new public policy -> REJECTED 400 InvalidPolicy because BPA is enabled!
    let r = req(
        &client,
        "PUT",
        &base,
        "/policy-bucket?policy",
        policy_json.as_bytes(),
        &[("content-type", "application/json")],
    );
    assert_eq!(r.status, 400);

    // DELETE ?policy and ?publicAccessBlock -> 204
    let r = req(&client, "DELETE", &base, "/policy-bucket?policy", b"", &[]);
    assert_eq!(r.status, 204);
    let r = req(
        &client,
        "DELETE",
        &base,
        "/policy-bucket?publicAccessBlock",
        b"",
        &[],
    );
    assert_eq!(r.status, 204);
}

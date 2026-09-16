//! Integration M4.5: Object Lock Gateway (WORM Retention GOVERNANCE/COMPLIANCE & Legal Hold).

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
fn test_bucket_object_lock_config() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();

    // Create bucket
    let r = req(&client, "PUT", &base, "/lock-bucket", b"", &[]);
    assert_eq!(r.status, 200);

    // GET ?object-lock before setting -> 404 ObjectLockConfigurationNotFoundError
    let r = req(&client, "GET", &base, "/lock-bucket?object-lock", b"", &[]);
    assert_eq!(r.status, 404);

    // PUT ?object-lock
    let lock_xml = r#"<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>"#;
    let r = req(
        &client,
        "PUT",
        &base,
        "/lock-bucket?object-lock",
        lock_xml.as_bytes(),
        &[("content-type", "application/xml")],
    );
    assert_eq!(r.status, 200);

    // GET ?object-lock -> returns configuration XML
    let r = req(&client, "GET", &base, "/lock-bucket?object-lock", b"", &[]);
    assert_eq!(r.status, 200);
    let body_text = String::from_utf8(r.body).unwrap();
    assert!(body_text.contains("Enabled"));
    assert!(body_text.contains("GOVERNANCE"));
    assert!(body_text.contains("30"));
}

#[test]
fn test_worm_legal_hold_and_retention_enforcement() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();

    let r = req(&client, "PUT", &base, "/worm-bucket", b"", &[]);
    assert_eq!(r.status, 200);

    // 1. Legal Hold test
    let r = req(
        &client,
        "PUT",
        &base,
        "/worm-bucket/legal.txt",
        b"legal hold file",
        &[],
    );
    assert_eq!(r.status, 200);

    // GET ?legal-hold -> OFF
    let r = req(
        &client,
        "GET",
        &base,
        "/worm-bucket/legal.txt?legal-hold",
        b"",
        &[],
    );
    assert_eq!(r.status, 200);
    assert!(String::from_utf8(r.body).unwrap().contains("OFF"));

    // PUT ?legal-hold ON
    let lh_xml =
        r#"<?xml version="1.0" encoding="UTF-8"?><LegalHold><Status>ON</Status></LegalHold>"#;
    let r = req(
        &client,
        "PUT",
        &base,
        "/worm-bucket/legal.txt?legal-hold",
        lh_xml.as_bytes(),
        &[("content-type", "application/xml")],
    );
    assert_eq!(r.status, 200);

    // Try DELETE -> REJECTED 403 AccessDenied because Legal Hold is ON!
    let r = req(&client, "DELETE", &base, "/worm-bucket/legal.txt", b"", &[]);
    assert_eq!(r.status, 403);

    // Turn Legal Hold OFF
    let lh_off_xml =
        r#"<?xml version="1.0" encoding="UTF-8"?><LegalHold><Status>OFF</Status></LegalHold>"#;
    let r = req(
        &client,
        "PUT",
        &base,
        "/worm-bucket/legal.txt?legal-hold",
        lh_off_xml.as_bytes(),
        &[("content-type", "application/xml")],
    );
    assert_eq!(r.status, 200);

    // DELETE -> 204 No Content
    let r = req(&client, "DELETE", &base, "/worm-bucket/legal.txt", b"", &[]);
    assert_eq!(r.status, 204);

    // 2. GOVERNANCE Retention test
    let r = req(
        &client,
        "PUT",
        &base,
        "/worm-bucket/gov.txt",
        b"governance retention file",
        &[],
    );
    assert_eq!(r.status, 200);

    let ret_xml = r#"<?xml version="1.0" encoding="UTF-8"?><Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-12-31T23:59:59Z</RetainUntilDate></Retention>"#;
    let r = req(
        &client,
        "PUT",
        &base,
        "/worm-bucket/gov.txt?retention",
        ret_xml.as_bytes(),
        &[("content-type", "application/xml")],
    );
    assert_eq!(r.status, 200);

    // GET ?retention
    let r = req(
        &client,
        "GET",
        &base,
        "/worm-bucket/gov.txt?retention",
        b"",
        &[],
    );
    assert_eq!(r.status, 200);
    assert!(String::from_utf8(r.body)
        .unwrap()
        .contains("2030-12-31T23:59:59Z"));

    // DELETE without bypass -> REJECTED 403
    let r = req(&client, "DELETE", &base, "/worm-bucket/gov.txt", b"", &[]);
    assert_eq!(r.status, 403);

    // DELETE with bypass header -> SUCCEEDS 204
    let r = req(
        &client,
        "DELETE",
        &base,
        "/worm-bucket/gov.txt",
        b"",
        &[("x-amz-bypass-governance-retention", "true")],
    );
    assert_eq!(r.status, 204);

    // 3. COMPLIANCE Retention test
    let r = req(
        &client,
        "PUT",
        &base,
        "/worm-bucket/comp.txt",
        b"compliance retention file",
        &[],
    );
    assert_eq!(r.status, 200);

    let comp_xml = r#"<?xml version="1.0" encoding="UTF-8"?><Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2030-12-31T23:59:59Z</RetainUntilDate></Retention>"#;
    let r = req(
        &client,
        "PUT",
        &base,
        "/worm-bucket/comp.txt?retention",
        comp_xml.as_bytes(),
        &[("content-type", "application/xml")],
    );
    assert_eq!(r.status, 200);

    // DELETE with bypass header -> STILL REJECTED 403 because COMPLIANCE mode cannot be bypassed!
    let r = req(
        &client,
        "DELETE",
        &base,
        "/worm-bucket/comp.txt",
        b"",
        &[("x-amz-bypass-governance-retention", "true")],
    );
    assert_eq!(r.status, 403);
}

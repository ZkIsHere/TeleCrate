//! Integration M3.4: Conditional Requests & Advanced Range Semantics via HTTP API.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
        listen_port: 1,
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

    let base = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    (dir, base)
}

struct Resp {
    status: u16,
    body: Vec<u8>,
    headers: reqwest::header::HeaderMap,
}

fn req(
    client: &reqwest::blocking::Client,
    method: &str,
    base: &str,
    path_query: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> Resp {
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_query, ""),
    };
    let payload = sha_hex(body);
    let host = base.trim_start_matches("http://").to_string();
    let mut headers = vec![
        ("host".to_string(), host),
        ("x-amz-content-sha256".to_string(), payload.clone()),
    ];
    let mut signed = vec!["host", "x-amz-content-sha256", "x-amz-date"];
    for (k, v) in extra {
        headers.push((k.to_string(), v.to_string()));
        if *k == "range"
            || *k == "if-match"
            || *k == "if-none-match"
            || *k == "if-range"
            || k.starts_with("x-amz-copy-source")
        {
            signed.push(k);
        }
    }
    signed.sort_unstable();
    let amzdate = amzdate(now_secs());
    let auth = telecrate::sigv4::sign(
        method, path, query, &headers, &signed, body, KEY, SECRET, REGION, &amzdate, &payload,
    );
    let url = format!("{base}{path_query}");
    let mut r = match method {
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        "POST" => client.post(&url),
        _ => client.get(&url),
    };
    r = r
        .header("x-amz-date", amzdate)
        .header("x-amz-content-sha256", payload)
        .header("authorization", auth);
    for (k, v) in extra {
        r = r.header(*k, *v);
    }
    let res = r.body(body.to_vec()).send().unwrap();
    Resp {
        status: res.status().as_u16(),
        headers: res.headers().clone(),
        body: res.bytes().unwrap().to_vec(),
    }
}

#[test]
fn test_conditional_requests_and_if_range() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();

    // 1. Create bucket
    let res = req(&client, "PUT", &base, "/cond-bucket", b"", &[]);
    assert_eq!(res.status, 200);

    // 2. PUT object
    let body_data = b"Hello Conditional Request World!";
    let res = req(
        &client,
        "PUT",
        &base,
        "/cond-bucket/file.txt",
        body_data,
        &[],
    );
    assert_eq!(res.status, 200);
    let etag = res
        .headers
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // 3. GET with If-Match (matching) -> 200
    let res = req(
        &client,
        "GET",
        &base,
        "/cond-bucket/file.txt",
        b"",
        &[("if-match", &etag)],
    );
    assert_eq!(res.status, 200);
    assert_eq!(res.body, body_data);

    // 4. GET with If-Match (mismatched) -> 412 PreconditionFailed
    let res = req(
        &client,
        "GET",
        &base,
        "/cond-bucket/file.txt",
        b"",
        &[("if-match", "\"wrong-etag\"")],
    );
    assert_eq!(res.status, 412);

    // 5. GET with If-None-Match (matching) -> 304 Not Modified
    let res = req(
        &client,
        "GET",
        &base,
        "/cond-bucket/file.txt",
        b"",
        &[("if-none-match", &etag)],
    );
    assert_eq!(res.status, 304);
    assert!(res.body.is_empty());

    // 6. PUT with If-None-Match: * on existing key -> 412 PreconditionFailed
    let res = req(
        &client,
        "PUT",
        &base,
        "/cond-bucket/file.txt",
        b"New Body",
        &[("if-none-match", "*")],
    );
    assert_eq!(res.status, 412);

    // 7. PUT with If-None-Match: * on new key -> 200 OK
    let res = req(
        &client,
        "PUT",
        &base,
        "/cond-bucket/new-file.txt",
        b"Fresh Content",
        &[("if-none-match", "*")],
    );
    assert_eq!(res.status, 200);

    // 8. Range with matching If-Range -> 206 Partial Content
    let res = req(
        &client,
        "GET",
        &base,
        "/cond-bucket/file.txt",
        b"",
        &[("range", "bytes=0-4"), ("if-range", &etag)],
    );
    assert_eq!(res.status, 206);
    assert_eq!(res.body, b"Hello");
    assert_eq!(
        res.headers.get("content-range").unwrap().to_str().unwrap(),
        "bytes 0-4/32"
    );

    // 9. Range with mismatched If-Range -> 200 OK (returns full object, ignores range)
    let res = req(
        &client,
        "GET",
        &base,
        "/cond-bucket/file.txt",
        b"",
        &[("range", "bytes=0-4"), ("if-range", "\"different-etag\"")],
    );
    assert_eq!(res.status, 200);
    assert_eq!(res.body, body_data);

    // 10. CopyObject with mismatched x-amz-copy-source-if-match -> 412 PreconditionFailed
    let res = req(
        &client,
        "PUT",
        &base,
        "/cond-bucket/copied.txt",
        b"",
        &[
            ("x-amz-copy-source", "/cond-bucket/file.txt"),
            ("x-amz-copy-source-if-match", "\"bad-etag\""),
        ],
    );
    assert_eq!(res.status, 412);
}

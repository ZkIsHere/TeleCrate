//! Integration M3.3: CopyObject, User Metadata & System Headers via HTTP.

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
    for (k, v) in extra {
        headers.push((k.to_string(), v.to_string()));
    }
    let signed = ["host", "x-amz-content-sha256", "x-amz-date"];
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
fn put_and_get_user_system_metadata() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();
    let bucket = "meta-bucket";

    // CreateBucket
    let r = req(&client, "PUT", &base, &format!("/{bucket}"), b"", &[]);
    assert_eq!(r.status, 200);

    // PUT object with x-amz-meta-author and Cache-Control headers
    let payload = b"hello metadata world";
    let extra_headers = [
        ("x-amz-meta-author", "alice"),
        ("x-amz-meta-project", "telecrate"),
        ("cache-control", "max-age=3600"),
        ("content-disposition", "inline; filename=\"hello.txt\""),
    ];
    let r_put = req(
        &client,
        "PUT",
        &base,
        &format!("/{bucket}/doc.txt"),
        payload,
        &extra_headers,
    );
    assert_eq!(r_put.status, 200);

    // HEAD object -> verify user and system metadata returned in headers
    let r_head = req(
        &client,
        "HEAD",
        &base,
        &format!("/{bucket}/doc.txt"),
        b"",
        &[],
    );
    assert_eq!(r_head.status, 200);
    assert_eq!(
        r_head
            .headers
            .get("x-amz-meta-author")
            .unwrap()
            .to_str()
            .unwrap(),
        "alice"
    );
    assert_eq!(
        r_head
            .headers
            .get("x-amz-meta-project")
            .unwrap()
            .to_str()
            .unwrap(),
        "telecrate"
    );
    assert_eq!(
        r_head
            .headers
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "max-age=3600"
    );

    // GET object -> verify metadata headers and body content
    let r_get = req(
        &client,
        "GET",
        &base,
        &format!("/{bucket}/doc.txt"),
        b"",
        &[],
    );
    assert_eq!(r_get.status, 200);
    assert_eq!(r_get.body, payload);
    assert_eq!(
        r_get
            .headers
            .get("x-amz-meta-author")
            .unwrap()
            .to_str()
            .unwrap(),
        "alice"
    );
}

#[test]
fn copy_object_default_and_replace_metadata() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();
    let bucket = "copy-bucket";

    // CreateBucket
    req(&client, "PUT", &base, &format!("/{bucket}"), b"", &[]);

    // PUT source object
    let payload = b"content to copy";
    req(
        &client,
        "PUT",
        &base,
        &format!("/{bucket}/src.txt"),
        payload,
        &[("x-amz-meta-orig", "src-val")],
    );

    // CopyObject (COPY metadata directive)
    let copy_header = format!("/{bucket}/src.txt");
    let r_copy = req(
        &client,
        "PUT",
        &base,
        &format!("/{bucket}/copy-default.txt"),
        b"",
        &[("x-amz-copy-source", &copy_header)],
    );
    assert_eq!(r_copy.status, 200);
    let xml = String::from_utf8(r_copy.body).unwrap();
    assert!(xml.contains("CopyObjectResult"));

    // GET copy-default.txt -> verify copied content & metadata
    let r_get = req(
        &client,
        "GET",
        &base,
        &format!("/{bucket}/copy-default.txt"),
        b"",
        &[],
    );
    assert_eq!(r_get.status, 200);
    assert_eq!(r_get.body, payload);
    assert_eq!(
        r_get
            .headers
            .get("x-amz-meta-orig")
            .unwrap()
            .to_str()
            .unwrap(),
        "src-val"
    );

    // CopyObject with REPLACE metadata directive
    let r_copy_replace = req(
        &client,
        "PUT",
        &base,
        &format!("/{bucket}/copy-replace.txt"),
        b"",
        &[
            ("x-amz-copy-source", &copy_header),
            ("x-amz-metadata-directive", "REPLACE"),
            ("x-amz-meta-newkey", "new-val"),
        ],
    );
    assert_eq!(r_copy_replace.status, 200);

    // GET copy-replace.txt -> verify new metadata and content
    let r_get_rep = req(
        &client,
        "GET",
        &base,
        &format!("/{bucket}/copy-replace.txt"),
        b"",
        &[],
    );
    assert_eq!(r_get_rep.status, 200);
    assert_eq!(r_get_rep.body, payload);
    assert_eq!(
        r_get_rep
            .headers
            .get("x-amz-meta-newkey")
            .unwrap()
            .to_str()
            .unwrap(),
        "new-val"
    );
    assert!(r_get_rep.headers.get("x-amz-meta-orig").is_none());
}

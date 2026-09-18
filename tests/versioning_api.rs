//! Integration M3.5: Object Versioning & Delete Markers via HTTP API.

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
fn test_bucket_and_object_versioning_lifecycle() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();

    // 1. Create bucket
    let res = req(&client, "PUT", &base, "/v-bucket", b"", &[]);
    assert_eq!(res.status, 200);

    // 2. Check initial versioning status (Disabled)
    let res = req(&client, "GET", &base, "/v-bucket?versioning", b"", &[]);
    assert_eq!(res.status, 200);
    let body_xml = String::from_utf8(res.body).unwrap();
    assert!(!body_xml.contains("<Status>Enabled</Status>"));

    // 3. Enable bucket versioning
    let versioning_xml = br#"<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>"#;
    let res = req(
        &client,
        "PUT",
        &base,
        "/v-bucket?versioning",
        versioning_xml,
        &[],
    );
    assert_eq!(res.status, 200);

    // 4. Verify versioning status is Enabled
    let res = req(&client, "GET", &base, "/v-bucket?versioning", b"", &[]);
    assert_eq!(res.status, 200);
    let body_xml = String::from_utf8(res.body).unwrap();
    assert!(body_xml.contains("<Status>Enabled</Status>"));

    // 5. PUT Version 1 of object
    let v1_data = b"Version 1 Content";
    let res = req(&client, "PUT", &base, "/v-bucket/item.txt", v1_data, &[]);
    assert_eq!(res.status, 200);
    let vid1 = res
        .headers
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(!vid1.is_empty() && vid1 != "null");

    // 6. PUT Version 2 of object
    let v2_data = b"Version 2 Content (Newer)";
    let res = req(&client, "PUT", &base, "/v-bucket/item.txt", v2_data, &[]);
    assert_eq!(res.status, 200);
    let vid2 = res
        .headers
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(!vid2.is_empty() && vid2 != "null");
    assert_ne!(vid1, vid2);

    // 7. GET latest (should return v2)
    let res = req(&client, "GET", &base, "/v-bucket/item.txt", b"", &[]);
    assert_eq!(res.status, 200);
    assert_eq!(res.body, v2_data);
    assert_eq!(
        res.headers
            .get("x-amz-version-id")
            .unwrap()
            .to_str()
            .unwrap(),
        vid2
    );

    // 8. GET explicit version 1 (should return v1)
    let res = req(
        &client,
        "GET",
        &base,
        &format!("/v-bucket/item.txt?versionId={vid1}"),
        b"",
        &[],
    );
    assert_eq!(res.status, 200);
    assert_eq!(res.body, v1_data);
    assert_eq!(
        res.headers
            .get("x-amz-version-id")
            .unwrap()
            .to_str()
            .unwrap(),
        vid1
    );

    // 9. DELETE /v-bucket/item.txt (creates Delete Marker)
    let res = req(&client, "DELETE", &base, "/v-bucket/item.txt", b"", &[]);
    assert_eq!(res.status, 204);
    assert_eq!(
        res.headers
            .get("x-amz-delete-marker")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
    let dm_vid = res
        .headers
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(!dm_vid.is_empty());

    // 10. GET latest now returns 404 with x-amz-delete-marker: true
    let res = req(&client, "GET", &base, "/v-bucket/item.txt", b"", &[]);
    assert_eq!(res.status, 404);
    assert_eq!(
        res.headers
            .get("x-amz-delete-marker")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );

    // 11. ListObjectVersions
    let res = req(&client, "GET", &base, "/v-bucket?versions", b"", &[]);
    assert_eq!(res.status, 200);
    let versions_xml = String::from_utf8(res.body).unwrap();
    assert!(versions_xml.contains("<DeleteMarker>"));
    assert!(versions_xml.contains(&format!("<VersionId>{dm_vid}</VersionId>")));
    assert!(versions_xml.contains(&format!("<VersionId>{vid2}</VersionId>")));
    assert!(versions_xml.contains(&format!("<VersionId>{vid1}</VersionId>")));

    // 12. Versioned DELETE of Delete Marker (restores v2 as latest!)
    let res = req(
        &client,
        "DELETE",
        &base,
        &format!("/v-bucket/item.txt?versionId={dm_vid}"),
        b"",
        &[],
    );
    assert_eq!(res.status, 204);
    assert_eq!(
        res.headers
            .get("x-amz-delete-marker")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );

    // 13. GET latest now returns v2 again!
    let res = req(&client, "GET", &base, "/v-bucket/item.txt", b"", &[]);
    assert_eq!(res.status, 200);
    assert_eq!(res.body, v2_data);
    assert_eq!(
        res.headers
            .get("x-amz-version-id")
            .unwrap()
            .to_str()
            .unwrap(),
        vid2
    );

    // 14. Versioned DELETE of v2 (restores v1 as latest!)
    let res = req(
        &client,
        "DELETE",
        &base,
        &format!("/v-bucket/item.txt?versionId={vid2}"),
        b"",
        &[],
    );
    assert_eq!(res.status, 204);

    let res = req(&client, "GET", &base, "/v-bucket/item.txt", b"", &[]);
    assert_eq!(res.status, 200);
    assert_eq!(res.body, v1_data);
    assert_eq!(
        res.headers
            .get("x-amz-version-id")
            .unwrap()
            .to_str()
            .unwrap(),
        vid1
    );
}

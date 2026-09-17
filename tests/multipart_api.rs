//! Integration M3.2: S3 Multipart Upload API (6 endpoints qua HTTP ký SigV4 thật).

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
fn multipart_upload_full_lifecycle() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();
    let bucket = "mp-bucket";

    // 1) CreateBucket
    let r = req(&client, "PUT", &base, &format!("/{bucket}"), b"", &[]);
    assert_eq!(r.status, 200);

    // 2) InitiateMultipartUpload (POST /{bucket}/large.bin?uploads)
    let r = req(
        &client,
        "POST",
        &base,
        &format!("/{bucket}/large.bin?uploads"),
        b"",
        &[],
    );
    assert_eq!(r.status, 200);
    let body_xml = String::from_utf8(r.body).unwrap();
    assert!(body_xml.contains("InitiateMultipartUploadResult"));

    // Extract UploadId
    let upload_id = body_xml
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();
    assert!(!upload_id.is_empty());

    // 3) ListMultipartUploads (GET /{bucket}?uploads)
    let r = req(
        &client,
        "GET",
        &base,
        &format!("/{bucket}?uploads"),
        b"",
        &[],
    );
    assert_eq!(r.status, 200);
    let list_mp_xml = String::from_utf8(r.body).unwrap();
    assert!(list_mp_xml.contains(&upload_id));

    // 4) UploadPart 1 (PUT /{bucket}/large.bin?partNumber=1&uploadId={upload_id})
    let part1_data = vec![b'A'; 1024 * 1024]; // 1 MiB
    let r1 = req(
        &client,
        "PUT",
        &base,
        &format!("/{bucket}/large.bin?partNumber=1&uploadId={upload_id}"),
        &part1_data,
        &[],
    );
    assert_eq!(r1.status, 200);
    let etag1 = r1
        .headers
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(etag1.starts_with('"') && etag1.ends_with('"'));

    // 5) UploadPart 2 (PUT /{bucket}/large.bin?partNumber=2&uploadId={upload_id})
    let part2_data = vec![b'B'; 512 * 1024]; // 512 KiB
    let r2 = req(
        &client,
        "PUT",
        &base,
        &format!("/{bucket}/large.bin?partNumber=2&uploadId={upload_id}"),
        &part2_data,
        &[],
    );
    assert_eq!(r2.status, 200);
    let etag2 = r2
        .headers
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // 6) ListParts (GET /{bucket}/large.bin?uploadId={upload_id})
    let r_list = req(
        &client,
        "GET",
        &base,
        &format!("/{bucket}/large.bin?uploadId={upload_id}"),
        b"",
        &[],
    );
    assert_eq!(r_list.status, 200);
    let parts_xml = String::from_utf8(r_list.body).unwrap();
    assert!(parts_xml.contains("<PartNumber>1</PartNumber>"));
    assert!(parts_xml.contains("<PartNumber>2</PartNumber>"));

    // 7) CompleteMultipartUpload (POST /{bucket}/large.bin?uploadId={upload_id})
    let complete_xml_body = format!(
        r#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part></CompleteMultipartUpload>"#
    );
    let r_comp = req(
        &client,
        "POST",
        &base,
        &format!("/{bucket}/large.bin?uploadId={upload_id}"),
        complete_xml_body.as_bytes(),
        &[],
    );
    assert_eq!(r_comp.status, 200);
    let complete_res_xml = String::from_utf8(r_comp.body).unwrap();
    assert!(complete_res_xml.contains("CompleteMultipartUploadResult"));

    // 8) GetObject (GET /{bucket}/large.bin) -> verify content byte-for-byte!
    let r_get = req(
        &client,
        "GET",
        &base,
        &format!("/{bucket}/large.bin"),
        b"",
        &[],
    );
    assert_eq!(r_get.status, 200);

    let mut expected_bytes = vec![b'A'; 1024 * 1024];
    expected_bytes.extend_from_slice(&vec![b'B'; 512 * 1024]);
    assert_eq!(r_get.body, expected_bytes);
}

#[test]
fn multipart_upload_abort_flow() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();
    let bucket = "abort-bucket";

    // CreateBucket
    let r = req(&client, "PUT", &base, &format!("/{bucket}"), b"", &[]);
    assert_eq!(r.status, 200);

    // Initiate
    let r = req(
        &client,
        "POST",
        &base,
        &format!("/{bucket}/abort.bin?uploads"),
        b"",
        &[],
    );
    assert_eq!(r.status, 200);
    let body_xml = String::from_utf8(r.body).unwrap();
    let upload_id = body_xml
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    // Upload part 1
    let r_part = req(
        &client,
        "PUT",
        &base,
        &format!("/{bucket}/abort.bin?partNumber=1&uploadId={upload_id}"),
        b"hello world",
        &[],
    );
    assert_eq!(r_part.status, 200);

    // Abort (DELETE /{bucket}/abort.bin?uploadId={upload_id})
    let r_abort = req(
        &client,
        "DELETE",
        &base,
        &format!("/{bucket}/abort.bin?uploadId={upload_id}"),
        b"",
        &[],
    );
    assert_eq!(r_abort.status, 204);

    // Verify ListParts returns 404 NoSuchUpload
    let r_list = req(
        &client,
        "GET",
        &base,
        &format!("/{bucket}/abort.bin?uploadId={upload_id}"),
        b"",
        &[],
    );
    assert_eq!(r_list.status, 404);
}

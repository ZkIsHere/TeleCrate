//! Integration M2.2: object lifecycle qua HTTP thật (không cần secrets).
//! Worker + Telegram thật được verify ở live e2e thủ công (xem telegram-capability.md).

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
        // Chunk nhỏ để kiểm multi-chunk trong integration (mặc định production 8 MiB).
        chunk_size_bytes: 1024 * 1024,
        ..Default::default()
    };
    std::fs::create_dir_all(&cfg.spool_dir).unwrap();
    let mut conn = telecrate::db::open(&cfg.db_path).unwrap();
    telecrate::db::apply_all_migrations(&mut conn).unwrap();
    drop(conn);

    let (tx, rx) = mpsc::channel();
    // Router dựng ngoài async context; test này không cấu hình telegram → transport None.
    let app = telecrate::app::router(cfg, None, telecrate::crypto::KeyStore::default());
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

fn md5_hex(b: &[u8]) -> String {
    format!("{:x}", md5::compute(b))
}

struct Resp {
    status: u16,
    body: Vec<u8>,
    headers: reqwest::header::HeaderMap,
}

#[allow(clippy::too_many_arguments)]
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
    let resp = r.body(body.to_vec()).send().unwrap();
    Resp {
        status: resp.status().as_u16(),
        headers: resp.headers().clone(),
        body: resp.bytes().unwrap().to_vec(),
    }
}

fn text(r: &Resp) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn mkbucket(client: &reqwest::blocking::Client, base: &str, name: &str) {
    let r = req(client, "PUT", base, &format!("/{name}"), b"", &[]);
    assert_eq!(r.status, 200, "mkbucket {}", text(&r));
}

#[test]
fn object_put_get_head_delete_roundtrip() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();
    mkbucket(&client, &base, "obj-bkt");

    let data = b"hello-telecrate-object".to_vec();
    let r = req(
        &client,
        "PUT",
        &base,
        "/obj-bkt/a/b.txt",
        &data,
        &[("content-type", "text/plain")],
    );
    assert_eq!(r.status, 200, "{}", text(&r));
    assert_eq!(
        r.headers.get("etag").unwrap().to_str().unwrap(),
        format!("\"{}\"", md5_hex(&data)),
        "headers: {:?}",
        r.headers
    );

    // GET byte-identical + headers.
    let r = req(&client, "GET", &base, "/obj-bkt/a/b.txt", b"", &[]);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, data);
    assert_eq!(
        r.headers.get("etag").unwrap().to_str().unwrap(),
        format!("\"{}\"", md5_hex(&data))
    );
    assert_eq!(
        r.headers.get("content-type").unwrap().to_str().unwrap(),
        "text/plain"
    );
    assert!(r.headers.contains_key("last-modified"));
    assert!(r.headers.contains_key("x-amz-request-id"));

    // HEAD như GET nhưng không body.
    let r = req(&client, "HEAD", &base, "/obj-bkt/a/b.txt", b"", &[]);
    assert_eq!(r.status, 200);
    assert!(r.body.is_empty());
    assert_eq!(
        r.headers.get("content-length").unwrap().to_str().unwrap(),
        data.len().to_string()
    );

    // Range đơn.
    let r = req(
        &client,
        "GET",
        &base,
        "/obj-bkt/a/b.txt",
        b"",
        &[("range", "bytes=0-4")],
    );
    assert_eq!(r.status, 206);
    assert_eq!(r.body, b"hello");
    assert_eq!(
        r.headers.get("content-range").unwrap().to_str().unwrap(),
        format!("bytes 0-4/{}", data.len())
    );
    let r = req(
        &client,
        "GET",
        &base,
        "/obj-bkt/a/b.txt",
        b"",
        &[("range", "bytes=-5")],
    );
    assert_eq!(r.status, 206);
    assert_eq!(r.body, b"bject");
    // Range vô lý → 416.
    let r = req(
        &client,
        "GET",
        &base,
        "/obj-bkt/a/b.txt",
        b"",
        &[("range", "bytes=999999-")],
    );
    assert_eq!(r.status, 416, "{}", text(&r));

    // Ghi đè thấy ngay.
    let r = req(&client, "PUT", &base, "/obj-bkt/a/b.txt", b"v2", &[]);
    assert_eq!(r.status, 200);
    let r = req(&client, "GET", &base, "/obj-bkt/a/b.txt", b"", &[]);
    assert_eq!(r.body, b"v2");

    // DELETE idempotent + GET sau xóa → 404.
    let r = req(&client, "DELETE", &base, "/obj-bkt/a/b.txt", b"", &[]);
    assert_eq!(r.status, 204);
    let r = req(&client, "GET", &base, "/obj-bkt/a/b.txt", b"", &[]);
    assert_eq!(r.status, 404);
    assert!(text(&r).contains("NoSuchKey"));
    let r = req(&client, "DELETE", &base, "/obj-bkt/a/b.txt", b"", &[]);
    assert_eq!(r.status, 204);

    // Bucket mất → 404 NoSuchBucket/NoSuchKey đúng mã.
    let r = req(&client, "GET", &base, "/ghost/k", b"", &[]);
    assert_eq!(r.status, 404);
    assert!(text(&r).contains("NoSuchBucket"));
    let r = req(&client, "PUT", &base, "/ghost/k", b"x", &[]);
    assert_eq!(r.status, 404);
}

#[test]
fn object_edge_cases_empty_unicode_special() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();
    mkbucket(&client, &base, "edge");

    // Object rỗng.
    let r = req(&client, "PUT", &base, "/edge/empty", b"", &[]);
    assert_eq!(r.status, 200);
    let r = req(&client, "GET", &base, "/edge/empty", b"", &[]);
    assert_eq!(r.status, 200);
    assert!(r.body.is_empty());

    // Unicode + ký tự đặc biệt (client percent-encode path).
    let key = "cà-phê/a b+100%.txt";
    let enc: String = key
        .as_bytes()
        .iter()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
                (*b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let r = req(&client, "PUT", &base, &format!("/edge/{enc}"), b"uni", &[]);
    assert_eq!(r.status, 200, "{}", text(&r));
    let r = req(&client, "GET", &base, &format!("/edge/{enc}"), b"", &[]);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"uni");

    // Quá giới hạn object (128 MiB) → EntityTooLarge trước khi ghi spool.
    let big = vec![0u8; 129 * 1024 * 1024];
    let r = req(&client, "PUT", &base, "/edge/big", &big, &[]);
    assert_eq!(r.status, 400);
    assert!(text(&r).contains("EntityTooLarge"));
}

#[test]
fn multichunk_roundtrip_and_range_spanning_boundary() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();
    mkbucket(&client, &base, "multi-chunk");

    // 2.5 MiB với chunk 1 MiB → 3 chunks.
    let data: Vec<u8> = (0u32..2_621_440)
        .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
        .collect();
    let r = req(&client, "PUT", &base, "/multi-chunk/big.bin", &data, &[]);
    assert_eq!(r.status, 200, "{}", text(&r));

    // GET ráp đủ 3 chunks, byte-identical.
    let r = req(&client, "GET", &base, "/multi-chunk/big.bin", b"", &[]);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, data);

    // Range cắt ngang biên chunk (1 MiB - 5 .. 1 MiB + 5).
    let a = 1024 * 1024 - 5;
    let b = 1024 * 1024 + 5;
    let range = format!("bytes={a}-{b}");
    let r = req(
        &client,
        "GET",
        &base,
        "/multi-chunk/big.bin",
        b"",
        &[("range", range.as_str())],
    );
    assert_eq!(r.status, 206);
    assert_eq!(r.body, data[a..=b]);
}

#[test]
fn list_v2_prefix_delimiter_pagination() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();
    mkbucket(&client, &base, "lst");
    for k in ["a/1", "a/2", "a/b/3", "c", "d"] {
        let r = req(&client, "PUT", &base, &format!("/lst/{k}"), b"x", &[]);
        assert_eq!(r.status, 200);
    }

    // Prefix + delimiter → CommonPrefixes.
    let r = req(
        &client,
        "GET",
        &base,
        "/lst?list-type=2&prefix=a/&delimiter=/",
        b"",
        &[],
    );
    assert_eq!(r.status, 200);
    let t = text(&r);
    assert!(t.contains("<Key>a/1</Key>"), "{t}");
    assert!(t.contains("<Key>a/2</Key>"), "{t}");
    assert!(t.contains("<Prefix>a/b/</Prefix>"), "{t}");
    assert!(!t.contains("<Key>a/b/3</Key>"), "{t}");

    // encoding-type=url (AWS CLI mặc định).
    let r = req(
        &client,
        "GET",
        &base,
        "/lst?list-type=2&prefix=a%2F&encoding-type=url",
        b"",
        &[],
    );
    assert_eq!(r.status, 200);
    let t = text(&r);
    assert!(t.contains("<EncodingType>url</EncodingType>"), "{t}");
    assert!(t.contains("<Key>a%2F1</Key>"), "{t}");

    // Pagination max-keys=2.
    let r = req(
        &client,
        "GET",
        &base,
        "/lst?list-type=2&max-keys=2",
        b"",
        &[],
    );
    assert_eq!(r.status, 200);
    let t = text(&r);
    assert!(t.contains("<IsTruncated>true</IsTruncated>"), "{t}");
    assert!(t.contains("<NextContinuationToken>"), "{t}");
    let token = t
        .split("<NextContinuationToken>")
        .nth(1)
        .unwrap()
        .split("</NextContinuationToken>")
        .next()
        .unwrap()
        .to_string();
    let r = req(
        &client,
        "GET",
        &base,
        &format!("/lst?list-type=2&max-keys=2&continuation-token={token}"),
        b"",
        &[],
    );
    assert_eq!(r.status, 200);
    let t2 = text(&r);
    assert!(
        t2.contains("<Key>c</Key>") || t2.contains("<Key>d</Key>"),
        "{t2}"
    );
}

#[test]
fn delete_objects_batch() {
    let (_dir, base) = spawn_server();
    let client = reqwest::blocking::Client::new();
    mkbucket(&client, &base, "multi");
    for k in ["k1", "k2", "k3"] {
        let r = req(&client, "PUT", &base, &format!("/multi/{k}"), b"x", &[]);
        assert_eq!(r.status, 200);
    }
    let xml = "<Delete><Object><Key>k1</Key></Object><Object><Key>k2</Key></Object><Object><Key>ghost</Key></Object></Delete>";
    let r = req(&client, "POST", &base, "/multi?delete", xml.as_bytes(), &[]);
    assert_eq!(r.status, 200);
    let t = text(&r);
    assert!(
        t.contains("<Key>k1</Key>") && t.contains("<Key>ghost</Key>"),
        "{t}"
    );
    // Quiet → không liệt kê Deleted.
    let xml = "<Delete><Quiet>true</Quiet><Object><Key>k3</Key></Object></Delete>";
    let r = req(&client, "POST", &base, "/multi?delete", xml.as_bytes(), &[]);
    assert_eq!(r.status, 200);
    assert!(!text(&r).contains("<Deleted>"), "{}", text(&r));
    // VersionId → 400 rõ ràng (M2.2 chưa versioning).
    let xml = "<Delete><Object><Key>k1</Key><VersionId>v</VersionId></Object></Delete>";
    let r = req(&client, "POST", &base, "/multi?delete", xml.as_bytes(), &[]);
    assert_eq!(r.status, 400);
    // Bucket rỗng sau batch → xóa bucket được (204).
    let r = req(&client, "DELETE", &base, "/multi", b"", &[]);
    assert_eq!(r.status, 204);
}

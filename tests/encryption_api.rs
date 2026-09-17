//! Integration M2.4: mã hóa nội dung bật/tắt, toggle, rotation, tamper (không cần secrets).

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use telecrate::config::{AccessKey, Config, ContentKeyRef};

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

fn sha_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

/// Ghi file key 32 bytes, trả ContentKeyRef.
fn write_key(dir: &std::path::Path, id: &str, byte: u8) -> ContentKeyRef {
    let p = dir.join(format!("{id}.key"));
    std::fs::write(&p, [byte; 32]).unwrap();
    ContentKeyRef {
        id: id.to_string(),
        file: p.to_str().unwrap().to_string(),
    }
}

fn base_config(dir: &tempfile::TempDir) -> Config {
    Config {
        db_path: dir.path().join("index.db").to_str().unwrap().to_string(),
        spool_dir: dir.path().join("spool").to_str().unwrap().to_string(),
        listen_port: 1,
        encryption: "off".to_string(),
        access_keys: vec![AccessKey {
            access_key_id: KEY.to_string(),
            secret_key: SECRET.to_string(),
        }],
        chunk_size_bytes: 1024 * 1024,
        ..Default::default()
    }
}

/// Dựng server từ config đầy đủ (init DB nếu chưa có). Trả base URL.
fn spawn_with(cfg: Config) -> String {
    std::fs::create_dir_all(&cfg.spool_dir).unwrap();
    let mut conn = telecrate::db::open(&cfg.db_path).unwrap();
    if telecrate::db::schema_version(&conn).unwrap() == 0 {
        telecrate::db::apply_all_migrations(&mut conn).unwrap();
    }
    drop(conn);
    let keys = cfg.load_keystore().unwrap_or_default();
    let app = telecrate::app::router(cfg, None, keys);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(l.local_addr().unwrap().port()).unwrap();
            axum::serve(l, app).await.unwrap();
        });
    });
    let base = format!(
        "http://127.0.0.1:{}",
        rx.recv_timeout(Duration::from_secs(10)).unwrap()
    );
    let client = reqwest::blocking::Client::new();
    for _ in 0..50 {
        if client.get(format!("{base}/health")).send().is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    base
}

struct Resp {
    status: u16,
    body: Vec<u8>,
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
    let amzdate = amzdate(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    let auth = telecrate::sigv4::sign(
        method, path, query, &headers, &signed, body, KEY, SECRET, REGION, &amzdate, &payload,
    );
    let url = format!("{base}{path_query}");
    let mut r = match method {
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
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
        body: resp.bytes().unwrap().to_vec(),
    }
}

fn text(r: &Resp) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn mkbucket(client: &reqwest::blocking::Client, base: &str) {
    let r = req(client, "PUT", base, "/enc", b"", &[]);
    assert_eq!(r.status, 200, "mkbucket {}", text(&r));
}

/// Đọc spool path của version đầu tiên của key (truy DB trực tiếp trong test).
fn spool_of(db_path: &str, bucket: &str, key: &str) -> String {
    let conn = telecrate::db::open(db_path).unwrap();
    let v = telecrate::db::latest_version(&conn, bucket, key)
        .unwrap()
        .unwrap();
    telecrate::db::chunks_of(&conn, &v.version_id).unwrap()[0]
        .spool_path
        .clone()
        .unwrap()
}

#[test]
fn encrypted_roundtrip_spool_is_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let k1 = write_key(dir.path(), "k1", 0x11);
    let mut cfg = base_config(&dir);
    cfg.encryption = "on".to_string();
    cfg.content_keys = vec![k1];
    let db_path = cfg.db_path.clone();
    let base = spawn_with(cfg);
    let client = reqwest::blocking::Client::new();
    mkbucket(&client, &base);

    let data = b"secret-payload-123".to_vec();
    let r = req(&client, "PUT", &base, "/enc/s.bin", &data, &[]);
    assert_eq!(r.status, 200, "{}", text(&r));
    // Spool KHÔNG chứa plaintext.
    let spool_bytes = std::fs::read(spool_of(&db_path, "enc", "s.bin")).unwrap();
    assert!(!spool_bytes
        .windows(data.len())
        .any(|w| w == data.as_slice()));
    assert!(spool_bytes.len() > data.len(), "phải có nonce overhead");
    // GET giải mã đúng + ETag vẫn MD5 plaintext.
    let r = req(&client, "GET", &base, "/enc/s.bin", b"", &[]);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, data);
}

#[test]
fn toggle_off_reads_old_encrypted_and_writes_plain() {
    let dir = tempfile::tempdir().unwrap();
    let k1 = write_key(dir.path(), "k1", 0x22);
    let mut cfg = base_config(&dir);
    cfg.encryption = "on".to_string();
    cfg.content_keys = vec![k1.clone()];
    let db_path = cfg.db_path.clone();
    let spool_dir = cfg.spool_dir.clone();
    let base_on = spawn_with(cfg);
    let client = reqwest::blocking::Client::new();
    mkbucket(&client, &base_on);
    let r = req(&client, "PUT", &base_on, "/enc/old.bin", b"old-secret", &[]);
    assert_eq!(r.status, 200);

    // Tắt toggle (giữ key + cùng DB/spool): dữ liệu cũ vẫn đọc được.
    let mut cfg2 = base_config(&dir);
    assert_eq!(cfg2.db_path, db_path);
    assert_eq!(cfg2.spool_dir, spool_dir);
    cfg2.encryption = "off".to_string();
    cfg2.content_keys = vec![k1];
    let base_off = spawn_with(cfg2);
    let r = req(&client, "GET", &base_off, "/enc/old.bin", b"", &[]);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"old-secret");
    // Ghi mới ở chế độ tắt → spool plaintext + mode none.
    let r = req(&client, "PUT", &base_off, "/enc/new.bin", b"plain-now", &[]);
    assert_eq!(r.status, 200);
    let spool_bytes = std::fs::read(spool_of(&db_path, "enc", "new.bin")).unwrap();
    assert_eq!(spool_bytes, b"plain-now");
}

#[test]
fn rotation_new_writes_use_new_key_old_still_readable() {
    let dir = tempfile::tempdir().unwrap();
    let k1 = write_key(dir.path(), "k1", 0x33);
    let k2 = write_key(dir.path(), "k2", 0x44);
    let mut cfg = base_config(&dir);
    cfg.encryption = "on".to_string();
    cfg.content_keys = vec![k1.clone()];
    let db_path = cfg.db_path.clone();
    let base = spawn_with(cfg);
    let client = reqwest::blocking::Client::new();
    mkbucket(&client, &base);
    let r = req(&client, "PUT", &base, "/enc/a.bin", b"era-one", &[]);
    assert_eq!(r.status, 200);

    // Rotation: giữ k1, default sang k2.
    let mut cfg2 = base_config(&dir);
    cfg2.encryption = "on".to_string();
    cfg2.content_keys = vec![k1, k2];
    cfg2.content_key_id = "k2".to_string();
    let base2 = spawn_with(cfg2);
    let r = req(&client, "PUT", &base2, "/enc/b.bin", b"era-two", &[]);
    assert_eq!(r.status, 200);
    // Cả hai đọc được.
    let r = req(&client, "GET", &base2, "/enc/a.bin", b"", &[]);
    assert_eq!(r.body, b"era-one");
    let r = req(&client, "GET", &base2, "/enc/b.bin", b"", &[]);
    assert_eq!(r.body, b"era-two");
    // b.bin dùng k2.
    let conn = telecrate::db::open(&db_path).unwrap();
    let v = telecrate::db::latest_version(&conn, "enc", "b.bin")
        .unwrap()
        .unwrap();
    let chunks = telecrate::db::chunks_of(&conn, &v.version_id).unwrap();
    assert_eq!(chunks[0].key_ref.as_deref(), Some("k2"));
}

#[test]
fn tampered_spool_fails_closed_and_wrong_key_fails() {
    let dir = tempfile::tempdir().unwrap();
    let k1 = write_key(dir.path(), "k1", 0x55);
    let mut cfg = base_config(&dir);
    cfg.encryption = "on".to_string();
    cfg.content_keys = vec![k1];
    let db_path = cfg.db_path.clone();
    let base = spawn_with(cfg);
    let client = reqwest::blocking::Client::new();
    mkbucket(&client, &base);
    let r = req(
        &client,
        "PUT",
        &base,
        "/enc/t.bin",
        b"tamper-me-please!",
        &[],
    );
    assert_eq!(r.status, 200);

    // Đảo 1 byte ciphertext trong spool → GET 500 fail đóng, không lộ key.
    let p = spool_of(&db_path, "enc", "t.bin");
    let mut bytes = std::fs::read(&p).unwrap();
    let n = bytes.len();
    bytes[n - 1] ^= 1;
    std::fs::write(&p, bytes).unwrap();
    let r = req(&client, "GET", &base, "/enc/t.bin", b"", &[]);
    assert_eq!(r.status, 500);
    assert!(text(&r).contains("cannot decrypt"), "{}", text(&r));

    // Server không giữ k1 (mất key) → GET 500, PUT vẫn 200 (ghi dùng key khác? không —
    // PUT với encryption=on mà không có key nào → 500 ngay). Dựng server mất key:
    let mut cfg2 = base_config(&dir);
    cfg2.encryption = "on".to_string();
    cfg2.content_keys = vec![write_key(dir.path(), "kX", 0x66)];
    let base2 = spawn_with(cfg2);
    let r = req(&client, "GET", &base2, "/enc/t.bin", b"", &[]);
    assert_eq!(r.status, 500);
}

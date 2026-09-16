//! Live e2e M2.2: S3 PUT → worker thật → Telegram → GET (spool GC + remote fallback) → DELETE.
//! `#[ignore]`, chỉ chạy khi có secrets (local hoặc CI job live-telegram).
//! Mỗi run để lại 0 tin nhắn (DELETE dọn remote best-effort).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
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

fn sha_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

fn signed(
    client: &reqwest::blocking::Client,
    method: &str,
    base: &str,
    path_query: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> (u16, Vec<u8>) {
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
    (resp.status().as_u16(), resp.bytes().unwrap().to_vec())
}

#[test]
#[ignore]
fn live_s3_worker_telegram_e2e() {
    let (token, chat) = live_secrets();
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = live_config(&dir, &token, chat);
    // Chunk 1 MiB + payload 2.5 MiB → 3 messages thật, tự xóa cuối test.
    cfg.chunk_size_bytes = 1024 * 1024;
    run_e2e(cfg, &token, chat, 2_621_440, "live s3 e2e multi-chunk");
}

#[test]
#[ignore]
fn live_encrypted_e2e() {
    let (token, chat) = live_secrets();
    let dir = tempfile::tempdir().unwrap();
    // Key mã hóa thật (file tạm, 0600 mặc định của tempfile trên unix).
    let key_path = dir.path().join("live.key");
    std::fs::write(&key_path, [0xA5u8; 32]).unwrap();
    let mut cfg = live_config(&dir, &token, chat);
    cfg.encryption = "on".to_string();
    cfg.content_keys = vec![telecrate::config::ContentKeyRef {
        id: "live-k1".to_string(),
        file: key_path.to_str().unwrap().to_string(),
    }];
    cfg.chunk_size_bytes = 1024 * 1024;
    // 1.5 MiB → 2 chunks mã hóa thật trên Telegram, tự xóa cuối test.
    run_e2e(cfg, &token, chat, 1_572_864, "live encrypted e2e");
}

fn live_secrets() -> (String, i64) {
    let token =
        std::env::var("TELECRATE_BOT_TOKEN").expect("thiếu TELECRATE_BOT_TOKEN — unverified");
    let chat: i64 = std::env::var("TELECRATE_TEST_CHAT_ID")
        .expect("thiếu TELECRATE_TEST_CHAT_ID")
        .parse()
        .unwrap();
    (token, chat)
}

fn live_config(dir: &tempfile::TempDir, token: &str, chat: i64) -> Config {
    let db_path = dir.path().join("index.db");
    Config {
        db_path: db_path.to_str().unwrap().to_string(),
        spool_dir: dir.path().join("spool").to_str().unwrap().to_string(),
        listen_port: 1,
        encryption: "off".to_string(),
        region: REGION.to_string(),
        access_keys: vec![AccessKey {
            access_key_id: KEY.to_string(),
            secret_key: SECRET.to_string(),
        }],
        telegram_bot_token: token.to_string(),
        telegram_chat_id: chat,
        worker_concurrency: 2,
        ..Default::default()
    }
}

fn run_e2e(cfg: Config, token: &str, chat: i64, payload_len: u32, label: &str) {
    std::fs::create_dir_all(&cfg.spool_dir).unwrap();
    let mut conn = telecrate::db::open(&cfg.db_path).unwrap();
    telecrate::db::apply_all_migrations(&mut conn).unwrap();
    drop(conn);

    // Server HTTP — router dựng NGOÀI async context (transport blocking).
    let transport = telecrate::app::build_transport(&cfg);
    let keys = cfg.load_keystore().unwrap_or_default();
    let (tx, rx) = mpsc::channel();
    let cfg2 = cfg.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let app = telecrate::app::router(cfg2, transport, keys);
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

    // Worker thật với transport thật.
    let transport = telecrate::telegram::BotApiHttpTransport::hosted(token, "live-e2e").unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = shutdown.clone();
    let dbp = cfg.db_path.clone();
    thread::spawn(move || {
        telecrate::worker::run_loop(
            &dbp,
            &transport,
            chat,
            "live-e2e".to_string(),
            Duration::from_secs(1),
            sd,
        );
    });

    // PUT bucket + object.
    let (s, _) = signed(&client, "PUT", &base, "/live-bkt", b"", &[]);
    assert_eq!(s, 200);
    let data: Vec<u8> = (0u32..payload_len)
        .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
        .collect();
    let (s, _) = signed(&client, "PUT", &base, "/live-bkt/e2e.bin", &data, &[]);
    assert_eq!(s, 200);
    // GET ngay (spool, worker chưa chạy xong cũng được).
    let (s, body) = signed(&client, "GET", &base, "/live-bkt/e2e.bin", b"", &[]);
    assert_eq!(s, 200);
    assert_eq!(body, data);

    // Chờ worker commit remote (timeout 120s).
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let conn = telecrate::db::open(&cfg.db_path).unwrap();
        let st: String = conn
            .query_row("SELECT state FROM upload_jobs LIMIT 1", [], |r| r.get(0))
            .unwrap();
        if st == "done" || st == "failed" {
            assert_eq!(st, "done", "worker failed — xem last_error trong DB");
            break;
        }
        assert!(std::time::Instant::now() < deadline, "worker timeout");
        thread::sleep(Duration::from_secs(2));
    }
    // Spool đã GC.
    let spool_count = std::fs::read_dir(&cfg.spool_dir).unwrap().count();
    assert_eq!(spool_count, 0, "spool chưa dọn sau remote commit");
    // GET sau GC → đọc từ Telegram (remote fallback), byte-identical.
    let (s, body) = signed(&client, "GET", &base, "/live-bkt/e2e.bin", b"", &[]);
    assert_eq!(s, 200);
    assert_eq!(body, data);

    // DELETE dọn DB + spool + remote message (best-effort).
    let (s, _) = signed(&client, "DELETE", &base, "/live-bkt/e2e.bin", b"", &[]);
    assert_eq!(s, 204);
    let (s, _) = signed(&client, "DELETE", &base, "/live-bkt", b"", &[]);
    assert_eq!(s, 204);

    shutdown.store(true, Ordering::Relaxed);
    // Chỉ in trạng thái, không in locator/token.
    println!("{label}: put/get/worker-remote/get-after-gc/delete ok=true");
}

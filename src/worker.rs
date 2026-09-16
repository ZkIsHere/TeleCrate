//! Worker upload Telegram M2.2 (tối giản): poll → claim (lease) → upload → commit → GC spool.
//!
//! Không giữ transaction DB mở suốt network upload. Mỗi chunk: đọc spool → upload → txn ngắn
//! commit locator. Job dùng lease để nhiều worker không giành nhau (M2.2 chạy 1 worker;
//! lease/timeout bảo vệ khi process chết giữa chừng).

use rusqlite::Connection;

use crate::telegram::{RemoteLocator, Transport, TransportError};

/// Claim 1 job sẵn sàng bằng lease. Lấy job `pending` tới hạn, hoặc job `uploading`
/// mà lease đã hết (worker cũ chết giữa chừng — reclaim, chống kẹt hàng đợi).
fn claim_job(
    conn: &Connection,
    owner: &str,
    lease_secs: i64,
    now: &str,
) -> Result<Option<Claimed>, String> {
    let mut stmt = conn
        .prepare("SELECT job_id, version_id, retry_count FROM upload_jobs WHERE next_attempt <= ? AND ((state = 'pending') OR (state = 'uploading' AND lease_expires IS NOT NULL AND lease_expires <= ?)) ORDER BY next_attempt LIMIT 1")
        .map_err(|e| format!("poll prepare: {e}"))?;
    let mut rows = stmt
        .query(rusqlite::params![now, now])
        .map_err(|e| format!("poll: {e}"))?;
    let Some(row) = rows.next().map_err(|e| format!("poll row: {e}"))? else {
        return Ok(None);
    };
    let (job_id, version_id, retry_count): (String, String, i64) = (
        row.get(0).map_err(|e| format!("row: {e}"))?,
        row.get(1).map_err(|e| format!("row: {e}"))?,
        row.get(2).map_err(|e| format!("row: {e}"))?,
    );
    // Đóng cursor đọc trước khi ghi trên cùng connection (tránh giữ snapshot khi upgrade lock).
    drop(rows);
    drop(stmt);
    // Claim atomic: chỉ thắng khi job pending, hoặc uploading mà lease đã hết.
    // (Nếu khớp cả uploading còn lease, 2 worker sẽ xử lý trùng job.)
    let n = conn
        .execute(
            "UPDATE upload_jobs SET state = 'uploading', lease_owner = ?, lease_expires = datetime(?, ?) WHERE job_id = ? AND (state = 'pending' OR (state = 'uploading' AND (lease_expires IS NULL OR lease_expires <= ?)))",
            rusqlite::params![owner, now, format!("+{lease_secs} seconds"), job_id, now],
        )
        .map_err(|e| format!("claim: {e}"))?;
    if n == 0 {
        return Ok(None); // worker khác claim trước.
    }
    Ok(Some(Claimed {
        job_id,
        version_id,
        retry_count,
    }))
}

struct Claimed {
    job_id: String,
    version_id: String,
    retry_count: i64,
}

/// Xử lý 1 job đã claim: upload từng chunk pending → commit locator → xong job → GC spool.
/// Trả `true` nếu đã xử lý (để loop tiếp ngay), `false` nếu không có việc.
pub fn process_one_job(
    conn: &Connection,
    transport: &dyn Transport,
    chat_id: i64,
    spool_cleanup: bool,
    owner: &str,
    now: &str,
) -> Result<bool, String> {
    let Some(job) = claim_job(conn, owner, 300, now)? else {
        return Ok(false);
    };
    // Version còn tồn tại không (có thể đã bị DELETE sau khi job tạo)?
    let version_alive: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM objects WHERE version_id = ?",
            [&job.version_id],
            |r| r.get(0),
        )
        .map_err(|e| format!("version check: {e}"))?;
    if version_alive == 0 {
        finish_job(conn, &job.job_id, true)?;
        return Ok(true);
    }
    let chunks = crate::db::chunks_of(conn, &job.version_id)?;
    for c in &chunks {
        if c.state == "remote" {
            continue;
        }
        let spool = c
            .spool_path
            .clone()
            .ok_or_else(|| "chunk thiếu spool_path".to_string())?;
        let bytes = std::fs::read(&spool).map_err(|e| format!("read spool: {e}"))?;
        match transport.upload(chat_id, &bytes) {
            Ok(loc) => commit_chunk(conn, &job.version_id, c.idx, &loc)?,
            Err(e) => {
                fail_job(conn, &job, &e)?;
                return Ok(true);
            }
        }
    }
    finish_job(conn, &job.job_id, true)?;
    // GC spool: mọi chunk đã remote → xóa file local (best-effort từng file) + set spool_path = NULL trong DB.
    if spool_cleanup {
        for c in &chunks {
            if let Some(p) = &c.spool_path {
                let _ = std::fs::remove_file(p);
                let _ = conn.execute(
                    "UPDATE chunks SET spool_path = NULL WHERE version_id = ? AND idx = ?",
                    rusqlite::params![job.version_id, c.idx],
                );
            }
        }
    }
    Ok(true)
}

fn locator_json(loc: &RemoteLocator) -> String {
    serde_json::to_string(loc).unwrap_or_default()
}

/// Commit locator 1 chunk trong txn ngắn (không giữ txn qua network).
fn commit_chunk(
    conn: &Connection,
    version_id: &str,
    idx: i64,
    loc: &RemoteLocator,
) -> Result<(), String> {
    // Giữ spool_path để GC xóa file sau; read fallback sang Telegram khi file mất.
    conn.execute(
        "UPDATE chunks SET state = 'remote', remote_locator_json = ? WHERE version_id = ? AND idx = ?",
        rusqlite::params![locator_json(loc), version_id, idx],
    )
    .map_err(|e| format!("commit chunk: {e}"))?;
    Ok(())
}

fn finish_job(conn: &Connection, job_id: &str, done: bool) -> Result<(), String> {
    if done {
        if let Ok(v_id) = conn.query_row(
            "SELECT version_id FROM upload_jobs WHERE job_id = ?",
            [job_id],
            |r| r.get::<_, String>(0),
        ) {
            let _ = conn.execute(
                "UPDATE objects SET storage_state = 'remote' WHERE version_id = ?",
                [&v_id],
            );
        }
    }
    conn.execute(
        "UPDATE upload_jobs SET state = ?, lease_owner = NULL, lease_expires = NULL WHERE job_id = ?",
        rusqlite::params![if done { "done" } else { "pending" }, job_id],
    )
    .map_err(|e| format!("finish job: {e}"))?;
    Ok(())
}

fn fail_job(conn: &Connection, job: &Claimed, e: &TransportError) -> Result<(), String> {
    match e {
        TransportError::Transient {
            retry_after_secs, ..
        } => {
            // Backoff: max(retry_after, 30s * 2^retry, trần 1h).
            let backoff = retry_after_secs
                .unwrap_or(30)
                .max(30 << job.retry_count.min(6))
                .min(3600);
            conn.execute(
                "UPDATE upload_jobs SET state = 'pending', lease_owner = NULL, lease_expires = NULL, retry_count = retry_count + 1, next_attempt = datetime('now', ?), last_error = ? WHERE job_id = ?",
                rusqlite::params![format!("+{backoff} seconds"), format!("{e:?}"), job.job_id],
            )
            .map_err(|e| format!("fail job: {e}"))?;
        }
        TransportError::Permanent { .. } => {
            conn.execute(
                "UPDATE upload_jobs SET state = 'failed', lease_owner = NULL, lease_expires = NULL, last_error = ? WHERE job_id = ?",
                rusqlite::params![format!("{e:?}"), job.job_id],
            )
            .map_err(|e| format!("fail job: {e}"))?;
        }
    }
    Ok(())
}

/// Vòng lặp worker cho daemon: poll mỗi `interval`, xử lý tới khi hết việc.
/// Transport blocking → caller bọc `spawn_blocking` (ADR 0002).
pub fn run_loop(
    db_path: &str,
    transport: &dyn Transport,
    chat_id: i64,
    owner: String,
    interval: std::time::Duration,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    while !shutdown.load(Ordering::Relaxed) {
        let step = (|| -> Result<bool, String> {
            let conn = crate::db::open(db_path)?;
            let now: String = conn
                .query_row("SELECT datetime('now')", [], |r| r.get(0))
                .map_err(|e| format!("now: {e}"))?;
            process_one_job(&conn, transport, chat_id, true, &owner, &now)
        })();
        match step {
            Ok(true) => continue, // còn việc → xử lý ngay.
            Ok(false) => std::thread::sleep(interval),
            Err(e) => {
                tracing::warn!("worker lỗi vòng lặp: {e} — ngủ rồi thử lại");
                std::thread::sleep(interval);
            }
        }
    }
}

/// Vòng lặp worker động cho daemon: tự nạp credentials từ config_lock để khởi tạo/cập nhật transport.
pub fn run_loop_dynamic(
    db_path: &str,
    config_lock: std::sync::Arc<std::sync::RwLock<crate::config::Config>>,
    owner: String,
    interval: std::time::Duration,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    let mut cached_token = String::new();
    let mut cached_chat_id = 0i64;
    let mut cached_base_url = String::new();
    let mut cached_transport: Option<crate::telegram::BotApiHttpTransport> = None;

    while !shutdown.load(Ordering::Relaxed) {
        let (bot_token, chat_id, base_url) = {
            let cfg = config_lock.read().unwrap_or_else(|e| e.into_inner());
            (
                cfg.telegram_bot_token.clone(),
                cfg.telegram_chat_id,
                cfg.telegram_base_url.clone(),
            )
        };

        if bot_token.is_empty() || chat_id == 0 {
            std::thread::sleep(interval);
            continue;
        }

        if cached_transport.is_none()
            || cached_token != bot_token
            || cached_chat_id != chat_id
            || cached_base_url != base_url
        {
            match crate::telegram::BotApiHttpTransport::new(&base_url, &bot_token, "telecrate") {
                Ok(t) => {
                    cached_token = bot_token;
                    cached_chat_id = chat_id;
                    cached_base_url = base_url;
                    cached_transport = Some(t);
                    if let Ok(conn) = crate::db::open(db_path) {
                        let _ = conn.execute(
                            "UPDATE upload_jobs SET state = 'pending', retry_count = 0 WHERE state = 'failed'",
                            [],
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Worker '{owner}' khởi tạo transport thất bại: {e:?}");
                    std::thread::sleep(interval);
                    continue;
                }
            }
        }

        let transport = cached_transport.as_ref().unwrap();

        let step = (|| -> Result<bool, String> {
            let conn = crate::db::open(db_path)?;
            let now: String = conn
                .query_row("SELECT datetime('now')", [], |r| r.get(0))
                .map_err(|e| format!("now: {e}"))?;
            process_one_job(&conn, transport, cached_chat_id, true, &owner, &now)
        })();

        match step {
            Ok(true) => continue,
            Ok(false) => std::thread::sleep(interval),
            Err(e) => {
                tracing::warn!("Worker '{owner}' lỗi vòng lặp: {e} — thử lại sau");
                std::thread::sleep(interval);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telegram::TransportType;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Mock thành công + đếm upload, lưu bytes theo message id.
    struct MockOk {
        store: Arc<Mutex<HashMap<i64, Vec<u8>>>>,
        next: Mutex<i64>,
        uploads: Arc<Mutex<u64>>,
    }

    impl MockOk {
        fn new() -> Self {
            Self {
                store: Arc::new(Mutex::new(HashMap::new())),
                next: Mutex::new(1),
                uploads: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl Transport for MockOk {
        fn transport_type(&self) -> TransportType {
            TransportType::BotApiHttp
        }
        fn upload(&self, chat_id: i64, bytes: &[u8]) -> Result<RemoteLocator, TransportError> {
            *self.uploads.lock().unwrap() += 1;
            let mut n = self.next.lock().unwrap();
            let mid = *n;
            *n += 1;
            self.store.lock().unwrap().insert(mid, bytes.to_vec());
            Ok(RemoteLocator {
                transport: TransportType::BotApiHttp,
                bot_name: "mock".to_string(),
                chat_id,
                message_id: mid,
                file_id: format!("f{mid}"),
                file_unique_id: format!("u{mid}"),
                size: bytes.len() as u64,
            })
        }
        fn download(&self, loc: &RemoteLocator) -> Result<Vec<u8>, TransportError> {
            self.store
                .lock()
                .unwrap()
                .get(&loc.message_id)
                .cloned()
                .ok_or(TransportError::Permanent {
                    reason: "gone".to_string(),
                })
        }
        fn delete(&self, loc: &RemoteLocator) -> Result<bool, TransportError> {
            Ok(self.store.lock().unwrap().remove(&loc.message_id).is_some())
        }
    }
    fn job_db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = crate::db::open(dir.path().join("i.db").to_str().unwrap()).unwrap();
        crate::db::apply_all_migrations(&mut conn).unwrap();
        crate::db::create_bucket(&conn, "bkt", "r").unwrap();
        (dir, conn)
    }

    /// Giờ DB hiện tại để job tới hạn claim được.
    fn db_now(conn: &Connection) -> String {
        conn.query_row("SELECT datetime('now')", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn worker_uploads_commits_and_gc_spool() {
        let (dir, mut conn) = job_db();
        let spool = dir.path().join("s1.chunk");
        crate::spool::write_durable(&spool, b"hello-worker").unwrap();
        crate::db::put_object(
            &mut conn,
            "bkt",
            "k",
            "v1",
            12,
            "etag",
            "text/plain",
            None,
            None,
            &[crate::db::NewChunk {
                offset: 0,
                length: 12,
                plaintext_sha256: "ph".to_string(),
                ciphertext_sha256: "ph".to_string(),
                mode: crate::crypto::MODE_NONE.to_string(),
                key_ref: None,
                spool_path: spool.to_str().unwrap().to_string(),
            }],
            "job1",
        )
        .unwrap();
        let t = MockOk::new();
        let now = db_now(&conn);
        assert!(process_one_job(&conn, &t, -99, true, "w1", &now).unwrap());
        // Hết việc → false.
        assert!(!process_one_job(&conn, &t, -99, true, "w1", &now).unwrap());
        assert_eq!(*t.uploads.lock().unwrap(), 1);
        // Chunk remote + locator + spool đã GC.
        let chunks = crate::db::chunks_of(&conn, "v1").unwrap();
        assert_eq!(chunks[0].state, "remote");
        assert!(!spool.exists());
        let loc: String = conn
            .query_row(
                "SELECT remote_locator_json FROM chunks WHERE version_id = 'v1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(loc.contains("\"file_id\":\"f1\""), "{loc}");
        let st: String = conn
            .query_row(
                "SELECT state FROM upload_jobs WHERE job_id = 'job1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(st, "done");
    }

    #[test]
    fn worker_skips_deleted_version_and_retries_transient() {
        let (_dir, mut conn) = job_db();
        // Version bị xóa sau khi job tạo (job mồ côi — phòng thủ sâu, thực tế hiếm nhờ txn):
        // dựng trực tiếp với FK tạm tắt.
        conn.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
        conn.execute(
            "INSERT INTO upload_jobs(job_id, version_id, state) VALUES ('j9', 'gv', 'pending')",
            [],
        )
        .unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let t = MockOk::new();
        let now = db_now(&conn);
        assert!(process_one_job(&conn, &t, -99, true, "w1", &now).unwrap());
        assert_eq!(*t.uploads.lock().unwrap(), 0);

        // Transport luôn transient → job pending lại + retry_count tăng.
        struct MockFlaky;
        impl Transport for MockFlaky {
            fn transport_type(&self) -> TransportType {
                TransportType::BotApiHttp
            }
            fn upload(&self, _: i64, _: &[u8]) -> Result<RemoteLocator, TransportError> {
                Err(TransportError::Transient {
                    reason: "net".to_string(),
                    retry_after_secs: Some(5),
                })
            }
            fn download(&self, _: &RemoteLocator) -> Result<Vec<u8>, TransportError> {
                unreachable!()
            }
            fn delete(&self, _: &RemoteLocator) -> Result<bool, TransportError> {
                unreachable!()
            }
        }
        let dir2 = tempfile::tempdir().unwrap();
        let spool = dir2.path().join("s.chunk");
        crate::spool::write_durable(&spool, b"x").unwrap();
        crate::db::put_object(
            &mut conn,
            "bkt",
            "k2",
            "v2",
            1,
            "e",
            "text/plain",
            None,
            None,
            &[crate::db::NewChunk {
                offset: 0,
                length: 1,
                plaintext_sha256: "ph".to_string(),
                ciphertext_sha256: "ph".to_string(),
                mode: crate::crypto::MODE_NONE.to_string(),
                key_ref: None,
                spool_path: spool.to_str().unwrap().to_string(),
            }],
            "job2",
        )
        .unwrap();
        assert!(process_one_job(&conn, &MockFlaky, -99, true, "w1", &db_now(&conn)).unwrap());
        let (st, retry): (String, i64) = conn
            .query_row(
                "SELECT state, retry_count FROM upload_jobs WHERE job_id = 'job2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(st, "pending");
        assert_eq!(retry, 1);
        // Spool KHÔNG bị GC khi upload lỗi.
        assert!(spool.exists());
    }

    #[test]
    fn worker_reclaims_expired_uploading_lease() {
        let (_dir, mut conn) = job_db();
        let dir2 = tempfile::tempdir().unwrap();
        let spool = dir2.path().join("r.chunk");
        crate::spool::write_durable(&spool, b"reclaim").unwrap();
        crate::db::put_object(
            &mut conn,
            "bkt",
            "rk",
            "rv",
            7,
            "e",
            "text/plain",
            None,
            None,
            &[crate::db::NewChunk {
                offset: 0,
                length: 7,
                plaintext_sha256: "ph".to_string(),
                ciphertext_sha256: "ph".to_string(),
                mode: crate::crypto::MODE_NONE.to_string(),
                key_ref: None,
                spool_path: spool.to_str().unwrap().to_string(),
            }],
            "jobreclaim",
        )
        .unwrap();
        // Giả lập worker cũ chết: uploading + lease hết từ lâu.
        conn.execute(
            "UPDATE upload_jobs SET state = 'uploading', lease_owner = 'dead', lease_expires = '2000-01-01 00:00:00', next_attempt = '2000-01-01 00:00:00' WHERE job_id = 'jobreclaim'",
            [],
        )
        .unwrap();
        let t = MockOk::new();
        assert!(process_one_job(&conn, &t, -99, true, "w2", &db_now(&conn)).unwrap());
        assert_eq!(*t.uploads.lock().unwrap(), 1);
        let st: String = conn
            .query_row(
                "SELECT state FROM upload_jobs WHERE job_id = 'jobreclaim'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(st, "done");
    }

    #[test]
    fn concurrent_workers_never_double_upload() {
        use std::thread;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("c.db");
        {
            let mut conn = crate::db::open(db_path.to_str().unwrap()).unwrap();
            crate::db::apply_all_migrations(&mut conn).unwrap();
            crate::db::create_bucket(&conn, "bkt", "r").unwrap();
            // 4 jobs, mỗi job 2 chunks.
            for i in 0..4 {
                let mut chunks = Vec::new();
                for j in 0..2 {
                    let p = dir.path().join(format!("c{i}-{j}.chunk"));
                    crate::spool::write_durable(&p, b"data").unwrap();
                    chunks.push(crate::db::NewChunk {
                        offset: j,
                        length: 4,
                        plaintext_sha256: "ph".to_string(),
                        ciphertext_sha256: "ph".to_string(),
                        mode: crate::crypto::MODE_NONE.to_string(),
                        key_ref: None,
                        spool_path: p.to_str().unwrap().to_string(),
                    });
                }
                crate::db::put_object(
                    &mut conn,
                    "bkt",
                    &format!("k{i}"),
                    &format!("v{i}"),
                    8,
                    "e",
                    "text/plain",
                    None,
                    None,
                    &chunks,
                    &format!("job{i}"),
                )
                .unwrap();
            }
        }
        let t = Arc::new(MockOk::new());
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut handles = Vec::new();
        for w in 0..4 {
            let dbp = db_path.to_str().unwrap().to_string();
            let tt = t.clone();
            let errs = errors.clone();
            handles.push(thread::spawn(move || {
                let conn = crate::db::open(&dbp).unwrap();
                let now: String = conn
                    .query_row("SELECT datetime('now')", [], |r| r.get(0))
                    .unwrap();
                // Mỗi worker xử lý tới khi hết việc.
                let mut n = 0;
                loop {
                    match process_one_job(&conn, &*tt, -99, true, &format!("w{w}"), &now) {
                        Ok(true) => n += 1,
                        Ok(false) => break,
                        Err(e) => {
                            errs.lock().unwrap().push(format!("worker {w}: {e}"));
                            break;
                        }
                    }
                }
                n
            }));
        }
        let total: i32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        let errs = errors.lock().unwrap();
        assert!(errs.is_empty(), "worker errors: {errs:?}");
        assert_eq!(total, 4, "mỗi job xử lý đúng 1 lần");
        assert_eq!(*t.uploads.lock().unwrap(), 8, "8 chunks upload đúng 1 lần");
    }
}

//! Worker upload Telegram M2.2 (tối giản): poll → claim (lease) → upload → commit → GC spool.
//!
//! Không giữ transaction DB mở suốt network upload. Mỗi chunk: đọc spool → upload → txn ngắn
//! commit locator. Job dùng lease để nhiều worker không giành nhau (M2.2 chạy 1 worker;
//! lease/timeout bảo vệ khi process chết giữa chừng).

use rusqlite::Connection;

use crate::telegram::{RemoteLocator, Transport, TransportError};

/// Claim 1 job sẵn sàng (pending + tới hạn) bằng lease. Trả None nếu không có việc.
fn claim_job(
    conn: &Connection,
    owner: &str,
    lease_secs: i64,
    now: &str,
) -> Result<Option<Claimed>, String> {
    let mut stmt = conn
        .prepare("SELECT job_id, version_id, retry_count FROM upload_jobs WHERE state = 'pending' AND next_attempt <= ? ORDER BY next_attempt LIMIT 1")
        .map_err(|e| format!("poll prepare: {e}"))?;
    let mut rows = stmt.query([now]).map_err(|e| format!("poll: {e}"))?;
    let Some(row) = rows.next().map_err(|e| format!("poll row: {e}"))? else {
        return Ok(None);
    };
    let (job_id, version_id, retry_count): (String, String, i64) = (
        row.get(0).map_err(|e| format!("row: {e}"))?,
        row.get(1).map_err(|e| format!("row: {e}"))?,
        row.get(2).map_err(|e| format!("row: {e}"))?,
    );
    let n = conn
        .execute(
            "UPDATE upload_jobs SET state = 'uploading', lease_owner = ?, lease_expires = datetime(?, ?) WHERE job_id = ? AND state = 'pending'",
            rusqlite::params![owner, now, format!("+{lease_secs} seconds"), job_id],
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
    // GC spool: mọi chunk đã remote → xóa file local (best-effort từng file).
    if spool_cleanup {
        for c in &chunks {
            if let Some(p) = &c.spool_path {
                let _ = std::fs::remove_file(p);
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
    owner: &str,
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
            process_one_job(&conn, transport, chat_id, true, owner, &now)
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
        crate::db::apply_migration(&mut conn, 1, crate::db::MIGRATION_001).unwrap();
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
            "ph",
            spool.to_str().unwrap(),
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
            "ph",
            spool.to_str().unwrap(),
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
}

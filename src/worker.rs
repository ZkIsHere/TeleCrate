//! Worker upload Telegram M2.2 (tối giản): poll → claim (lease) → upload → commit → GC spool.
//!
//! Không giữ transaction DB mở suốt network upload. Mỗi chunk: đọc spool → upload → txn ngắn
//! commit locator. Job dùng lease để nhiều worker không giành nhau (M2.2 chạy 1 worker;
//! lease/timeout bảo vệ khi process chết giữa chừng).

use crate::db::{Db, Val};
use crate::telegram::{RemoteLocator, Transport, TransportError};

/// Claim 1 job sẵn sàng bằng lease. Lấy job `pending` tới hạn, hoặc job `uploading`
/// mà lease đã hết (worker cũ chết giữa chừng — reclaim, chống kẹt hàng đợi).
///
/// `now` so sánh chuỗi với cột datetime TEXT (`YYYY-MM-DD HH:MM:SS`); hàm chấp nhận
/// cả ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`) và chuẩn hóa trước khi so sánh để caller
/// khác format không claim sai lặng lẽ.
async fn claim_job(
    db: &Db,
    owner: &str,
    lease_secs: i64,
    now: &str,
) -> Result<Option<Claimed>, String> {
    let normalized = now.replace('T', " ").trim_end_matches('Z').to_string();
    let now = normalized.as_str();
    let rows = crate::db::fetch_all(
        db,
        "SELECT job_id, version_id, retry_count FROM upload_jobs WHERE next_attempt <= ? AND ((state = 'pending') OR (state = 'uploading' AND lease_expires IS NOT NULL AND lease_expires <= ?)) ORDER BY next_attempt LIMIT 1",
        &[Val::text(now), Val::text(now)],
    )
    .await
    .map_err(|e| format!("poll: {e}"))?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let job = Claimed {
        job_id: row.get_string(0).map_err(|e| format!("row: {e}"))?,
        version_id: row.get_string(1).map_err(|e| format!("row: {e}"))?,
        retry_count: row.get_i64(2).map_err(|e| format!("row: {e}"))?,
    };
    // Claim atomic: chỉ thắng khi job pending, hoặc uploading mà lease đã hết.
    // (Nếu khớp cả uploading còn lease, 2 worker sẽ xử lý trùng job.)
    let lease_until = crate::db::now_plus_str(lease_secs);
    let n = crate::db::exec(
        db,
        "UPDATE upload_jobs SET state = 'uploading', lease_owner = ?, lease_expires = ? WHERE job_id = ? AND (state = 'pending' OR (state = 'uploading' AND (lease_expires IS NULL OR lease_expires <= ?)))",
        &[
            Val::text(owner),
            Val::text(&lease_until),
            Val::text(&job.job_id),
            Val::text(now),
        ],
    )
    .await
    .map_err(|e| format!("claim: {e}"))?;
    if n == 0 {
        return Ok(None); // worker khác claim trước.
    }
    Ok(Some(job))
}

struct Claimed {
    job_id: String,
    version_id: String,
    retry_count: i64,
}

/// Xử lý 1 job đã claim: upload từng chunk pending → commit locator → xong job → GC spool.
/// Trả `true` nếu đã xử lý (để loop tiếp ngay), `false` nếu không có việc.
pub async fn process_one_job(
    db: &Db,
    transport: &dyn Transport,
    chat_id: i64,
    spool_cleanup: bool,
    owner: &str,
    now: &str,
) -> Result<bool, String> {
    let Some(job) = claim_job(db, owner, 300, now).await? else {
        return Ok(false);
    };
    // Version còn tồn tại không (có thể đã bị DELETE sau khi job tạo)?
    let version_alive = crate::db::count(
        db,
        "SELECT COUNT(*) FROM objects WHERE version_id = ?",
        &[Val::text(&job.version_id)],
    )
    .await
    .map_err(|e| format!("version check: {e}"))?;
    if version_alive == 0 {
        finish_job(db, &job.job_id, true).await?;
        return Ok(true);
    }
    let chunks = crate::db::chunks_of(db, &job.version_id).await?;
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
            Ok(loc) => commit_chunk(db, &job.version_id, c.idx, &loc).await?,
            Err(e) => {
                fail_job(db, &job, &e).await?;
                return Ok(true);
            }
        }
    }
    finish_job(db, &job.job_id, true).await?;
    // GC spool: mọi chunk đã remote → xóa file local (best-effort từng file) + set spool_path = NULL trong DB.
    if spool_cleanup {
        for c in &chunks {
            if let Some(p) = &c.spool_path {
                let _ = std::fs::remove_file(p);
                let _ = crate::db::exec(
                    db,
                    "UPDATE chunks SET spool_path = NULL WHERE version_id = ? AND idx = ?",
                    &[Val::text(&job.version_id), Val::int(c.idx)],
                )
                .await;
            }
        }
    }
    Ok(true)
}

fn locator_json(loc: &RemoteLocator) -> String {
    serde_json::to_string(loc).unwrap_or_default()
}

/// Commit locator 1 chunk trong txn ngắn (không giữ txn qua network).
async fn commit_chunk(
    db: &Db,
    version_id: &str,
    idx: i64,
    loc: &RemoteLocator,
) -> Result<(), String> {
    // Giữ spool_path để GC xóa file sau; read fallback sang Telegram khi file mất.
    crate::db::exec(
        db,
        "UPDATE chunks SET state = 'remote', remote_locator_json = ? WHERE version_id = ? AND idx = ?",
        &[Val::text(&locator_json(loc)), Val::text(version_id), Val::int(idx)],
    )
    .await
    .map_err(|e| format!("commit chunk: {e}"))?;
    Ok(())
}

async fn finish_job(db: &Db, job_id: &str, done: bool) -> Result<(), String> {
    if done {
        if let Some(r) = crate::db::fetch_opt(
            db,
            "SELECT version_id FROM upload_jobs WHERE job_id = ?",
            &[Val::text(job_id)],
        )
        .await
        .map_err(|e| format!("finish lookup: {e}"))?
        {
            if let Ok(v_id) = r.get_string(0) {
                let _ = crate::db::exec(
                    db,
                    "UPDATE objects SET storage_state = 'remote' WHERE version_id = ?",
                    &[Val::text(&v_id)],
                )
                .await;
            }
        }
    }
    crate::db::exec(
        db,
        "UPDATE upload_jobs SET state = ?, lease_owner = NULL, lease_expires = NULL WHERE job_id = ?",
        &[Val::text(if done { "done" } else { "pending" }), Val::text(job_id)],
    )
    .await
    .map_err(|e| format!("finish job: {e}"))?;
    Ok(())
}

async fn fail_job(db: &Db, job: &Claimed, e: &TransportError) -> Result<(), String> {
    match e {
        TransportError::Transient {
            retry_after_secs, ..
        } => {
            // Backoff: max(retry_after, 30s * 2^retry, trần 1h).
            let backoff = retry_after_secs
                .unwrap_or(30)
                .max(30 << job.retry_count.min(6))
                .min(3600);
            let next = crate::db::now_plus_str(backoff as i64);
            crate::db::exec(
                db,
                "UPDATE upload_jobs SET state = 'pending', lease_owner = NULL, lease_expires = NULL, retry_count = retry_count + 1, next_attempt = ?, last_error = ? WHERE job_id = ?",
                &[Val::text(&next), Val::text(&format!("{e:?}")), Val::text(&job.job_id)],
            )
            .await
            .map_err(|e| format!("fail job: {e}"))?;
        }
        TransportError::Permanent { .. } => {
            crate::db::exec(
                db,
                "UPDATE upload_jobs SET state = 'failed', lease_owner = NULL, lease_expires = NULL, last_error = ? WHERE job_id = ?",
                &[Val::text(&format!("{e:?}")), Val::text(&job.job_id)],
            )
            .await
            .map_err(|e| format!("fail job: {e}"))?;
        }
    }
    Ok(())
}

/// Xử lý 1 job kiểu đồng bộ cho worker thread: DB qua `rt.block_on` từng bước ngắn,
/// upload blocking GỌI NGOÀI mọi async context (reqwest blocking cấm lồng runtime —
/// lồng `current_thread` sẽ panic "Cannot drop a runtime..." và kẹt live-e2e).
/// `process_one_job` async giữ lại cho unit test với mock (không blocking thật).
pub fn process_one_job_sync(
    db: &Db,
    rt: &tokio::runtime::Runtime,
    transport: &dyn Transport,
    chat_id: i64,
    owner: &str,
) -> Result<bool, String> {
    let now = crate::db::now_str();
    let claimed = rt.block_on(claim_job(db, owner, 300, &now))?;
    let Some(job) = claimed else {
        return Ok(false);
    };
    let version_alive = rt
        .block_on(crate::db::count(
            db,
            "SELECT COUNT(*) FROM objects WHERE version_id = ?",
            &[Val::text(&job.version_id)],
        ))
        .map_err(|e| format!("version check: {e}"))?;
    if version_alive == 0 {
        rt.block_on(finish_job(db, &job.job_id, true))?;
        return Ok(true);
    }
    let chunks = rt.block_on(crate::db::chunks_of(db, &job.version_id))?;
    for c in &chunks {
        if c.state == "remote" {
            continue;
        }
        let spool = c
            .spool_path
            .clone()
            .ok_or_else(|| "chunk thiếu spool_path".to_string())?;
        let bytes = std::fs::read(&spool).map_err(|e| format!("read spool: {e}"))?;
        // NGOÀI runtime: không block_on đang giữ ở đây.
        match transport.upload(chat_id, &bytes) {
            Ok(loc) => rt.block_on(commit_chunk(db, &job.version_id, c.idx, &loc))?,
            Err(e) => {
                rt.block_on(fail_job(db, &job, &e))?;
                return Ok(true);
            }
        }
    }
    rt.block_on(finish_job(db, &job.job_id, true))?;
    for c in &chunks {
        if let Some(p) = &c.spool_path {
            let _ = std::fs::remove_file(p);
            let _ = rt.block_on(crate::db::exec(
                db,
                "UPDATE chunks SET spool_path = NULL WHERE version_id = ? AND idx = ?",
                &[Val::text(&job.version_id), Val::int(c.idx)],
            ));
        }
    }
    Ok(true)
}

/// Vòng lặp worker cho daemon: poll mỗi `interval`, xử lý tới khi hết việc.
/// Transport blocking → gọi NGOÀI block_on qua `process_one_job_sync` (ADR 0002).
/// Chạy trên std thread với runtime riêng (block_on an toàn vì không lồng runtime).
pub fn run_loop(
    db: Db,
    transport: &dyn Transport,
    chat_id: i64,
    owner: String,
    interval: std::time::Duration,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let rt = match rt {
        Ok(rt) => rt,
        Err(e) => {
            tracing::warn!("worker không dựng được runtime: {e}");
            return;
        }
    };
    while !shutdown.load(Ordering::Relaxed) {
        let step: Result<bool, String> = process_one_job_sync(&db, &rt, transport, chat_id, &owner);
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
    db: Db,
    config_lock: std::sync::Arc<std::sync::RwLock<crate::config::Config>>,
    owner: String,
    interval: std::time::Duration,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let rt = match rt {
        Ok(rt) => rt,
        Err(e) => {
            tracing::warn!("worker không dựng được runtime: {e}");
            return;
        }
    };
    let mut cached_token = String::new();
    let mut cached_chat_id = 0i64;
    let mut cached_transport: Option<crate::telegram::BotApiHttpTransport> = None;

    while !shutdown.load(Ordering::Relaxed) {
        let (bot_token, chat_id) = {
            let cfg = config_lock.read().unwrap_or_else(|e| e.into_inner());
            (cfg.telegram_bot_token.clone(), cfg.telegram_chat_id)
        };

        if bot_token.is_empty() || chat_id == 0 {
            std::thread::sleep(interval);
            continue;
        }

        if cached_transport.is_none() || cached_token != bot_token || cached_chat_id != chat_id {
            match crate::telegram::BotApiHttpTransport::new(
                crate::config::TELEGRAM_API_BASE,
                &bot_token,
                "telecrate",
            ) {
                Ok(t) => {
                    cached_token = bot_token;
                    cached_chat_id = chat_id;
                    cached_transport = Some(t);
                    let reset: Result<(), String> = rt.block_on(async {
                        crate::db::exec(
                            &db,
                            "UPDATE upload_jobs SET state = 'pending', retry_count = 0 WHERE state = 'failed'",
                            &[],
                        )
                        .await
                        .map(|_| ())
                    });
                    let _ = reset;
                }
                Err(e) => {
                    tracing::warn!("Worker '{owner}' khởi tạo transport thất bại: {e:?}");
                    std::thread::sleep(interval);
                    continue;
                }
            }
        }

        let transport = cached_transport.as_ref().unwrap();

        let step: Result<bool, String> =
            process_one_job_sync(&db, &rt, transport, cached_chat_id, &owner);

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
    async fn job_db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::db::Db::open_sqlite(dir.path().join("i.db").to_str().unwrap())
            .await
            .unwrap();
        crate::db::apply_all_migrations(&conn).await.unwrap();
        crate::db::create_bucket(&conn, "bkt", "r").await.unwrap();
        (dir, conn)
    }

    /// Giờ DB hiện tại để job tới hạn claim được.
    async fn db_now(conn: &Db) -> String {
        crate::db::query_scalar_string(conn, "SELECT datetime('now')", &[])
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn worker_uploads_commits_and_gc_spool() {
        let (dir, conn) = job_db().await;
        let spool = dir.path().join("s1.chunk");
        crate::spool::write_durable(&spool, b"hello-worker").unwrap();
        crate::db::put_object(
            &conn,
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
        .await
        .unwrap();
        let t = MockOk::new();
        let now = db_now(&conn).await;
        assert!(process_one_job(&conn, &t, -99, true, "w1", &now)
            .await
            .unwrap());
        // Hết việc → false.
        assert!(!process_one_job(&conn, &t, -99, true, "w1", &now)
            .await
            .unwrap());
        assert_eq!(*t.uploads.lock().unwrap(), 1);
        // Chunk remote + locator + spool đã GC.
        let chunks = crate::db::chunks_of(&conn, "v1").await.unwrap();
        assert_eq!(chunks[0].state, "remote");
        assert!(!spool.exists());
        let loc: String = crate::db::query_scalar_string(
            &conn,
            "SELECT remote_locator_json FROM chunks WHERE version_id = 'v1'",
            &[],
        )
        .await
        .unwrap();
        assert!(loc.contains("\"file_id\":\"f1\""), "{loc}");
        let st: String = crate::db::query_scalar_string(
            &conn,
            "SELECT state FROM upload_jobs WHERE job_id = 'job1'",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(st, "done");
    }

    #[tokio::test]
    async fn worker_skips_deleted_version_and_retries_transient() {
        let (_dir, conn) = job_db().await;
        // Version bị xóa sau khi job tạo (job mồ côi — phòng thủ sâu, thực tế hiếm nhờ txn):
        // dựng trực tiếp với FK tạm tắt qua connection độc lập.
        {
            let raw = rusqlite::Connection::open(_dir.path().join("i.db")).unwrap();
            raw.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
            raw.execute(
                "INSERT INTO upload_jobs(job_id, version_id, state) VALUES ('j9', 'gv', 'pending')",
                [],
            )
            .unwrap();
        }
        let t = MockOk::new();
        let now = db_now(&conn).await;
        assert!(process_one_job(&conn, &t, -99, true, "w1", &now)
            .await
            .unwrap());
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
            &conn,
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
        .await
        .unwrap();
        assert!(
            process_one_job(&conn, &MockFlaky, -99, true, "w1", &db_now(&conn).await)
                .await
                .unwrap()
        );
        let row = crate::db::query_row(
            &conn,
            "SELECT state, retry_count FROM upload_jobs WHERE job_id = 'job2'",
            &[],
        )
        .await
        .unwrap();
        let st = row.get_string(0).unwrap();
        let retry = row.get_i64(1).unwrap();
        assert_eq!(st, "pending");
        assert_eq!(retry, 1);
        // Spool KHÔNG bị GC khi upload lỗi.
        assert!(spool.exists());
    }

    #[tokio::test]
    async fn worker_reclaims_expired_uploading_lease() {
        let (_dir, conn) = job_db().await;
        let dir2 = tempfile::tempdir().unwrap();
        let spool = dir2.path().join("r.chunk");
        crate::spool::write_durable(&spool, b"reclaim").unwrap();
        crate::db::put_object(
            &conn,
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
        .await
        .unwrap();
        // Giả lập worker cũ chết: uploading + lease hết từ lâu.
        crate::db::exec(
            &conn,
            "UPDATE upload_jobs SET state = 'uploading', lease_owner = 'dead', lease_expires = '2000-01-01 00:00:00', next_attempt = '2000-01-01 00:00:00' WHERE job_id = 'jobreclaim'",
            &[],
        )
        .await
        .unwrap();
        let t = MockOk::new();
        assert!(
            process_one_job(&conn, &t, -99, true, "w2", &db_now(&conn).await)
                .await
                .unwrap()
        );
        assert_eq!(*t.uploads.lock().unwrap(), 1);
        let st: String = crate::db::query_scalar_string(
            &conn,
            "SELECT state FROM upload_jobs WHERE job_id = 'jobreclaim'",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(st, "done");
    }

    #[tokio::test]
    async fn concurrent_workers_never_double_upload() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("c.db");
        {
            let conn = crate::db::Db::open_sqlite(db_path.to_str().unwrap())
                .await
                .unwrap();
            crate::db::apply_all_migrations(&conn).await.unwrap();
            crate::db::create_bucket(&conn, "bkt", "r").await.unwrap();
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
                    &conn,
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
                .await
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
            handles.push(tokio::spawn(async move {
                let conn = crate::db::Db::open_sqlite(&dbp).await.unwrap();
                let now: String =
                    crate::db::query_scalar_string(&conn, "SELECT datetime('now')", &[])
                        .await
                        .unwrap();
                // Mỗi worker xử lý tới khi hết việc.
                let mut n = 0;
                loop {
                    match process_one_job(&conn, &*tt, -99, true, &format!("w{w}"), &now).await {
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
        let mut total = 0;
        for h in handles {
            total += h.await.unwrap();
        }
        let errs = errors.lock().unwrap();
        assert!(errs.is_empty(), "worker errors: {errs:?}");
        assert_eq!(total, 4, "mỗi job xử lý đúng 1 lần");
        assert_eq!(*t.uploads.lock().unwrap(), 8, "8 chunks upload đúng 1 lần");
    }
}

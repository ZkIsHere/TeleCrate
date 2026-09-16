//! Integration test: Crash injection tại 6 ranh giới bền vững (Docs Architecture section 3).

use telecrate::db::{self, NewChunk};
use telecrate::spool::{self, write_durable};
use tempfile::TempDir;

fn setup_test_env() -> (TempDir, String, String) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("index.db").to_str().unwrap().to_string();
    let spool_dir = dir.path().join("spool").to_str().unwrap().to_string();
    std::fs::create_dir_all(&spool_dir).unwrap();

    let mut conn = db::open(&db_path).unwrap();
    db::apply_migration(&mut conn, 1, db::MIGRATION_001).unwrap();
    db::create_bucket(&conn, "crash-bkt", "telecrate-1").unwrap();

    (dir, db_path, spool_dir)
}

/// Crash Point 1: Dở dang khi ghi file `.tmp` trước khi rename.
/// Phục hồi: `reconcile_spool` dọn sạch file `.tmp` mồ côi.
#[test]
fn crash_point_1_interrupted_tmp_write() {
    let (_dir, db_path, spool_dir) = setup_test_env();
    let conn = db::open(&db_path).unwrap();

    let tmp_path = std::path::Path::new(&spool_dir).join("interrupted.tmp");
    std::fs::write(&tmp_path, b"partial tmp payload data").unwrap();
    assert!(tmp_path.exists());

    let active_spools = db::active_spool_paths(&conn).unwrap();
    let (tmps_cleared, chunks_cleared) =
        spool::reconcile_spool(std::path::Path::new(&spool_dir), &active_spools).unwrap();

    assert_eq!(tmps_cleared, 1);
    assert_eq!(chunks_cleared, 0);
    assert!(!tmp_path.exists());
}

/// Crash Point 2: File đã rename thành `.chunk` trên FS nhưng crash trước DB txn commit.
/// Phục hồi: `reconcile_spool` dọn file `.chunk` mồ côi vì không có trong DB.
#[test]
fn crash_point_2_chunk_renamed_before_db_commit() {
    let (_dir, db_path, spool_dir) = setup_test_env();
    let conn = db::open(&db_path).unwrap();

    let orphan_chunk = std::path::Path::new(&spool_dir).join("uncommitted.chunk");
    write_durable(&orphan_chunk, b"uncommitted chunk content").unwrap();
    assert!(orphan_chunk.exists());

    let active_spools = db::active_spool_paths(&conn).unwrap();
    let (tmps_cleared, chunks_cleared) =
        spool::reconcile_spool(std::path::Path::new(&spool_dir), &active_spools).unwrap();

    assert_eq!(tmps_cleared, 0);
    assert_eq!(chunks_cleared, 1);
    assert!(!orphan_chunk.exists());
}

/// Crash Point 3: DB commit thành công nhưng client crash/disconnect trước S3 HTTP response.
/// Phục hồi: Client retry ghi đè/idempotency, DB giữ hàng hiện hành mới nhất, không lỗi duplicate constraint.
#[test]
fn crash_point_3_db_committed_before_client_response() {
    let (_dir, db_path, spool_dir) = setup_test_env();
    let mut conn = db::open(&db_path).unwrap();

    let chunk_file_1 = std::path::Path::new(&spool_dir).join("chunk1.chunk");
    write_durable(&chunk_file_1, b"attempt 1 data").unwrap();

    let chunk_spec_1 = NewChunk {
        offset: 0,
        length: 14,
        plaintext_sha256: "hash1".to_string(),
        ciphertext_sha256: "hash1".to_string(),
        spool_path: chunk_file_1.to_str().unwrap().to_string(),
        mode: telecrate::crypto::MODE_NONE.to_string(),
        key_ref: None,
    };

    db::put_object(
        &mut conn,
        "crash-bkt",
        "retry-key",
        "v-attempt-1",
        14,
        "etag1",
        "application/octet-stream",
        &[chunk_spec_1],
        "job-attempt-1",
    )
    .unwrap();

    // Client không nhận được response 200, tiến hành retry lần 2.
    let chunk_file_2 = std::path::Path::new(&spool_dir).join("chunk2.chunk");
    write_durable(&chunk_file_2, b"attempt 2 data").unwrap();

    let chunk_spec_2 = NewChunk {
        offset: 0,
        length: 14,
        plaintext_sha256: "hash2".to_string(),
        ciphertext_sha256: "hash2".to_string(),
        spool_path: chunk_file_2.to_str().unwrap().to_string(),
        mode: telecrate::crypto::MODE_NONE.to_string(),
        key_ref: None,
    };

    let old_spools = db::put_object(
        &mut conn,
        "crash-bkt",
        "retry-key",
        "v-attempt-2",
        14,
        "etag2",
        "application/octet-stream",
        &[chunk_spec_2],
        "job-attempt-2",
    )
    .unwrap();

    // Spool cũ thu gom thành công
    assert_eq!(old_spools, vec![chunk_file_1.to_str().unwrap().to_string()]);
    let latest = db::latest_version(&conn, "crash-bkt", "retry-key")
        .unwrap()
        .unwrap();
    assert_eq!(latest.version_id, "v-attempt-2");
    assert_eq!(latest.etag, "etag2");
}

/// Crash Point 4: Sau S3 response thành công (`accepted-local`), trước khi worker upload Telegram.
/// Phục hồi: Trạng thái `accepted-local` giúp GET vẫn đọc được từ spool local, worker chạy lại reclaim job và upload bình thường.
#[test]
fn crash_point_4_accepted_local_readable_and_worker_resumes() {
    let (_dir, db_path, spool_dir) = setup_test_env();
    let mut conn = db::open(&db_path).unwrap();

    let chunk_file = std::path::Path::new(&spool_dir).join("accepted.chunk");
    write_durable(&chunk_file, b"local payload").unwrap();

    let chunk_spec = NewChunk {
        offset: 0,
        length: 13,
        plaintext_sha256: "hash_local".to_string(),
        ciphertext_sha256: "hash_local".to_string(),
        spool_path: chunk_file.to_str().unwrap().to_string(),
        mode: telecrate::crypto::MODE_NONE.to_string(),
        key_ref: None,
    };

    db::put_object(
        &mut conn,
        "crash-bkt",
        "local-obj",
        "v-local-1",
        13,
        "etag_local",
        "text/plain",
        &[chunk_spec],
        "job-local-1",
    )
    .unwrap();

    // Trạng thái object là accepted-local
    let v = db::latest_version(&conn, "crash-bkt", "local-obj")
        .unwrap()
        .unwrap();
    assert_eq!(v.storage_state, "accepted-local");

    // Worker chưa upload: GET đọc trực tiếp từ spool local
    let chunks = db::chunks_of(&conn, "v-local-1").unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].state, "pending");
    let content = std::fs::read(chunks[0].spool_path.as_ref().unwrap()).unwrap();
    assert_eq!(content, b"local payload");

    // Giả lập worker chạy: claim job, upload mock transport, commit remote
    let mock_transport = telecrate::telegram::MockTransport::default();
    telecrate::worker::process_one_job(
        &conn,
        &mock_transport,
        100,
        true,
        "w1",
        "2026-09-16T14:00:00Z",
    )
    .unwrap();

    let chunks_after = db::chunks_of(&conn, "v-local-1").unwrap();
    assert_eq!(chunks_after[0].state, "remote");
}

/// Crash Point 5: Worker upload thành công lên Telegram nhưng worker crash trước khi commit DB remote locator.
/// Phục hồi: Lease hết hạn, worker tiếp theo reclaim job, generation guard & mock upload dedup an toàn.
#[test]
fn crash_point_5_worker_crash_before_remote_db_commit() {
    let (_dir, db_path, spool_dir) = setup_test_env();
    let mut conn = db::open(&db_path).unwrap();

    let chunk_file = std::path::Path::new(&spool_dir).join("crash_worker.chunk");
    write_durable(&chunk_file, b"worker payload").unwrap();

    let chunk_spec = NewChunk {
        offset: 0,
        length: 14,
        plaintext_sha256: "hash_w".to_string(),
        ciphertext_sha256: "hash_w".to_string(),
        spool_path: chunk_file.to_str().unwrap().to_string(),
        mode: telecrate::crypto::MODE_NONE.to_string(),
        key_ref: None,
    };

    db::put_object(
        &mut conn,
        "crash-bkt",
        "worker-obj",
        "v-w-1",
        14,
        "etag_w",
        "text/plain",
        &[chunk_spec],
        "job-w-1",
    )
    .unwrap();

    // Giả lập worker 1 claim lease và crash (để lease hết hạn trong quá khứ)
    conn.execute(
        "UPDATE upload_jobs SET state = 'uploading', lease_owner = 'worker-dead', lease_expires = datetime('now', '-10 seconds') WHERE job_id = 'job-w-1'",
        [],
    )
    .unwrap();

    let mock_transport = telecrate::telegram::MockTransport::default();
    // Worker 2 reclaim job hết hạn và hoàn thành
    let processed = telecrate::worker::process_one_job(
        &conn,
        &mock_transport,
        200,
        true,
        "worker-alive",
        "2026-09-16T14:00:00Z",
    )
    .unwrap();
    assert!(processed);

    let chunks = db::chunks_of(&conn, "v-w-1").unwrap();
    assert_eq!(chunks[0].state, "remote");
}

/// Crash Point 6: Remote commit thành công nhưng crash trước khi GC spool file.
/// Phục hồi: GC worker chạy lại idempotent, kiểm tra state == 'remote' và refcount == 0, giải phóng spool file an toàn.
#[test]
fn crash_point_6_remote_committed_before_spool_gc() {
    let (_dir, db_path, spool_dir) = setup_test_env();
    let mut conn = db::open(&db_path).unwrap();

    let chunk_file = std::path::Path::new(&spool_dir).join("gc_crash.chunk");
    write_durable(&chunk_file, b"gc payload").unwrap();

    let chunk_spec = NewChunk {
        offset: 0,
        length: 10,
        plaintext_sha256: "hash_gc".to_string(),
        ciphertext_sha256: "hash_gc".to_string(),
        spool_path: chunk_file.to_str().unwrap().to_string(),
        mode: telecrate::crypto::MODE_NONE.to_string(),
        key_ref: None,
    };

    db::put_object(
        &mut conn,
        "crash-bkt",
        "gc-obj",
        "v-gc-1",
        10,
        "etag_gc",
        "text/plain",
        &[chunk_spec],
        "job-gc-1",
    )
    .unwrap();

    let mock_transport = telecrate::telegram::MockTransport::default();
    telecrate::worker::process_one_job(
        &conn,
        &mock_transport,
        300,
        true,
        "w-gc",
        "2026-09-16T14:00:00Z",
    )
    .unwrap();

    // Sau khi process_one_job thành công, spool file đã được dọn dẹp an toàn qua GC
    assert!(!chunk_file.exists());

    let chunks = db::chunks_of(&conn, "v-gc-1").unwrap();
    assert_eq!(chunks[0].state, "remote");
    assert!(chunks[0].spool_path.is_none());
}

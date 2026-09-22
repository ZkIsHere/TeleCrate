//! Integration test: Crash injection tại 6 ranh giới bền vững (Docs Architecture section 3).

use telecrate::db::{self, NewChunk};
use telecrate::spool::{self, write_durable};
use tempfile::TempDir;

async fn setup_test_env() -> (TempDir, String, String) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("index.db").to_str().unwrap().to_string();
    let spool_dir = dir.path().join("spool").to_str().unwrap().to_string();
    std::fs::create_dir_all(&spool_dir).unwrap();

    let conn = db::Db::open_sqlite(&db_path).await.unwrap();
    db::apply_all_migrations(&conn).await.unwrap();
    db::create_bucket(&conn, "crash-bkt", "telecrate-1")
        .await
        .unwrap();

    (dir, db_path, spool_dir)
}

/// Crash Point 1: Dở dang khi ghi file `.tmp` trước khi rename.
/// Phục hồi: `reconcile_spool` dọn sạch file `.tmp` mồ côi.
#[tokio::test]
async fn crash_point_1_interrupted_tmp_write() {
    let (_dir, db_path, spool_dir) = setup_test_env().await;
    let conn = db::Db::open_sqlite(&db_path).await.unwrap();

    let tmp_path = std::path::Path::new(&spool_dir).join("interrupted.tmp");
    std::fs::write(&tmp_path, b"partial tmp payload data").unwrap();
    assert!(tmp_path.exists());

    let active_spools = db::active_spool_paths(&conn).await.unwrap();
    let (tmps_cleared, chunks_cleared) =
        spool::reconcile_spool(std::path::Path::new(&spool_dir), &active_spools).unwrap();

    assert_eq!(tmps_cleared, 1);
    assert_eq!(chunks_cleared, 0);
    assert!(!tmp_path.exists());
}

/// Crash Point 2: File đã rename thành `.chunk` trên FS nhưng crash trước DB txn commit.
/// Phục hồi: `reconcile_spool` dọn file `.chunk` mồ côi vì không có trong DB.
#[tokio::test]
async fn crash_point_2_chunk_renamed_before_db_commit() {
    let (_dir, db_path, spool_dir) = setup_test_env().await;
    let conn = db::Db::open_sqlite(&db_path).await.unwrap();

    let orphan_chunk = std::path::Path::new(&spool_dir).join("uncommitted.chunk");
    write_durable(&orphan_chunk, b"uncommitted chunk content").unwrap();
    assert!(orphan_chunk.exists());

    let active_spools = db::active_spool_paths(&conn).await.unwrap();
    let (tmps_cleared, chunks_cleared) =
        spool::reconcile_spool(std::path::Path::new(&spool_dir), &active_spools).unwrap();

    assert_eq!(tmps_cleared, 0);
    assert_eq!(chunks_cleared, 1);
    assert!(!orphan_chunk.exists());
}

/// Crash Point 3: DB commit thành công nhưng client crash/disconnect trước S3 HTTP response.
/// Phục hồi: Client retry ghi đè/idempotency, DB giữ hàng hiện hành mới nhất, không lỗi duplicate constraint.
#[tokio::test]
async fn crash_point_3_db_committed_before_client_response() {
    let (_dir, db_path, spool_dir) = setup_test_env().await;
    let conn = db::Db::open_sqlite(&db_path).await.unwrap();

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
        &conn,
        "crash-bkt",
        "retry-key",
        "v-attempt-1",
        14,
        "etag1",
        "application/octet-stream",
        None,
        None,
        &[chunk_spec_1],
        "job-attempt-1",
    )
    .await
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

    let (old_spools, _) = db::put_object(
        &conn,
        "crash-bkt",
        "retry-key",
        "v-attempt-2",
        14,
        "etag2",
        "application/octet-stream",
        None,
        None,
        &[chunk_spec_2],
        "job-attempt-2",
    )
    .await
    .unwrap();

    // Spool cũ thu gom thành công
    assert_eq!(old_spools, vec![chunk_file_1.to_str().unwrap().to_string()]);
    let latest = db::latest_version(&conn, "crash-bkt", "retry-key")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest.version_id, "v-attempt-2");
    assert_eq!(latest.etag, "etag2");
}

/// Crash Point 4: Sau S3 response thành công (`accepted-local`), trước khi worker upload Telegram.
/// Phục hồi: Trạng thái `accepted-local` giúp GET vẫn đọc được từ spool local, worker chạy lại reclaim job và upload bình thường.
#[tokio::test]
async fn crash_point_4_accepted_local_readable_and_worker_resumes() {
    let (_dir, db_path, spool_dir) = setup_test_env().await;
    let conn = db::Db::open_sqlite(&db_path).await.unwrap();

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
        &conn,
        "crash-bkt",
        "local-obj",
        "v-local-1",
        13,
        "etag_local",
        "text/plain",
        None,
        None,
        &[chunk_spec],
        "job-local-1",
    )
    .await
    .unwrap();

    // Trạng thái object là accepted-local
    let v = db::latest_version(&conn, "crash-bkt", "local-obj")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v.storage_state, "accepted-local");

    // Worker chưa upload: GET đọc trực tiếp từ spool local
    let chunks = db::chunks_of(&conn, "v-local-1").await.unwrap();
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
        &telecrate::db::now_str(),
    )
    .await
    .unwrap();

    let chunks_after = db::chunks_of(&conn, "v-local-1").await.unwrap();
    assert_eq!(chunks_after[0].state, "remote");
}

/// Crash Point 5: Worker upload thành công lên Telegram nhưng worker crash trước khi commit DB remote locator.
/// Phục hồi: Lease hết hạn, worker tiếp theo reclaim job, generation guard & mock upload dedup an toàn.
#[tokio::test]
async fn crash_point_5_worker_crash_before_remote_db_commit() {
    let (_dir, db_path, spool_dir) = setup_test_env().await;
    let conn = db::Db::open_sqlite(&db_path).await.unwrap();

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
        &conn,
        "crash-bkt",
        "worker-obj",
        "v-w-1",
        14,
        "etag_w",
        "text/plain",
        None,
        None,
        &[chunk_spec],
        "job-w-1",
    )
    .await
    .unwrap();

    // Giả lập worker 1 claim lease và crash (để lease hết hạn trong quá khứ)
    db::force_job_lease(
        &conn,
        "job-w-1",
        "uploading",
        Some("worker-dead"),
        Some("2000-01-01 00:00:00"),
        Some("2000-01-01 00:00:00"),
    )
    .await
    .unwrap();

    let mock_transport = telecrate::telegram::MockTransport::default();
    // Worker 2 reclaim job hết hạn và hoàn thành
    let processed = telecrate::worker::process_one_job(
        &conn,
        &mock_transport,
        200,
        true,
        "worker-alive",
        &telecrate::db::now_str(),
    )
    .await
    .unwrap();
    assert!(processed);

    let chunks = db::chunks_of(&conn, "v-w-1").await.unwrap();
    assert_eq!(chunks[0].state, "remote");
}

/// Crash Point 6: Remote commit thành công nhưng crash trước khi GC spool file.
/// Phục hồi: GC worker chạy lại idempotent, kiểm tra state == 'remote' và refcount == 0, giải phóng spool file an toàn.
#[tokio::test]
async fn crash_point_6_remote_committed_before_spool_gc() {
    let (_dir, db_path, spool_dir) = setup_test_env().await;
    let conn = db::Db::open_sqlite(&db_path).await.unwrap();

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
        &conn,
        "crash-bkt",
        "gc-obj",
        "v-gc-1",
        10,
        "etag_gc",
        "text/plain",
        None,
        None,
        &[chunk_spec],
        "job-gc-1",
    )
    .await
    .unwrap();

    let mock_transport = telecrate::telegram::MockTransport::default();
    telecrate::worker::process_one_job(
        &conn,
        &mock_transport,
        300,
        true,
        "w-gc",
        &telecrate::db::now_str(),
    )
    .await
    .unwrap();

    // Sau khi process_one_job thành công, spool file đã được dọn dẹp an toàn qua GC
    assert!(!chunk_file.exists());

    let chunks = db::chunks_of(&conn, "v-gc-1").await.unwrap();
    assert_eq!(chunks[0].state, "remote");
    assert!(chunks[0].spool_path.is_none());
}

/// Crash Point 7: Interrupted `.tmp` file during Multipart `UploadPart`.
/// Phục hồi: `reconcile_spool` dọn dẹp `.tmp` part dở dang.
#[tokio::test]
async fn crash_point_7_multipart_interrupted_part_tmp() {
    let (_dir, db_path, spool_dir) = setup_test_env().await;
    let conn = db::Db::open_sqlite(&db_path).await.unwrap();

    let upload_id = "upload-crash-7";
    db::create_multipart_upload(
        &conn,
        upload_id,
        "crash-bkt",
        "mp-key-7",
        "text/plain",
        None,
    )
    .await
    .unwrap();

    let tmp_part = std::path::Path::new(&spool_dir).join(format!("{upload_id}_p1.tmp"));
    std::fs::write(&tmp_part, b"interrupted part tmp payload").unwrap();
    assert!(tmp_part.exists());

    let active_spools = db::active_spool_paths(&conn).await.unwrap();
    let (tmps_cleared, chunks_cleared) =
        spool::reconcile_spool(std::path::Path::new(&spool_dir), &active_spools).unwrap();

    assert_eq!(tmps_cleared, 1);
    assert_eq!(chunks_cleared, 0);
    assert!(!tmp_part.exists());
}

/// Crash Point 8: Part `.chunk` written to spool but process crashes before `save_multipart_part` DB commit.
/// Phục hồi: `reconcile_spool` dọn chunk mồ côi vì chưa có record trong `multipart_parts`.
#[tokio::test]
async fn crash_point_8_multipart_part_renamed_before_db_commit() {
    let (_dir, db_path, spool_dir) = setup_test_env().await;
    let conn = db::Db::open_sqlite(&db_path).await.unwrap();

    let upload_id = "upload-crash-8";
    db::create_multipart_upload(
        &conn,
        upload_id,
        "crash-bkt",
        "mp-key-8",
        "text/plain",
        None,
    )
    .await
    .unwrap();

    let orphan_part = std::path::Path::new(&spool_dir).join(format!("{upload_id}_p1.chunk"));
    write_durable(&orphan_part, b"uncommitted part content").unwrap();
    assert!(orphan_part.exists());

    let active_spools = db::active_spool_paths(&conn).await.unwrap();
    let (tmps_cleared, chunks_cleared) =
        spool::reconcile_spool(std::path::Path::new(&spool_dir), &active_spools).unwrap();

    assert_eq!(tmps_cleared, 0);
    assert_eq!(chunks_cleared, 1);
    assert!(!orphan_part.exists());
}

/// Crash Point 9: Client calls `AbortMultipartUpload` after uploading parts.
/// Phục hồi: DB records xóa hoàn toàn và toàn bộ spool_paths của parts được dọn dẹp sạch đĩa.
#[tokio::test]
async fn crash_point_9_abort_multipart_cleans_spool() {
    let (_dir, db_path, spool_dir) = setup_test_env().await;
    let conn = db::Db::open_sqlite(&db_path).await.unwrap();

    let upload_id = "upload-crash-9";
    db::create_multipart_upload(
        &conn,
        upload_id,
        "crash-bkt",
        "mp-key-9",
        "text/plain",
        None,
    )
    .await
    .unwrap();

    let part1_file = std::path::Path::new(&spool_dir).join(format!("{upload_id}_p1.chunk"));
    let part2_file = std::path::Path::new(&spool_dir).join(format!("{upload_id}_p2.chunk"));
    write_durable(&part1_file, b"part1 data").unwrap();
    write_durable(&part2_file, b"part2 data").unwrap();

    db::save_multipart_part(
        &conn,
        upload_id,
        1,
        10,
        "\"etag1\"",
        "hash1",
        "hash1",
        Some(part1_file.to_str().unwrap()),
    )
    .await
    .unwrap();
    db::save_multipart_part(
        &conn,
        upload_id,
        2,
        10,
        "\"etag2\"",
        "hash2",
        "hash2",
        Some(part2_file.to_str().unwrap()),
    )
    .await
    .unwrap();

    let spool_paths = db::abort_multipart_upload(&conn, upload_id).await.unwrap();
    assert_eq!(spool_paths.len(), 2);
    for p in spool_paths {
        let _ = std::fs::remove_file(p);
    }

    assert!(!part1_file.exists());
    assert!(!part2_file.exists());
    assert!(db::get_multipart_upload(&conn, upload_id)
        .await
        .unwrap()
        .is_none());
}

/// Crash Point 10: `CompleteMultipartUpload` DB commit succeeds, but process crashes before HTTP response.
/// Phục hồi: Object version được khởi tạo ở trạng thái `accepted-local`, GET đọc được từ spool, worker background resume upload.
#[tokio::test]
async fn crash_point_10_complete_multipart_crash_recovery() {
    let (_dir, db_path, spool_dir) = setup_test_env().await;
    let conn = db::Db::open_sqlite(&db_path).await.unwrap();

    let upload_id = "upload-crash-10";
    db::create_multipart_upload(
        &conn,
        upload_id,
        "crash-bkt",
        "mp-key-10",
        "text/plain",
        None,
    )
    .await
    .unwrap();

    let part1_file = std::path::Path::new(&spool_dir).join(format!("{upload_id}_p1.chunk"));
    let part2_file = std::path::Path::new(&spool_dir).join(format!("{upload_id}_p2.chunk"));
    write_durable(&part1_file, b"part1 content ").unwrap();
    write_durable(&part2_file, b"part2 content").unwrap();

    let etag1 = "\"0123456789abcdef0123456789abcdef\"";
    let etag2 = "\"fedcba9876543210fedcba9876543210\"";

    db::save_multipart_part(
        &conn,
        upload_id,
        1,
        14,
        etag1,
        "hash10_1",
        "hash10_1",
        Some(part1_file.to_str().unwrap()),
    )
    .await
    .unwrap();
    db::save_multipart_part(
        &conn,
        upload_id,
        2,
        13,
        etag2,
        "hash10_2",
        "hash10_2",
        Some(part2_file.to_str().unwrap()),
    )
    .await
    .unwrap();

    let req_parts = vec![(1, etag1.to_string()), (2, etag2.to_string())];
    let version_id = "v-mp-10";
    let job_id = "job-mp-10";

    let (_old_spools, version) =
        db::complete_multipart_upload_txn(&conn, upload_id, version_id, &req_parts, job_id)
            .await
            .unwrap();

    assert_eq!(version.version_id, "v-mp-10");
    assert_eq!(version.storage_state, "accepted-local");

    // Client crash trước HTTP response. Node khởi động lại: GET đọc được local spool data
    let chunks = db::chunks_of(&conn, "v-mp-10").await.unwrap();
    assert_eq!(chunks.len(), 2);
    let mut full_body = Vec::new();
    for c in &chunks {
        let b = std::fs::read(c.spool_path.as_ref().unwrap()).unwrap();
        full_body.extend_from_slice(&b);
    }
    assert_eq!(full_body, b"part1 content part2 content");

    // Worker resume upload nền
    let mock_transport = telecrate::telegram::MockTransport::default();
    let processed = telecrate::worker::process_one_job(
        &conn,
        &mock_transport,
        1000,
        true,
        "w-mp-10",
        &telecrate::db::now_str(),
    )
    .await
    .unwrap();
    assert!(processed);

    let chunks_after = db::chunks_of(&conn, "v-mp-10").await.unwrap();
    assert_eq!(chunks_after[0].state, "remote");
    assert_eq!(chunks_after[1].state, "remote");
}

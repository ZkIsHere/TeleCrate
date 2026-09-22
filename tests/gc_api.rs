//! Integration test cho Garbage Collection Engine.

use telecrate::db::*;
use telecrate::gc::*;
use telecrate::telegram::{MockTransport, Transport};
use tempfile::tempdir;

#[tokio::test]
async fn test_integration_gc_spool_remote_and_multipart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("gc_integration.db");
    let spool_dir = dir.path().join("spool");
    std::fs::create_dir_all(&spool_dir).unwrap();

    let conn = Db::open_sqlite(db_path.to_str().unwrap()).await.unwrap();
    apply_all_migrations(&conn).await.unwrap();

    let mock = MockTransport::default();
    let loc = mock.upload(200, b"data").unwrap();
    let loc_json = serde_json::to_string(&loc).unwrap();

    create_bucket(&conn, "gc-bucket", "telecrate-1")
        .await
        .unwrap();

    // 1. Spool chunk committed -> spool file should be deleted
    let spool1 = spool_dir.join("c1.chunk");
    std::fs::write(&spool1, b"committed chunk data").unwrap();

    put_object(
        &conn,
        "gc-bucket",
        "file1.bin",
        "v1",
        20,
        "etag",
        "application/octet-stream",
        None,
        None,
        &[NewChunk {
            offset: 0,
            length: 20,
            plaintext_sha256: "sha1".into(),
            ciphertext_sha256: "sha1".into(),
            spool_path: spool1.to_str().unwrap().into(),
            mode: "none".into(),
            key_ref: None,
        }],
        "j1",
    )
    .await
    .unwrap();

    telecrate::db::set_chunk_state(&conn, "v1", "telegram-committed")
        .await
        .unwrap();

    // 2. Deleted object version with remote locator -> should be deleted on Telegram
    put_object(
        &conn,
        "gc-bucket",
        "file2.bin",
        "v2-del",
        200,
        "etag",
        "application/octet-stream",
        None,
        None,
        &[NewChunk {
            offset: 0,
            length: 200,
            plaintext_sha256: "sha2".into(),
            ciphertext_sha256: "sha2".into(),
            spool_path: "/dummy".into(),
            mode: "none".into(),
            key_ref: None,
        }],
        "j2",
    )
    .await
    .unwrap();

    telecrate::db::set_chunk_locator(&conn, "v2-del", 0, &loc_json)
        .await
        .unwrap();

    telecrate::db::flag_object_delete_marker(&conn, "v2-del", true)
        .await
        .unwrap();

    // 3. Orphan multipart part -> should be cleaned up
    let orphan_part_spool = spool_dir.join("orphan_part.chunk");
    std::fs::write(&orphan_part_spool, b"part data").unwrap();

    {
        let raw = rusqlite::Connection::open(&db_path).unwrap();
        raw.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        raw.execute(
            "INSERT INTO multipart_parts (upload_id, part_number, size, etag, plaintext_sha256, ciphertext_sha256, spool_path, state)
             VALUES ('dead-upload', 1, 9, 'e', 'p', 'c', ?1, 'pending')",
            [orphan_part_spool.to_str().unwrap()],
        )
        .unwrap();
    }

    // 4. Run GC
    let stats = run_gc(&conn, &spool_dir, Some(&mock)).await.unwrap();

    assert!(stats.spool_files_deleted >= 1);
    assert!(!spool1.exists());
    assert_eq!(stats.telegram_messages_deleted, 1);
    assert_eq!(stats.orphaned_parts_cleaned, 1);
    assert!(!orphan_part_spool.exists());
}

//! Integration test cho Garbage Collection Engine.

use telecrate::db::*;
use telecrate::gc::*;
use telecrate::telegram::{MockTransport, Transport};
use tempfile::tempdir;

#[test]
fn test_integration_gc_spool_remote_and_multipart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("gc_integration.db");
    let spool_dir = dir.path().join("spool");
    std::fs::create_dir_all(&spool_dir).unwrap();

    let mut conn = open(db_path.to_str().unwrap()).unwrap();
    apply_all_migrations(&mut conn).unwrap();

    let mock = MockTransport::default();
    let loc = mock.upload(200, b"data").unwrap();
    let loc_json = serde_json::to_string(&loc).unwrap();

    create_bucket(&conn, "gc-bucket", "telecrate-1").unwrap();

    // 1. Spool chunk committed -> spool file should be deleted
    let spool1 = spool_dir.join("c1.chunk");
    std::fs::write(&spool1, b"committed chunk data").unwrap();

    put_object(
        &mut conn,
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
    .unwrap();

    conn.execute(
        "UPDATE chunks SET state = 'telegram-committed' WHERE version_id = 'v1'",
        [],
    )
    .unwrap();

    // 2. Deleted object version with remote locator -> should be deleted on Telegram
    put_object(
        &mut conn,
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
    .unwrap();

    conn.execute(
        "UPDATE chunks SET remote_locator_json = ? WHERE version_id = 'v2-del'",
        [loc_json],
    )
    .unwrap();

    conn.execute(
        "UPDATE objects SET is_delete_marker = 1 WHERE version_id = 'v2-del'",
        [],
    )
    .unwrap();

    // 3. Orphan multipart part -> should be cleaned up
    let orphan_part_spool = spool_dir.join("orphan_part.chunk");
    std::fs::write(&orphan_part_spool, b"part data").unwrap();

    conn.execute("PRAGMA foreign_keys = OFF;", []).unwrap();
    conn.execute(
        "INSERT INTO multipart_parts (upload_id, part_number, size, etag, plaintext_sha256, ciphertext_sha256, spool_path, state)
         VALUES ('dead-upload', 1, 9, 'e', 'p', 'c', ?, 'pending')",
        [orphan_part_spool.to_str().unwrap()],
    )
    .unwrap();
    conn.execute("PRAGMA foreign_keys = ON;", []).unwrap();

    // 4. Run GC
    let stats = run_gc(&conn, &spool_dir, Some(&mock)).unwrap();

    assert!(stats.spool_files_deleted >= 1);
    assert!(!spool1.exists());
    assert_eq!(stats.telegram_messages_deleted, 1);
    assert_eq!(stats.orphaned_parts_cleaned, 1);
    assert!(!orphan_part_spool.exists());
}

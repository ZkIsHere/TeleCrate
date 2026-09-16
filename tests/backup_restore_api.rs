//! Integration test cho DB Backup & Restore Engine.

use telecrate::db::*;
use tempfile::tempdir;

#[test]
fn test_integration_backup_restore_plain_and_encrypted() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("main.db");
    let plain_backup = dir.path().join("backup_plain.db");
    let enc_backup = dir.path().join("backup_enc.db.enc");
    let restored_db = dir.path().join("restored.db");

    // 1. Tạo DB nguồn với nhiều dữ liệu
    let mut conn = open(db_path.to_str().unwrap()).unwrap();
    apply_all_migrations(&mut conn).unwrap();

    create_bucket(&conn, "bucket-alpha", "telecrate-1").unwrap();
    create_bucket(&conn, "bucket-beta", "telecrate-1").unwrap();

    put_object(
        &mut conn,
        "bucket-alpha",
        "file1.txt",
        "v1",
        100,
        "etag-1",
        "text/plain",
        None,
        None,
        &[NewChunk {
            offset: 0,
            length: 100,
            plaintext_sha256: "sha-plain".into(),
            ciphertext_sha256: "sha-cipher".into(),
            spool_path: "/spool/path1".into(),
            mode: "none".into(),
            key_ref: None,
        }],
        "job-1",
    )
    .unwrap();

    set_object_legal_hold(&conn, "bucket-alpha", "file1.txt", "v1", true).unwrap();

    // 2. Backup plain & restore
    backup_db(&conn, plain_backup.to_str().unwrap()).unwrap();
    assert!(plain_backup.exists());

    restore_db(
        plain_backup.to_str().unwrap(),
        restored_db.to_str().unwrap(),
        None,
    )
    .unwrap();

    let restored_conn = open(restored_db.to_str().unwrap()).unwrap();
    assert!(head_bucket(&restored_conn, "bucket-alpha").unwrap());
    assert!(head_bucket(&restored_conn, "bucket-beta").unwrap());
    let ver = latest_version(&restored_conn, "bucket-alpha", "file1.txt")
        .unwrap()
        .unwrap();
    assert_eq!(ver.version_id, "v1");
    assert!(get_object_legal_hold(&restored_conn, "bucket-alpha", "file1.txt", "v1").unwrap());
    drop(restored_conn);

    // 3. Backup encrypted & restore
    backup_db_encrypted(&conn, enc_backup.to_str().unwrap(), "super-passphrase").unwrap();
    assert!(enc_backup.exists());

    let err = restore_db(
        enc_backup.to_str().unwrap(),
        restored_db.to_str().unwrap(),
        Some("wrong"),
    );
    assert!(err.is_err());

    restore_db(
        enc_backup.to_str().unwrap(),
        restored_db.to_str().unwrap(),
        Some("super-passphrase"),
    )
    .unwrap();

    let restored_conn2 = open(restored_db.to_str().unwrap()).unwrap();
    assert!(head_bucket(&restored_conn2, "bucket-alpha").unwrap());
    assert!(get_object_legal_hold(&restored_conn2, "bucket-alpha", "file1.txt", "v1").unwrap());
}

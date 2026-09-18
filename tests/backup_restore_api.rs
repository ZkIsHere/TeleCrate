//! Integration test cho DB Backup & Restore Engine.

use telecrate::db::*;
use tempfile::tempdir;

#[tokio::test]
async fn test_integration_backup_restore_plain_and_encrypted() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("main.db");
    let plain_backup = dir.path().join("backup_plain.db");
    let enc_backup = dir.path().join("backup_enc.db.enc");
    let restored_db = dir.path().join("restored.db");

    // 1. Tạo DB nguồn với nhiều dữ liệu
    let conn = Db::open_sqlite(db_path.to_str().unwrap()).await.unwrap();
    apply_all_migrations(&conn).await.unwrap();

    create_bucket(&conn, "bucket-alpha", "telecrate-1")
        .await
        .unwrap();
    create_bucket(&conn, "bucket-beta", "telecrate-1")
        .await
        .unwrap();

    put_object(
        &conn,
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
    .await
    .unwrap();

    set_object_legal_hold(&conn, "bucket-alpha", "file1.txt", "v1", true)
        .await
        .unwrap();

    // 2. Backup plain & restore
    backup_db(&conn, plain_backup.to_str().unwrap())
        .await
        .unwrap();
    assert!(plain_backup.exists());

    restore_db(
        plain_backup.to_str().unwrap(),
        restored_db.to_str().unwrap(),
        None,
    )
    .await
    .unwrap();

    let restored_conn = Db::open_sqlite(restored_db.to_str().unwrap())
        .await
        .unwrap();
    assert!(head_bucket(&restored_conn, "bucket-alpha").await.unwrap());
    assert!(head_bucket(&restored_conn, "bucket-beta").await.unwrap());
    let ver = latest_version(&restored_conn, "bucket-alpha", "file1.txt")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ver.version_id, "v1");
    assert!(
        get_object_legal_hold(&restored_conn, "bucket-alpha", "file1.txt", "v1")
            .await
            .unwrap()
    );
    drop(restored_conn);

    // 3. Backup encrypted & restore
    backup_db_encrypted(&conn, enc_backup.to_str().unwrap(), "super-passphrase")
        .await
        .unwrap();
    assert!(enc_backup.exists());

    let err = restore_db(
        enc_backup.to_str().unwrap(),
        restored_db.to_str().unwrap(),
        Some("wrong"),
    )
    .await;
    assert!(err.is_err());

    restore_db(
        enc_backup.to_str().unwrap(),
        restored_db.to_str().unwrap(),
        Some("super-passphrase"),
    )
    .await
    .unwrap();

    let restored_conn2 = Db::open_sqlite(restored_db.to_str().unwrap())
        .await
        .unwrap();
    assert!(head_bucket(&restored_conn2, "bucket-alpha").await.unwrap());
    assert!(
        get_object_legal_hold(&restored_conn2, "bucket-alpha", "file1.txt", "v1")
            .await
            .unwrap()
    );
}

//! Integration test cho Doctor, Spool Verification, Remote Scrubbing & Standalone Recovery Bundle.

use telecrate::db::*;
use telecrate::doctor::*;
use telecrate::recovery::*;
use telecrate::telegram::{MockTransport, Transport};
use tempfile::tempdir;

#[tokio::test]
async fn test_integration_doctor_recovery_bundle_and_scrub() {
    let dir = tempdir().unwrap();
    let src_db = dir.path().join("src.db");
    let restored_db = dir.path().join("restored.db");
    let spool_dir = dir.path().join("spool");
    let bundle_file = dir.path().join("recovery_bundle.json");
    let enc_bundle_file = dir.path().join("recovery_bundle.enc");
    std::fs::create_dir_all(&spool_dir).unwrap();

    let conn = Db::open_sqlite(src_db.to_str().unwrap()).await.unwrap();
    apply_all_migrations(&conn).await.unwrap();

    let mock = MockTransport::default();
    let loc = mock.upload(50, b"scrub data").unwrap();
    let loc_json = serde_json::to_string(&loc).unwrap();

    create_bucket(&conn, "doc-bucket", "telecrate-1")
        .await
        .unwrap();

    let spool1 = spool_dir.join("c1.chunk");
    let data1 = b"doctor data line 1";
    std::fs::write(&spool1, data1).unwrap();

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data1);
    let sha1 = hex::encode(hasher.finalize());

    put_object(
        &conn,
        "doc-bucket",
        "doc_file.txt",
        "v_doc_1",
        data1.len() as i64,
        "etag-doc",
        "text/plain",
        None,
        None,
        &[NewChunk {
            offset: 0,
            length: data1.len() as i64,
            plaintext_sha256: sha1.clone(),
            ciphertext_sha256: sha1.clone(),
            spool_path: spool1.to_str().unwrap().into(),
            mode: "none".into(),
            key_ref: None,
        }],
        "job_doc_1",
    )
    .await
    .unwrap();

    telecrate::db::exec(
        &conn,
        "UPDATE chunks SET remote_locator_json = ? WHERE version_id = 'v_doc_1'",
        &[Val::text(&loc_json)],
    )
    .await
    .unwrap();

    // 1. Doctor Report
    let doc_rep = run_doctor(&conn).await.unwrap();
    assert!(doc_rep.db_integrity_ok);
    assert!(doc_rep.foreign_keys_ok);
    assert_eq!(doc_rep.bucket_count, 1);
    assert_eq!(doc_rep.object_count, 1);
    assert_eq!(doc_rep.chunk_count, 1);

    // 2. Spool Verification Report
    let spool_rep = run_verify_spool(&conn, &spool_dir).await.unwrap();
    assert_eq!(spool_rep.missing_spool_chunks.len(), 0);
    assert_eq!(spool_rep.corrupt_checksum_files.len(), 0);

    // 3. Remote Scrub Report
    let scrub_rep = run_scrub_remote(&conn, &mock).await.unwrap();
    assert_eq!(scrub_rep.total_remote_chunks, 1);
    assert_eq!(scrub_rep.verified_ok, 1);
    assert_eq!(scrub_rep.missing_or_corrupt_remote.len(), 0);

    // 4. Recovery Bundle Export & Import
    export_recovery_bundle_file(&conn, bundle_file.to_str().unwrap(), None)
        .await
        .unwrap();
    assert!(bundle_file.exists());

    let restored_conn = Db::open_sqlite(restored_db.to_str().unwrap())
        .await
        .unwrap();
    import_recovery_bundle_file(bundle_file.to_str().unwrap(), &restored_conn, None)
        .await
        .unwrap();

    let ver = latest_version(&restored_conn, "doc-bucket", "doc_file.txt")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ver.version_id, "v_doc_1");

    // Encrypted Recovery Bundle Export & Import
    export_recovery_bundle_file(
        &conn,
        enc_bundle_file.to_str().unwrap(),
        Some("secret-bundle-pass"),
    )
    .await
    .unwrap();

    let restored_conn2 = Db::open_sqlite(dir.path().join("restored2.db").to_str().unwrap())
        .await
        .unwrap();
    let err = import_recovery_bundle_file(
        enc_bundle_file.to_str().unwrap(),
        &restored_conn2,
        Some("wrong-pass"),
    )
    .await;
    assert!(err.is_err());

    let restored_conn3 = Db::open_sqlite(dir.path().join("restored3.db").to_str().unwrap())
        .await
        .unwrap();
    import_recovery_bundle_file(
        enc_bundle_file.to_str().unwrap(),
        &restored_conn3,
        Some("secret-bundle-pass"),
    )
    .await
    .unwrap();
}

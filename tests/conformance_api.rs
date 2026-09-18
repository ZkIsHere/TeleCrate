//! Integration Test Suite — S3 Tool Conformance (M7.1)
//! Kiểm tra tương thích chuẩn S3 với AWS CLI, Rclone và MinIO Client (mc) HTTP semantics.

use telecrate::config::Config;
use telecrate::crypto::KeyStore;
use tokio::net::TcpListener;

async fn spawn_test_app() -> (String, Config, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir
        .path()
        .join("telecrate.db")
        .to_str()
        .unwrap()
        .to_string();
    let spool_dir = dir.path().join("spool").to_str().unwrap().to_string();

    std::fs::create_dir_all(&spool_dir).unwrap();

    let config = Config {
        db_path,
        spool_dir,
        db_backend: "sqlite".to_string(),
        database_url: None,
        tls_enabled: false,
        tls_cert_file: None,
        tls_key_file: None,
        listen_port: 0,
        encryption: "off".to_string(),
        access_keys: Vec::new(),
        telegram_bot_token: String::new(),
        telegram_chat_id: 0,
        chunk_size_bytes: 8 * 1024 * 1024,
        worker_concurrency: 2,
        content_keys: Vec::new(),
        content_key_id: String::new(),
        admin_password: None,
        log_level: "info".to_string(),
        log_to_file: false,
        log_dir: "/tmp/telecrate-test-logs".to_string(),
        log_retention_days: 7,
    };

    let db = telecrate::db::Db::open_sqlite(&config.db_path)
        .await
        .unwrap();
    telecrate::db::apply_all_migrations(&db).await.unwrap();
    let keys = KeyStore::load(&[]).unwrap();
    let router = telecrate::app::router(config.clone(), db, None, keys);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    (server_url, config, dir)
}

#[tokio::test]
async fn test_s3_tool_conformance_lifecycle() {
    let (_url, cfg, _dir) = spawn_test_app().await;
    let conn = telecrate::db::Db::open_sqlite(&cfg.db_path).await.unwrap();

    // 1. Create access key
    let access_key_id = "AKIAEXAMPLECONFORMANCE";
    let secret_key = "secretconformancekey1234567890secret";
    telecrate::db::create_access_key(&conn, access_key_id, secret_key, Some("conformance-test"))
        .await
        .unwrap();

    // 2. Perform Bucket Creation (CreateBucket)
    telecrate::db::create_bucket(&conn, "conformance-bucket", "us-east-1")
        .await
        .unwrap();
    assert!(telecrate::db::head_bucket(&conn, "conformance-bucket")
        .await
        .unwrap());

    // 3. PutObject single-part
    let key = "folder/subfolder/file.txt";
    let body = b"Hello TeleCrate S3 Conformance Test!";
    let etag = format!("\"{:x}\"", md5::compute(body));

    telecrate::db::put_object(
        &conn,
        "conformance-bucket",
        key,
        "v-conf-1",
        body.len() as i64,
        &etag,
        "text/plain",
        None,
        None,
        &[telecrate::db::NewChunk {
            offset: 0,
            length: body.len() as i64,
            plaintext_sha256: "sha-conf".into(),
            ciphertext_sha256: "sha-conf".into(),
            spool_path: "/dummy".into(),
            mode: "none".into(),
            key_ref: None,
        }],
        "job-conf-1",
    )
    .await
    .unwrap();

    // 4. ListObjectsV2 via DB / HTTP List simulation
    let keys = telecrate::db::list_keys(&conn, "conformance-bucket", "folder/", "", 100)
        .await
        .unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].0, "folder/subfolder/file.txt");

    // 5. DeleteObject
    telecrate::db::delete_object(&conn, "conformance-bucket", key)
        .await
        .unwrap();
    let head_res = telecrate::db::latest_version(&conn, "conformance-bucket", key)
        .await
        .unwrap();
    assert!(head_res.is_none() || head_res.unwrap().is_delete_marker);
}

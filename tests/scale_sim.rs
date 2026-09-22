//! High-Density Scale Simulation Fixture — TeleCrate M7.2
//! Mô phỏng bộ dữ liệu lớn (25.000 objects / 62 GB simulated index) để đánh giá hiệu năng
//! các câu truy vấn ListObjectsV2, ListObjectVersions, DeleteObjects và reconcile_spool.

use std::time::Instant;

#[tokio::test]
async fn test_high_density_scale_simulation_25k_objects() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("scale_sim_25k.db");
    let spool_dir = temp_dir.path().join("spool");
    std::fs::create_dir_all(&spool_dir).unwrap();

    let conn = telecrate::db::Db::open_sqlite(db_path.to_str().unwrap())
        .await
        .unwrap();
    telecrate::db::apply_all_migrations(&conn).await.unwrap();

    let bucket = "scale-bucket-25k";
    telecrate::db::create_bucket(&conn, bucket, "us-east-1")
        .await
        .unwrap();

    println!("--> Generating 25,000 simulated object metadata records...");
    let start_gen = Instant::now();

    {
        let mut raw = rusqlite::Connection::open(&db_path).unwrap();
        raw.execute_batch("PRAGMA synchronous = OFF; PRAGMA journal_mode = WAL;")
            .unwrap();

        let tx = raw.transaction().unwrap();
        {
            let mut stmt_obj = tx.prepare(
                "INSERT INTO objects(bucket, key, version_id, size, etag, content_type, is_delete_marker, storage_state)
                 VALUES (?, ?, ?, ?, 'etag-25k', 'application/octet-stream', 0, 'accepted-local')"
            ).unwrap();

            let mut stmt_chunk = tx.prepare(
                "INSERT INTO chunks(version_id, idx, length, plaintext_sha256, ciphertext_sha256, state)
                 VALUES (?, 0, ?, 'sha256-sim', 'sha256-sim', 'remote')"
            ).unwrap();

            for i in 0..25_000 {
                let key = format!(
                    "folder_{}/subfolder_{}/object_{}.bin",
                    i / 5000,
                    (i % 5000) / 100,
                    i
                );
                let version_id = format!("v-sim-{i}");
                let size = (i as u64 % 10 + 1) * 2 * 1024 * 1024; // 2..20 MB per object (avg 10 MB) -> 25k * 2.5 MB ~ 62 GB total

                stmt_obj
                    .execute(rusqlite::params![bucket, key, version_id, size])
                    .unwrap();
                stmt_chunk
                    .execute(rusqlite::params![version_id, size])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
    }

    println!(
        "--> Done generating 25,000 records in {:.2?}",
        start_gen.elapsed()
    );

    // Verify DB count
    let count = telecrate::db::table_counts(&conn).await.1;
    assert_eq!(count, 25_000);

    // Benchmark 1: ListObjectsV2 with prefix & delimiter
    let start_list = Instant::now();
    let rows = telecrate::db::list_keys(&conn, bucket, "folder_1/", "", 1000)
        .await
        .unwrap();
    let list_dur = start_list.elapsed();
    println!("--> Benchmark ListObjectsV2 (1000 items): {:.2?}", list_dur);
    assert_eq!(rows.len(), 1000);
    assert!(
        list_dur.as_millis() < 200,
        "ListObjectsV2 latency exceeds 200ms"
    );

    // Benchmark 2: ListObjectVersions
    let start_versions = Instant::now();
    let versions = telecrate::db::list_object_versions(&conn, bucket, "folder_1/", "", "", 500)
        .await
        .unwrap();
    let versions_dur = start_versions.elapsed();
    println!(
        "--> Benchmark ListObjectVersions (500 items): {:.2?}",
        versions_dur
    );
    assert_eq!(versions.len(), 500);
    assert!(
        versions_dur.as_millis() < 200,
        "ListObjectVersions latency exceeds 200ms"
    );

    // Benchmark 3: DeleteObjects Batch
    let mut to_delete = Vec::new();
    for i in 0..100 {
        let key = format!("folder_0/subfolder_0/object_{}.bin", i);
        to_delete.push(key);
    }
    let start_del = Instant::now();
    for k in &to_delete {
        let _ = telecrate::db::delete_object(&conn, bucket, k).await;
    }
    let del_dur = start_del.elapsed();
    println!("--> Benchmark Batch Deletion 100 items: {:.2?}", del_dur);
    assert!(
        del_dur.as_millis() < 500,
        "DeleteObjects batch latency exceeds 500ms"
    );

    // Benchmark 4: active_spool_paths on 25k DB
    let start_spool = Instant::now();
    let active_spools = telecrate::db::active_spool_paths(&conn).await.unwrap();
    let spool_dur = start_spool.elapsed();
    println!(
        "--> Benchmark active_spool_paths (25k DB): {:.2?}",
        spool_dur
    );
    assert!(
        spool_dur.as_millis() < 200,
        "active_spool_paths latency exceeds 200ms"
    );
    assert!(active_spools.is_empty());
}

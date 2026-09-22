//! Module Garbage Collection (GC Engine) — dọn dẹp spool local và message Telegram.

use crate::db::Db;
use crate::telegram::{RemoteLocator, Transport};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcStats {
    pub spool_files_deleted: usize,
    pub spool_bytes_freed: u64,
    pub telegram_messages_deleted: usize,
    pub orphaned_parts_cleaned: usize,
    pub errors: Vec<String>,
}

/// Thực thi Garbage Collection cho spool local và remote Telegram.
pub async fn run_gc(
    db: &Db,
    spool_dir: &Path,
    transport: Option<&dyn Transport>,
) -> Result<GcStats, String> {
    let mut stats = GcStats::default();

    // 1. Spool GC: Dọn dẹp spool file của các chunk đã remote nhưng còn spool
    // (worker crash giữa remote-commit và spool-cleanup).
    if let Ok(spool_rows) = crate::db::remote_spool_chunks(db).await {
        for (chunk_version_id, idx, spool_path) in spool_rows {
            let path = Path::new(&spool_path);
            if path.exists() {
                if let Ok(meta) = std::fs::metadata(path) {
                    stats.spool_bytes_freed += meta.len();
                }
                if std::fs::remove_file(path).is_ok() {
                    stats.spool_files_deleted += 1;
                    let _ = crate::db::clear_chunk_spool_path(db, &chunk_version_id, idx).await;
                }
            } else {
                let _ = crate::db::clear_chunk_spool_path(db, &chunk_version_id, idx).await;
            }
        }
    }

    // Dọn dẹp spool files mồ côi không nằm trong bất kỳ active_spool nào của DB
    if let Ok(active_set) = crate::db::active_spool_paths(db).await {
        if let Ok(entries) = std::fs::read_dir(spool_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file()
                    && !active_set.contains(&p)
                    && p.extension().and_then(|s| s.to_str()) == Some("chunk")
                {
                    let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    if std::fs::remove_file(&p).is_ok() {
                        stats.spool_files_deleted += 1;
                        stats.spool_bytes_freed += len;
                    }
                }
            }
        }
    }

    // 2. Telegram Remote GC: Xóa remote Telegram blob của các object version đã bị xóa/tombstoned
    // Ràng buộc: KHÔNG xóa nếu version đang được bảo vệ bởi Object Lock Retention hoặc Legal Hold!
    if let Some(tr) = transport {
        let now_iso = crate::db::now_str();

        if let Ok(locators) = crate::db::deletable_telegram_locators(db, &now_iso).await {
            for (version_id, idx, locator_json) in locators {
                if let Ok(locator) = serde_json::from_str::<RemoteLocator>(&locator_json) {
                    match tr.delete(&locator) {
                        Ok(_) => {
                            stats.telegram_messages_deleted += 1;
                            let _ = crate::db::clear_chunk_locator(db, &version_id, idx).await;
                        }
                        Err(e) => {
                            stats.errors.push(format!(
                                "delete message for version {version_id}/{idx}: {e:?}"
                            ));
                        }
                    }
                }
            }
        }
    }

    // 3. Multipart GC: Dọn dẹp parts của multipart upload bị abort hoặc expired
    if let Ok(cleaned) = crate::db::clean_orphan_multipart_parts(db).await {
        stats.orphaned_parts_cleaned += cleaned;
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::*;
    use crate::telegram::MockTransport;

    #[tokio::test]
    async fn test_spool_gc_and_orphan_cleanup() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("gc.db");
        let spool_dir = temp_dir.path().join("spool");
        std::fs::create_dir_all(&spool_dir).unwrap();

        let conn = Db::open_sqlite(db_path.to_str().unwrap()).await.unwrap();
        apply_all_migrations(&conn).await.unwrap();

        // Create a dummy spool file for a committed chunk
        let dummy_chunk_path = spool_dir.join("c1.chunk");
        std::fs::write(&dummy_chunk_path, b"hello chunk data").unwrap();

        create_bucket(&conn, "bkt", "r").await.unwrap();
        put_object(
            &conn,
            "bkt",
            "k1",
            "v1",
            16,
            "etag",
            "text/plain",
            None,
            None,
            &[NewChunk {
                offset: 0,
                length: 16,
                plaintext_sha256: "s1".into(),
                ciphertext_sha256: "s1".into(),
                spool_path: dummy_chunk_path.to_str().unwrap().into(),
                mode: "none".into(),
                key_ref: None,
            }],
            "job1",
        )
        .await
        .unwrap();

        // Mark chunk uploaded (spool chưa dọn — GC phải xử lý).
        crate::db::set_chunk_state(&conn, "v1", "remote")
            .await
            .unwrap();

        // Create an orphan chunk file on disk
        let orphan_path = spool_dir.join("orphan.chunk");
        std::fs::write(&orphan_path, b"orphan data").unwrap();

        let stats = run_gc(&conn, &spool_dir, None).await.unwrap();
        assert_eq!(stats.spool_files_deleted, 2);
        assert!(!dummy_chunk_path.exists());
        assert!(!orphan_path.exists());
    }

    #[tokio::test]
    async fn test_remote_telegram_gc_respects_object_lock() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("gc_lock.db");
        let spool_dir = temp_dir.path().join("spool");
        std::fs::create_dir_all(&spool_dir).unwrap();

        let conn = Db::open_sqlite(db_path.to_str().unwrap()).await.unwrap();
        apply_all_migrations(&conn).await.unwrap();

        let mock = MockTransport::default();
        let loc = mock.upload(100, b"data").unwrap();
        let loc_json = serde_json::to_string(&loc).unwrap();

        create_bucket(&conn, "bkt-lock", "r").await.unwrap();

        // 1. Version v-deleted with legal hold -> NOT deleted by GC
        put_object(
            &conn,
            "bkt-lock",
            "k-locked",
            "v-locked",
            4,
            "etag",
            "text/plain",
            None,
            None,
            &[NewChunk {
                offset: 0,
                length: 4,
                plaintext_sha256: "s".into(),
                ciphertext_sha256: "s".into(),
                spool_path: "/dummy".into(),
                mode: "none".into(),
                key_ref: None,
            }],
            "j1",
        )
        .await
        .unwrap();
        crate::db::set_chunk_locator(&conn, "v-locked", 0, &loc_json)
            .await
            .unwrap();
        crate::db::flag_object_delete_marker(&conn, "v-locked", true)
            .await
            .unwrap();
        set_bucket_object_lock_config(
            &conn,
            "bkt-lock",
            &ObjectLockConfig {
                status: "Enabled".into(),
                default_retention_mode: None,
                default_retention_days: None,
            },
        )
        .await
        .unwrap();
        set_object_legal_hold(&conn, "bkt-lock", "k-locked", "v-locked", true)
            .await
            .unwrap();

        let stats = run_gc(&conn, &spool_dir, Some(&mock)).await.unwrap();
        assert_eq!(stats.telegram_messages_deleted, 0);

        // Turn off legal hold -> GC deletes remote message
        set_object_legal_hold(&conn, "bkt-lock", "k-locked", "v-locked", false)
            .await
            .unwrap();
        let stats = run_gc(&conn, &spool_dir, Some(&mock)).await.unwrap();
        assert_eq!(stats.telegram_messages_deleted, 1);
    }
}

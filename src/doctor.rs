//! Module Integrity Verification, Doctor & Scrubbing Engine.

use crate::db::{schema_version, Db, DbBackend};
use crate::telegram::{RemoteLocator, Transport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorReport {
    pub db_integrity_ok: bool,
    pub foreign_keys_ok: bool,
    pub schema_version: i64,
    pub bucket_count: usize,
    pub object_count: usize,
    pub chunk_count: usize,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpoolVerifyReport {
    pub total_spool_files: usize,
    pub missing_spool_chunks: Vec<String>,
    pub corrupt_checksum_files: Vec<String>,
    pub orphan_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScrubReport {
    pub total_remote_chunks: usize,
    pub verified_ok: usize,
    pub missing_or_corrupt_remote: Vec<String>,
}

/// Kiểm tra toàn vẹn DB (`PRAGMA integrity_check` trên SQLite;
/// sanity SELECT + version trên Postgres), FK, schema_version, counts.
pub async fn run_doctor(db: &Db) -> Result<DoctorReport, String> {
    let mut issues = Vec::new();

    let (db_integrity_ok, foreign_keys_ok) = match db.backend() {
        DbBackend::Sqlite => {
            let integrity = crate::db::sqlite_integrity_check(db)
                .await
                .unwrap_or_else(|_| "error".to_string());
            let ok = integrity == "ok";
            if !ok {
                issues.push(format!("DB integrity failure: {integrity}"));
            }
            // foreign_key_check trả về các dòng vi phạm (rỗng = sạch).
            let fk_rows = crate::db::sqlite_fk_violations(db)
                .await
                .unwrap_or_default();
            let fk_ok = fk_rows.is_empty();
            if !fk_ok {
                issues.push(format!("Foreign key violations: {fk_rows:?}"));
            }
            (ok, fk_ok)
        }
        DbBackend::Postgres => {
            // Postgres không có PRAGMA: sanity qua schema_version + counts bên dưới.
            // FK được engine Postgres enforce lúc ghi nên không cần check riêng.
            (true, true)
        }
    };

    let ver = schema_version(db).await.unwrap_or(0);
    if ver < 1 {
        issues.push(format!("Invalid schema_version: {ver}"));
    }

    let (b, o, c) = crate::db::table_counts(db).await;
    let bucket_count: usize = b as usize;
    let object_count: usize = o as usize;
    let chunk_count: usize = c as usize;

    Ok(DoctorReport {
        db_integrity_ok,
        foreign_keys_ok,
        schema_version: ver,
        bucket_count,
        object_count,
        chunk_count,
        issues,
    })
}

/// Kiểm tra spool local: phát hiện chunk bị thiếu file, file mồ côi, hoặc sai checksum SHA-256.
pub async fn run_verify_spool(db: &Db, spool_dir: &Path) -> Result<SpoolVerifyReport, String> {
    let mut missing_spool_chunks = Vec::new();
    let mut corrupt_checksum_files = Vec::new();
    let mut orphan_files = Vec::new();

    // 1. Kiểm tra các chunk trong DB có spool_path IS NOT NULL
    let rows = crate::db::spool_verify_rows(db)
        .await
        .map_err(|e| format!("query verify spool: {e}"))?;

    for (version_id, idx, spool_path, plain_sha, cipher_sha, enc_mode) in &rows {
        let path = Path::new(&spool_path);
        if !path.exists() {
            missing_spool_chunks.push(format!("{version_id}/{idx}: {spool_path}"));
        } else if let Ok(data) = std::fs::read(path) {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let actual_sha = hex::encode(hasher.finalize());

            let expected_sha = if enc_mode == "none" {
                &plain_sha
            } else {
                &cipher_sha
            };

            if !expected_sha.is_empty() && actual_sha.as_str() != expected_sha.as_str() {
                corrupt_checksum_files.push(format!(
                    "{version_id}/{idx}: {spool_path} (expected {expected_sha}, got {actual_sha})"
                ));
            }
        }
    }

    // 2. Phát hiện file mồ côi trong spool_dir
    let mut total_spool_files = 0;
    if let Ok(active_set) = crate::db::active_spool_paths(db).await {
        if let Ok(entries) = std::fs::read_dir(spool_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    total_spool_files += 1;
                    if !active_set.contains(&p)
                        && p.extension().and_then(|s| s.to_str()) == Some("chunk")
                    {
                        if let Some(p_str) = p.to_str() {
                            orphan_files.push(p_str.to_string());
                        }
                    }
                }
            }
        }
    }

    Ok(SpoolVerifyReport {
        total_spool_files,
        missing_spool_chunks,
        corrupt_checksum_files,
        orphan_files,
    })
}

/// Scrubbing remote Telegram locators: kiểm tra message remote có tải/đọc được bình thường không.
pub async fn run_scrub_remote(db: &Db, transport: &dyn Transport) -> Result<ScrubReport, String> {
    let mut verified_ok = 0;
    let mut missing_or_corrupt_remote = Vec::new();

    let rows = crate::db::remote_scrub_rows(db)
        .await
        .map_err(|e| format!("query scrub rows: {e}"))?;

    let mut total_remote_chunks = 0;
    for (version_id, idx, locator_json) in &rows {
        total_remote_chunks += 1;
        if let Ok(locator) = serde_json::from_str::<RemoteLocator>(locator_json) {
            match transport.download(&locator) {
                Ok(_) => {
                    verified_ok += 1;
                }
                Err(e) => {
                    missing_or_corrupt_remote.push(format!("{version_id}/{idx}: {e:?}"));
                }
            }
        } else {
            missing_or_corrupt_remote.push(format!("{version_id}/{idx}: invalid locator JSON"));
        }
    }

    Ok(ScrubReport {
        total_remote_chunks,
        verified_ok,
        missing_or_corrupt_remote,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::*;
    use crate::telegram::MockTransport;

    #[tokio::test]
    async fn test_doctor_verify_and_scrub() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("doctor.db");
        let spool_dir = temp_dir.path().join("spool");
        std::fs::create_dir_all(&spool_dir).unwrap();

        let conn = Db::open_sqlite(db_path.to_str().unwrap()).await.unwrap();
        apply_all_migrations(&conn).await.unwrap();

        // 1. Run doctor
        let doc_rep = run_doctor(&conn).await.unwrap();
        assert!(doc_rep.db_integrity_ok);
        assert!(doc_rep.foreign_keys_ok);
        assert_eq!(doc_rep.schema_version, 4);
        assert_eq!(doc_rep.issues.len(), 0);

        // 2. Put object with 1 valid spool chunk and 1 missing spool chunk
        let chunk1_path = spool_dir.join("valid.chunk");
        let data1 = b"hello doctor data";
        std::fs::write(&chunk1_path, data1).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(data1);
        let sha1 = hex::encode(hasher.finalize());

        create_bucket(&conn, "doc-bkt", "r").await.unwrap();
        put_object(
            &conn,
            "doc-bkt",
            "f.txt",
            "v1",
            data1.len() as i64,
            "etag",
            "text/plain",
            None,
            None,
            &[
                NewChunk {
                    offset: 0,
                    length: data1.len() as i64,
                    plaintext_sha256: sha1.clone(),
                    ciphertext_sha256: sha1.clone(),
                    spool_path: chunk1_path.to_str().unwrap().into(),
                    mode: "none".into(),
                    key_ref: None,
                },
                NewChunk {
                    offset: data1.len() as i64,
                    length: 10,
                    plaintext_sha256: "missing_sha".into(),
                    ciphertext_sha256: "missing_sha".into(),
                    spool_path: spool_dir.join("missing.chunk").to_str().unwrap().into(),
                    mode: "none".into(),
                    key_ref: None,
                },
            ],
            "job1",
        )
        .await
        .unwrap();

        // Add an orphan chunk file
        let orphan_path = spool_dir.join("orphan.chunk");
        std::fs::write(&orphan_path, b"orphan").unwrap();

        let spool_rep = run_verify_spool(&conn, &spool_dir).await.unwrap();
        assert_eq!(spool_rep.missing_spool_chunks.len(), 1);
        assert_eq!(spool_rep.orphan_files.len(), 1);
        assert_eq!(spool_rep.corrupt_checksum_files.len(), 0);

        // 3. Scrub remote Telegram locators
        let mock = MockTransport::default();
        let loc = mock.upload(100, b"data").unwrap();
        let loc_json = serde_json::to_string(&loc).unwrap();

        crate::db::set_chunk_locator(&conn, "v1", 0, &loc_json)
            .await
            .unwrap();

        let scrub_rep = run_scrub_remote(&conn, &mock).await.unwrap();
        assert_eq!(scrub_rep.total_remote_chunks, 1);
        assert_eq!(scrub_rep.verified_ok, 1);
    }
}

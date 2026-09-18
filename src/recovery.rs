//! Module Standalone Recovery Bundle — Export/Import toàn bộ metadata index để tái tạo DB khi hỏng.

use crate::db::{apply_all_migrations, Db, Val};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const REC_BUNDLE_MAGIC: &[u8] = b"TELECRATE_REC_BUNDLE_V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BucketRecord {
    pub name: String,
    pub region: String,
    pub versioning_status: String,
    pub encryption_override: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectRecord {
    pub bucket: String,
    pub key: String,
    pub version_id: String,
    pub is_delete_marker: bool,
    pub storage_state: String,
    pub size: i64,
    pub etag: String,
    pub content_type: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkRecord {
    pub version_id: String,
    pub idx: i32,
    pub offset: i64,
    pub length: i64,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub encryption_mode: String,
    pub key_ref: Option<String>,
    pub nonce: Option<String>,
    pub spool_path: Option<String>,
    pub remote_locator_json: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectLockRecord {
    pub bucket: String,
    pub key: String,
    pub version_id: String,
    pub retain_until_date: Option<String>,
    pub mode: Option<String>,
    pub legal_hold: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryBundle {
    pub version: u32,
    pub created_at: String,
    pub buckets: Vec<BucketRecord>,
    pub objects: Vec<ObjectRecord>,
    pub chunks: Vec<ChunkRecord>,
    pub object_locks: Vec<ObjectLockRecord>,
}

/// Export toàn bộ metadata index thành RecoveryBundle struct.
pub async fn export_recovery_bundle(db: &Db) -> Result<RecoveryBundle, String> {
    let now_iso = crate::db::now_str();

    // 1. Buckets
    let rows = crate::db::fetch_all(
        db,
        "SELECT name, region, versioning_status, encryption_override, created_at FROM buckets",
        &[],
    )
    .await
    .map_err(|e| format!("query buckets export: {e}"))?;
    let mut buckets = Vec::new();
    for r in &rows {
        buckets.push(BucketRecord {
            name: r
                .get_string(0)
                .map_err(|e| format!("row buckets export: {e}"))?,
            region: r
                .get_string(1)
                .map_err(|e| format!("row buckets export: {e}"))?,
            versioning_status: r
                .get_string(2)
                .map_err(|e| format!("row buckets export: {e}"))?,
            encryption_override: r
                .get_opt_string(3)
                .map_err(|e| format!("row buckets export: {e}"))?,
            created_at: r
                .get_string(4)
                .map_err(|e| format!("row buckets export: {e}"))?,
        });
    }

    // 2. Objects
    let rows = crate::db::fetch_all(
        db,
        "SELECT bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type, created_at FROM objects",
        &[],
    )
    .await
    .map_err(|e| format!("query objects export: {e}"))?;
    let mut objects = Vec::new();
    for r in &rows {
        objects.push(ObjectRecord {
            bucket: r
                .get_string(0)
                .map_err(|e| format!("row objects export: {e}"))?,
            key: r
                .get_string(1)
                .map_err(|e| format!("row objects export: {e}"))?,
            version_id: r
                .get_string(2)
                .map_err(|e| format!("row objects export: {e}"))?,
            is_delete_marker: r
                .get_bool(3)
                .map_err(|e| format!("row objects export: {e}"))?,
            storage_state: r
                .get_string(4)
                .map_err(|e| format!("row objects export: {e}"))?,
            size: r
                .get_i64(5)
                .map_err(|e| format!("row objects export: {e}"))?,
            etag: r
                .get_string(6)
                .map_err(|e| format!("row objects export: {e}"))?,
            content_type: r
                .get_string(7)
                .map_err(|e| format!("row objects export: {e}"))?,
            created_at: r
                .get_string(8)
                .map_err(|e| format!("row objects export: {e}"))?,
        });
    }

    // 3. Chunks
    let rows = crate::db::fetch_all(
        db,
        "SELECT version_id, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref, nonce, spool_path, remote_locator_json, state FROM chunks",
        &[],
    )
    .await
    .map_err(|e| format!("query chunks export: {e}"))?;
    let mut chunks = Vec::new();
    for r in &rows {
        chunks.push(ChunkRecord {
            version_id: r
                .get_string(0)
                .map_err(|e| format!("row chunks export: {e}"))?,
            idx: r
                .get_i32(1)
                .map_err(|e| format!("row chunks export: {e}"))?,
            offset: r
                .get_i64(2)
                .map_err(|e| format!("row chunks export: {e}"))?,
            length: r
                .get_i64(3)
                .map_err(|e| format!("row chunks export: {e}"))?,
            plaintext_sha256: r
                .get_string(4)
                .map_err(|e| format!("row chunks export: {e}"))?,
            ciphertext_sha256: r
                .get_string(5)
                .map_err(|e| format!("row chunks export: {e}"))?,
            encryption_mode: r
                .get_string(6)
                .map_err(|e| format!("row chunks export: {e}"))?,
            key_ref: r
                .get_opt_string(7)
                .map_err(|e| format!("row chunks export: {e}"))?,
            nonce: r
                .get_opt_string(8)
                .map_err(|e| format!("row chunks export: {e}"))?,
            spool_path: r
                .get_opt_string(9)
                .map_err(|e| format!("row chunks export: {e}"))?,
            remote_locator_json: r
                .get_opt_string(10)
                .map_err(|e| format!("row chunks export: {e}"))?,
            state: r
                .get_string(11)
                .map_err(|e| format!("row chunks export: {e}"))?,
        });
    }

    // 4. Object Locks
    let rows = crate::db::fetch_all(
        db,
        "SELECT bucket, key, version_id, retain_until_date, mode, legal_hold FROM object_locks",
        &[],
    )
    .await
    .map_err(|e| format!("query locks export: {e}"))?;
    let mut object_locks = Vec::new();
    for r in &rows {
        object_locks.push(ObjectLockRecord {
            bucket: r
                .get_string(0)
                .map_err(|e| format!("row locks export: {e}"))?,
            key: r
                .get_string(1)
                .map_err(|e| format!("row locks export: {e}"))?,
            version_id: r
                .get_string(2)
                .map_err(|e| format!("row locks export: {e}"))?,
            retain_until_date: r
                .get_opt_string(3)
                .map_err(|e| format!("row locks export: {e}"))?,
            mode: r
                .get_opt_string(4)
                .map_err(|e| format!("row locks export: {e}"))?,
            legal_hold: r
                .get_bool(5)
                .map_err(|e| format!("row locks export: {e}"))?,
        });
    }

    Ok(RecoveryBundle {
        version: 1,
        created_at: now_iso,
        buckets,
        objects,
        chunks,
        object_locks,
    })
}

/// Export RecoveryBundle ra file (plain JSON hoặc mã hóa passphrase).
pub async fn export_recovery_bundle_file(
    db: &Db,
    output_path: &str,
    passphrase: Option<&str>,
) -> Result<(), String> {
    let bundle = export_recovery_bundle(db).await?;
    let json_bytes =
        serde_json::to_vec_pretty(&bundle).map_err(|e| format!("serialize bundle: {e}"))?;

    if let Some(pass) = passphrase {
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut salt).map_err(|e| format!("getrandom salt: {e}"))?;
        getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("getrandom nonce: {e}"))?;

        let mut hasher = Sha256::new();
        hasher.update(pass.as_bytes());
        hasher.update(salt);
        let key_bytes = hasher.finalize();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let mut buf = json_bytes;
        cipher
            .encrypt_in_place(Nonce::from_slice(&nonce_bytes), REC_BUNDLE_MAGIC, &mut buf)
            .map_err(|e| format!("encrypt bundle: {e}"))?;

        let mut out = Vec::with_capacity(REC_BUNDLE_MAGIC.len() + 16 + 12 + buf.len());
        out.extend_from_slice(REC_BUNDLE_MAGIC);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&buf);

        if let Some(parent) = Path::new(output_path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| format!("create output dir: {e}"))?;
            }
        }
        std::fs::write(output_path, out).map_err(|e| format!("write enc bundle: {e}"))?;
    } else {
        if let Some(parent) = Path::new(output_path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| format!("create output dir: {e}"))?;
            }
        }
        std::fs::write(output_path, json_bytes).map_err(|e| format!("write plain bundle: {e}"))?;
    }
    Ok(())
}

/// Import RecoveryBundle từ file vào DB đích (đã có schema — apply migrations trước).
/// Chạy được cả hai backend (import logic qua queries, không copy file).
pub async fn import_recovery_bundle_file(
    input_path: &str,
    db: &Db,
    passphrase: Option<&str>,
) -> Result<(), String> {
    let raw = std::fs::read(input_path).map_err(|e| format!("read bundle file: {e}"))?;
    if raw.is_empty() {
        return Err("recovery bundle file is empty".into());
    }

    let json_bytes = if raw.starts_with(REC_BUNDLE_MAGIC) {
        let pass = passphrase.ok_or("encrypted bundle requires passphrase")?;
        if raw.len() < REC_BUNDLE_MAGIC.len() + 16 + 12 {
            return Err("encrypted bundle file is corrupted or truncated".into());
        }
        let salt = &raw[REC_BUNDLE_MAGIC.len()..REC_BUNDLE_MAGIC.len() + 16];
        let nonce = &raw[REC_BUNDLE_MAGIC.len() + 16..REC_BUNDLE_MAGIC.len() + 28];
        let ciphertext = &raw[REC_BUNDLE_MAGIC.len() + 28..];

        let mut hasher = Sha256::new();
        hasher.update(pass.as_bytes());
        hasher.update(salt);
        let key_bytes = hasher.finalize();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let mut buf = ciphertext.to_vec();
        cipher
            .decrypt_in_place(Nonce::from_slice(nonce), REC_BUNDLE_MAGIC, &mut buf)
            .map_err(|_| "decrypt bundle failed (wrong passphrase or tampered file)".to_string())?;
        buf
    } else {
        raw
    };

    let bundle: RecoveryBundle = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("parse recovery bundle JSON: {e}"))?;

    // Apply migrations trên DB đích rồi import trong 1 txn.
    apply_all_migrations(db).await?;

    let mut tx = db.begin().await?;

    // Restore Buckets
    for b in bundle.buckets {
        tx.exec(
            "INSERT INTO buckets(name, region, versioning_status, encryption_override, created_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(name) DO UPDATE SET
               region=excluded.region,
               versioning_status=excluded.versioning_status",
            &[
                Val::text(&b.name),
                Val::text(&b.region),
                Val::text(&b.versioning_status),
                Val::opt_text(b.encryption_override.as_deref()),
                Val::text(&b.created_at),
            ],
        )
        .await
        .map_err(|e| format!("restore bucket {}: {e}", b.name))?;
    }

    // Restore Objects
    for o in bundle.objects {
        tx.exec(
            "INSERT INTO objects(bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(version_id) DO NOTHING",
            &[
                Val::text(&o.bucket),
                Val::text(&o.key),
                Val::text(&o.version_id),
                Val::int(o.is_delete_marker as i64),
                Val::text(&o.storage_state),
                Val::int(o.size),
                Val::text(&o.etag),
                Val::text(&o.content_type),
                Val::text(&o.created_at),
            ],
        )
        .await
        .map_err(|e| format!("restore object {}: {e}", o.version_id))?;
    }

    // Restore Chunks
    for c in bundle.chunks {
        tx.exec(
            "INSERT INTO chunks(version_id, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref, nonce, spool_path, remote_locator_json, state)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(version_id, idx) DO NOTHING",
            &[
                Val::text(&c.version_id),
                Val::int(c.idx as i64),
                Val::int(c.offset),
                Val::int(c.length),
                Val::text(&c.plaintext_sha256),
                Val::text(&c.ciphertext_sha256),
                Val::text(&c.encryption_mode),
                Val::opt_text(c.key_ref.as_deref()),
                Val::opt_text(c.nonce.as_deref()),
                Val::opt_text(c.spool_path.as_deref()),
                Val::opt_text(c.remote_locator_json.as_deref()),
                Val::text(&c.state),
            ],
        )
        .await
        .map_err(|e| format!("restore chunk {}/{}: {e}", c.version_id, c.idx))?;
    }

    // Restore Object Locks
    for l in bundle.object_locks {
        tx.exec(
            "INSERT INTO object_locks(bucket, key, version_id, retain_until_date, mode, legal_hold)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(bucket, key, version_id) DO NOTHING",
            &[
                Val::text(&l.bucket),
                Val::text(&l.key),
                Val::text(&l.version_id),
                Val::opt_text(l.retain_until_date.as_deref()),
                Val::opt_text(l.mode.as_deref()),
                Val::int(l.legal_hold as i64),
            ],
        )
        .await
        .map_err(|e| format!("restore lock {}/{}: {e}", l.bucket, l.key))?;
    }

    tx.commit()
        .await
        .map_err(|e| format!("commit import tx: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::*;

    #[tokio::test]
    async fn test_recovery_bundle_export_import_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src_db = temp_dir.path().join("src.db");
        let restored_db = temp_dir.path().join("restored.db");
        let plain_bundle = temp_dir.path().join("bundle.json");
        let enc_bundle = temp_dir.path().join("bundle.enc");

        let conn = Db::open_sqlite(src_db.to_str().unwrap()).await.unwrap();
        apply_all_migrations(&conn).await.unwrap();

        create_bucket(&conn, "rec-bucket", "telecrate-1")
            .await
            .unwrap();
        put_object(
            &conn,
            "rec-bucket",
            "hello.txt",
            "v100",
            12,
            "etag-100",
            "text/plain",
            None,
            None,
            &[NewChunk {
                offset: 0,
                length: 12,
                plaintext_sha256: "p1".into(),
                ciphertext_sha256: "c1".into(),
                spool_path: "/spool/chunk1".into(),
                mode: "none".into(),
                key_ref: None,
            }],
            "job100",
        )
        .await
        .unwrap();
        set_object_legal_hold(&conn, "rec-bucket", "hello.txt", "v100", true)
            .await
            .unwrap();

        // 1. Export plain bundle
        export_recovery_bundle_file(&conn, plain_bundle.to_str().unwrap(), None)
            .await
            .unwrap();
        assert!(plain_bundle.exists());

        // Import into clean DB
        let restored_conn = Db::open_sqlite(restored_db.to_str().unwrap())
            .await
            .unwrap();
        import_recovery_bundle_file(plain_bundle.to_str().unwrap(), &restored_conn, None)
            .await
            .unwrap();

        assert!(head_bucket(&restored_conn, "rec-bucket").await.unwrap());
        let ver = latest_version(&restored_conn, "rec-bucket", "hello.txt")
            .await
            .unwrap()
            .unwrap();
        let _chunks = chunks_of(&restored_conn, &ver.version_id).await.unwrap();
        assert_eq!(ver.version_id, "v100");
        let p1_count = count(
            &restored_conn,
            "SELECT COUNT(*) FROM chunks WHERE plaintext_sha256 = 'p1'",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(p1_count, 1);
        assert!(
            get_object_legal_hold(&restored_conn, "rec-bucket", "hello.txt", "v100")
                .await
                .unwrap()
        );

        // 2. Export encrypted bundle
        export_recovery_bundle_file(
            &conn,
            enc_bundle.to_str().unwrap(),
            Some("recovery-passphrase"),
        )
        .await
        .unwrap();
        assert!(enc_bundle.exists());

        // Import with wrong passphrase -> fails
        let restored_conn2 =
            Db::open_sqlite(temp_dir.path().join("restored2.db").to_str().unwrap())
                .await
                .unwrap();
        let res = import_recovery_bundle_file(
            enc_bundle.to_str().unwrap(),
            &restored_conn2,
            Some("wrong-pass"),
        )
        .await;
        assert!(res.is_err());

        // Import with correct passphrase -> succeeds
        let restored_conn3 =
            Db::open_sqlite(temp_dir.path().join("restored3.db").to_str().unwrap())
                .await
                .unwrap();
        import_recovery_bundle_file(
            enc_bundle.to_str().unwrap(),
            &restored_conn3,
            Some("recovery-passphrase"),
        )
        .await
        .unwrap();
    }
}

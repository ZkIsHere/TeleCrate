//! Module Standalone Recovery Bundle — Export/Import toàn bộ metadata index để tái tạo DB khi hỏng.

use crate::db::{apply_all_migrations, open};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use rusqlite::Connection;
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
pub fn export_recovery_bundle(conn: &Connection) -> Result<RecoveryBundle, String> {
    let now_iso: String = conn
        .query_row("SELECT datetime('now')", [], |r| r.get(0))
        .unwrap_or_default();

    // 1. Buckets
    let mut stmt = conn
        .prepare(
            "SELECT name, region, versioning_status, encryption_override, created_at FROM buckets",
        )
        .map_err(|e| format!("prepare buckets export: {e}"))?;
    let buckets = stmt
        .query_map([], |r| {
            Ok(BucketRecord {
                name: r.get(0)?,
                region: r.get(1)?,
                versioning_status: r.get(2)?,
                encryption_override: r.get(3)?,
                created_at: r.get(4)?,
            })
        })
        .map_err(|e| format!("query buckets export: {e}"))?
        .flatten()
        .collect();

    // 2. Objects
    let mut stmt = conn
        .prepare("SELECT bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type, created_at FROM objects")
        .map_err(|e| format!("prepare objects export: {e}"))?;
    let objects = stmt
        .query_map([], |r| {
            let dm: i32 = r.get(3)?;
            Ok(ObjectRecord {
                bucket: r.get(0)?,
                key: r.get(1)?,
                version_id: r.get(2)?,
                is_delete_marker: dm != 0,
                storage_state: r.get(4)?,
                size: r.get(5)?,
                etag: r.get(6)?,
                content_type: r.get(7)?,
                created_at: r.get(8)?,
            })
        })
        .map_err(|e| format!("query objects export: {e}"))?
        .flatten()
        .collect();

    // 3. Chunks
    let mut stmt = conn
        .prepare("SELECT version_id, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref, nonce, spool_path, remote_locator_json, state FROM chunks")
        .map_err(|e| format!("prepare chunks export: {e}"))?;
    let chunks = stmt
        .query_map([], |r| {
            Ok(ChunkRecord {
                version_id: r.get(0)?,
                idx: r.get(1)?,
                offset: r.get(2)?,
                length: r.get(3)?,
                plaintext_sha256: r.get(4)?,
                ciphertext_sha256: r.get(5)?,
                encryption_mode: r.get(6)?,
                key_ref: r.get(7)?,
                nonce: r.get(8)?,
                spool_path: r.get(9)?,
                remote_locator_json: r.get(10)?,
                state: r.get(11)?,
            })
        })
        .map_err(|e| format!("query chunks export: {e}"))?
        .flatten()
        .collect();

    // 4. Object Locks
    let mut stmt = conn
        .prepare(
            "SELECT bucket, key, version_id, retain_until_date, mode, legal_hold FROM object_locks",
        )
        .map_err(|e| format!("prepare locks export: {e}"))?;
    let object_locks = stmt
        .query_map([], |r| {
            let lh: i32 = r.get(5)?;
            Ok(ObjectLockRecord {
                bucket: r.get(0)?,
                key: r.get(1)?,
                version_id: r.get(2)?,
                retain_until_date: r.get(3)?,
                mode: r.get(4)?,
                legal_hold: lh != 0,
            })
        })
        .map_err(|e| format!("query locks export: {e}"))?
        .flatten()
        .collect();

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
pub fn export_recovery_bundle_file(
    conn: &Connection,
    output_path: &str,
    passphrase: Option<&str>,
) -> Result<(), String> {
    let bundle = export_recovery_bundle(conn)?;
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

/// Import RecoveryBundle từ file để tái tạo lại toàn bộ SQLite index từ đầu.
pub fn import_recovery_bundle_file(
    input_path: &str,
    target_db_path: &str,
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

    // Mở DB đích và apply migrations
    let mut conn = open(target_db_path)?;
    apply_all_migrations(&mut conn)?;

    let tx = conn.transaction().map_err(|e| format!("begin tx: {e}"))?;

    // Restore Buckets
    for b in bundle.buckets {
        tx.execute(
            "INSERT INTO buckets(name, region, versioning_status, encryption_override, created_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(name) DO UPDATE SET
               region=excluded.region,
               versioning_status=excluded.versioning_status",
            rusqlite::params![
                b.name,
                b.region,
                b.versioning_status,
                b.encryption_override,
                b.created_at
            ],
        )
        .map_err(|e| format!("restore bucket {}: {e}", b.name))?;
    }

    // Restore Objects
    for o in bundle.objects {
        tx.execute(
            "INSERT INTO objects(bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(version_id) DO NOTHING",
            rusqlite::params![
                o.bucket,
                o.key,
                o.version_id,
                if o.is_delete_marker { 1 } else { 0 },
                o.storage_state,
                o.size,
                o.etag,
                o.content_type,
                o.created_at
            ],
        )
        .map_err(|e| format!("restore object {}: {e}", o.version_id))?;
    }

    // Restore Chunks
    for c in bundle.chunks {
        tx.execute(
            "INSERT INTO chunks(version_id, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref, nonce, spool_path, remote_locator_json, state)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(version_id, idx) DO NOTHING",
            rusqlite::params![
                c.version_id,
                c.idx,
                c.offset,
                c.length,
                c.plaintext_sha256,
                c.ciphertext_sha256,
                c.encryption_mode,
                c.key_ref,
                c.nonce,
                c.spool_path,
                c.remote_locator_json,
                c.state
            ],
        )
        .map_err(|e| format!("restore chunk {}/{}: {e}", c.version_id, c.idx))?;
    }

    // Restore Object Locks
    for l in bundle.object_locks {
        tx.execute(
            "INSERT INTO object_locks(bucket, key, version_id, retain_until_date, mode, legal_hold)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(bucket, key, version_id) DO NOTHING",
            rusqlite::params![
                l.bucket,
                l.key,
                l.version_id,
                l.retain_until_date,
                l.mode,
                if l.legal_hold { 1 } else { 0 }
            ],
        )
        .map_err(|e| format!("restore lock {}/{}: {e}", l.bucket, l.key))?;
    }

    tx.commit().map_err(|e| format!("commit import tx: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::*;

    #[test]
    fn test_recovery_bundle_export_import_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src_db = temp_dir.path().join("src.db");
        let restored_db = temp_dir.path().join("restored.db");
        let plain_bundle = temp_dir.path().join("bundle.json");
        let enc_bundle = temp_dir.path().join("bundle.enc");

        let mut conn = open(src_db.to_str().unwrap()).unwrap();
        apply_all_migrations(&mut conn).unwrap();

        create_bucket(&conn, "rec-bucket", "telecrate-1").unwrap();
        put_object(
            &mut conn,
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
        .unwrap();
        set_object_legal_hold(&conn, "rec-bucket", "hello.txt", "v100", true).unwrap();

        // 1. Export plain bundle
        export_recovery_bundle_file(&conn, plain_bundle.to_str().unwrap(), None).unwrap();
        assert!(plain_bundle.exists());

        // Import into clean DB
        import_recovery_bundle_file(
            plain_bundle.to_str().unwrap(),
            restored_db.to_str().unwrap(),
            None,
        )
        .unwrap();

        let restored_conn = open(restored_db.to_str().unwrap()).unwrap();
        assert!(head_bucket(&restored_conn, "rec-bucket").unwrap());
        let ver = latest_version(&restored_conn, "rec-bucket", "hello.txt")
            .unwrap()
            .unwrap();
        let _chunks = chunks_of(&restored_conn, &ver.version_id).unwrap();
        assert_eq!(ver.version_id, "v100");
        let p1_count: i64 = restored_conn
            .query_row(
                "SELECT COUNT(*) FROM chunks WHERE plaintext_sha256 = 'p1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(p1_count, 1);
        assert!(get_object_legal_hold(&restored_conn, "rec-bucket", "hello.txt", "v100").unwrap());
        drop(restored_conn);

        // 2. Export encrypted bundle
        export_recovery_bundle_file(
            &conn,
            enc_bundle.to_str().unwrap(),
            Some("recovery-passphrase"),
        )
        .unwrap();
        assert!(enc_bundle.exists());

        // Import with wrong passphrase -> fails
        let res = import_recovery_bundle_file(
            enc_bundle.to_str().unwrap(),
            restored_db.to_str().unwrap(),
            Some("wrong-pass"),
        );
        assert!(res.is_err());

        // Import with correct passphrase -> succeeds
        import_recovery_bundle_file(
            enc_bundle.to_str().unwrap(),
            restored_db.to_str().unwrap(),
            Some("recovery-passphrase"),
        )
        .unwrap();
    }
}

//! Module Standalone Recovery Bundle — Export/Import toàn bộ metadata index để tái tạo DB khi hỏng.

use crate::db::{apply_all_migrations, Db};
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

    use crate::db::entities::{buckets, chunks, object_locks, objects};
    use sea_orm::EntityTrait;
    let conn = db.sea_conn();

    // 1. Buckets
    let buckets = buckets::Entity::find()
        .all(&conn)
        .await
        .map_err(|e| format!("query buckets export: {e}"))?
        .into_iter()
        .map(|m| BucketRecord {
            name: m.name,
            region: m.region,
            versioning_status: m.versioning_status,
            encryption_override: m.encryption_override,
            created_at: m.created_at,
        })
        .collect();

    // 2. Objects
    let objects = objects::Entity::find()
        .all(&conn)
        .await
        .map_err(|e| format!("query objects export: {e}"))?
        .into_iter()
        .map(|m| ObjectRecord {
            bucket: m.bucket,
            key: m.key,
            version_id: m.version_id,
            is_delete_marker: m.is_delete_marker != 0,
            storage_state: m.storage_state,
            size: m.size,
            etag: m.etag,
            content_type: m.content_type,
            created_at: m.created_at,
        })
        .collect();

    // 3. Chunks
    let chunks = chunks::Entity::find()
        .all(&conn)
        .await
        .map_err(|e| format!("query chunks export: {e}"))?
        .into_iter()
        .map(|m| {
            Ok::<_, String>(ChunkRecord {
                version_id: m.version_id,
                idx: i32::try_from(m.idx)
                    .map_err(|_| "row chunks export: idx out of i32 range".to_string())?,
                offset: m.offset,
                length: m.length,
                plaintext_sha256: m.plaintext_sha256,
                ciphertext_sha256: m.ciphertext_sha256,
                encryption_mode: m.encryption_mode,
                key_ref: m.key_ref,
                nonce: m.nonce,
                spool_path: m.spool_path,
                remote_locator_json: m.remote_locator_json,
                state: m.state,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // 4. Object Locks
    let object_locks = object_locks::Entity::find()
        .all(&conn)
        .await
        .map_err(|e| format!("query locks export: {e}"))?
        .into_iter()
        .map(|m| ObjectLockRecord {
            bucket: m.bucket,
            key: m.key,
            version_id: m.version_id,
            retain_until_date: m.retain_until_date,
            mode: m.mode,
            legal_hold: m.legal_hold != 0,
        })
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

    use sea_orm::sea_query::OnConflict;
    use sea_orm::{EntityTrait, Set, TransactionTrait};
    let conn = db.sea_conn();
    let txn = conn.begin().await.map_err(|e| format!("begin txn: {e}"))?;

    // Restore Buckets
    for b in bundle.buckets {
        crate::db::entities::buckets::Entity::insert(crate::db::entities::buckets::ActiveModel {
            name: Set(b.name.clone()),
            region: Set(b.region.clone()),
            versioning_status: Set(b.versioning_status.clone()),
            encryption_override: Set(b.encryption_override.clone()),
            created_at: Set(b.created_at.clone()),
        })
        .on_conflict(
            OnConflict::columns([crate::db::entities::buckets::Column::Name])
                .update_columns([
                    crate::db::entities::buckets::Column::Region,
                    crate::db::entities::buckets::Column::VersioningStatus,
                ])
                .to_owned(),
        )
        .exec(&txn)
        .await
        .map_err(|e| format!("restore bucket {}: {e}", b.name))?;
    }

    // Restore Objects
    for o in bundle.objects {
        crate::db::entities::objects::Entity::insert(crate::db::entities::objects::ActiveModel {
            bucket: Set(o.bucket.clone()),
            key: Set(o.key.clone()),
            version_id: Set(o.version_id.clone()),
            is_delete_marker: Set(o.is_delete_marker as i64),
            storage_state: Set(o.storage_state.clone()),
            size: Set(o.size),
            etag: Set(o.etag.clone()),
            content_type: Set(o.content_type.clone()),
            created_at: Set(o.created_at.clone()),
            ..Default::default()
        })
        .on_conflict(
            OnConflict::columns([crate::db::entities::objects::Column::VersionId])
                .do_nothing()
                .to_owned(),
        )
        .exec(&txn)
        .await
        .map_err(|e| format!("restore object {}: {e}", o.version_id))?;
    }

    // Restore Chunks
    for c in bundle.chunks {
        // Mọi cột đều Set tường minh (khớp SQL cũ); `..Default` chỉ để đủ field.
        #[allow(clippy::needless_update)]
        let am = crate::db::entities::chunks::ActiveModel {
            version_id: Set(c.version_id.clone()),
            idx: Set(c.idx as i64),
            offset: Set(c.offset),
            length: Set(c.length),
            plaintext_sha256: Set(c.plaintext_sha256.clone()),
            ciphertext_sha256: Set(c.ciphertext_sha256.clone()),
            encryption_mode: Set(c.encryption_mode.clone()),
            key_ref: Set(c.key_ref.clone()),
            nonce: Set(c.nonce.clone()),
            spool_path: Set(c.spool_path.clone()),
            remote_locator_json: Set(c.remote_locator_json.clone()),
            state: Set(c.state.clone()),
            ..Default::default()
        };
        crate::db::entities::chunks::Entity::insert(am)
            .on_conflict(
                OnConflict::columns([
                    crate::db::entities::chunks::Column::VersionId,
                    crate::db::entities::chunks::Column::Idx,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec(&txn)
            .await
            .map_err(|e| format!("restore chunk {}/{}: {e}", c.version_id, c.idx))?;
    }

    // Restore Object Locks
    for l in bundle.object_locks {
        // `..Default` giữ `updated_at` theo DB default (như SQL cũ không set).
        #[allow(clippy::needless_update)]
        let am = crate::db::entities::object_locks::ActiveModel {
            bucket: Set(l.bucket.clone()),
            key: Set(l.key.clone()),
            version_id: Set(l.version_id.clone()),
            retain_until_date: Set(l.retain_until_date.clone()),
            mode: Set(l.mode.clone()),
            legal_hold: Set(l.legal_hold as i64),
            ..Default::default()
        };
        crate::db::entities::object_locks::Entity::insert(am)
            .on_conflict(
                OnConflict::columns([
                    crate::db::entities::object_locks::Column::Bucket,
                    crate::db::entities::object_locks::Column::Key,
                    crate::db::entities::object_locks::Column::VersionId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec(&txn)
            .await
            .map_err(|e| format!("restore lock {}/{}: {e}", l.bucket, l.key))?;
    }

    txn.commit()
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

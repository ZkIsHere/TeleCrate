//! DB layer — SQLite WAL, migrations forward-only.

use rusqlite::Connection;
use std::path::Path;

/// Mở DB (tạo file + bật WAL + foreign keys). Không giữ txn mở suốt network upload.
pub fn open(db_path: &str) -> Result<Connection, String> {
    if let Some(parent) = Path::new(db_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create db parent dir: {e}"))?;
        }
    }
    let conn = Connection::open(db_path).map_err(|e| format!("open db: {e}"))?;
    // WAL + FK + busy timeout 5s: daemon (HTTP + N worker) và CLI dùng chung DB,
    // writer chờ nhau thay vì SQLITE_BUSY ngay.
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
    )
    .map_err(|e| format!("pragma: {e}"))?;
    Ok(conn)
}

/// Lấy version migration hiện tại (0 nếu chưa có bảng).
pub fn schema_version(conn: &Connection) -> Result<i64, String> {
    let v: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(v)
}

/// Apply migration SQL một lần, ghi schema_version trong cùng txn.
pub fn apply_migration(conn: &mut Connection, version: i64, sql: &str) -> Result<(), String> {
    let tx = conn.transaction().map_err(|e| format!("begin txn: {e}"))?;
    tx.execute_batch(sql)
        .map_err(|e| format!("migration {version}: {e}"))?;
    tx.execute("INSERT INTO schema_version(version) VALUES (?)", [version])
        .map_err(|e| format!("record version: {e}"))?;
    tx.commit().map_err(|e| format!("commit: {e}"))?;
    Ok(())
}

pub const MIGRATION_001: &str = include_str!("../migrations/0001_init.sql");
pub const MIGRATION_002: &str = include_str!("../migrations/0002_m3_multipart_versioning.sql");

/// Apply tất cả migrations chưa apply từ 0 lên head.
pub fn apply_all_migrations(conn: &mut Connection) -> Result<i64, String> {
    let mut current = schema_version(conn)?;
    if current < 1 {
        apply_migration(conn, 1, MIGRATION_001)?;
        current = 1;
    }
    if current < 2 {
        apply_migration(conn, 2, MIGRATION_002)?;
        current = 2;
    }
    Ok(current)
}

/// Thông tin một Multipart Upload đang tiến hành.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartUpload {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub content_type: String,
    pub metadata_json: Option<String>,
    pub created_at: String,
}

/// Thông tin một Part của Multipart Upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartPart {
    pub upload_id: String,
    pub part_number: i32,
    pub size: i64,
    pub etag: String,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub spool_path: Option<String>,
    pub remote_locator_json: Option<String>,
    pub state: String,
    pub created_at: String,
}

/// Khởi tạo Multipart Upload mới. Trả về Error nếu bucket không tồn tại.
pub fn create_multipart_upload(
    conn: &Connection,
    upload_id: &str,
    bucket: &str,
    key: &str,
    content_type: &str,
    metadata_json: Option<&str>,
) -> Result<(), String> {
    if !head_bucket(conn, bucket)? {
        return Err("NoSuchBucket".to_string());
    }
    conn.execute(
        "INSERT INTO multipart_uploads(upload_id, bucket, key, content_type, metadata_json) VALUES (?, ?, ?, ?, ?)",
        rusqlite::params![upload_id, bucket, key, content_type, metadata_json],
    )
    .map_err(|e| format!("insert multipart_upload: {e}"))?;
    Ok(())
}

/// Lấy thông tin Multipart Upload theo upload_id.
pub fn get_multipart_upload(
    conn: &Connection,
    upload_id: &str,
) -> Result<Option<MultipartUpload>, String> {
    let mut stmt = conn
        .prepare("SELECT upload_id, bucket, key, content_type, metadata_json, created_at FROM multipart_uploads WHERE upload_id = ?")
        .map_err(|e| format!("prepare get multipart_upload: {e}"))?;
    let mut rows = stmt
        .query_map([upload_id], |r| {
            Ok(MultipartUpload {
                upload_id: r.get(0)?,
                bucket: r.get(1)?,
                key: r.get(2)?,
                content_type: r.get(3)?,
                metadata_json: r.get(4)?,
                created_at: r.get(5)?,
            })
        })
        .map_err(|e| format!("query get multipart_upload: {e}"))?;
    match rows.next() {
        Some(Ok(u)) => Ok(Some(u)),
        Some(Err(e)) => Err(format!("row multipart_upload: {e}")),
        None => Ok(None),
    }
}

/// Lưu hoặc cập nhật một Part của Multipart Upload.
#[allow(clippy::too_many_arguments)]
pub fn save_multipart_part(
    conn: &Connection,
    upload_id: &str,
    part_number: i32,
    size: i64,
    etag: &str,
    plaintext_sha256: &str,
    ciphertext_sha256: &str,
    spool_path: Option<&str>,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO multipart_parts(upload_id, part_number, size, etag, plaintext_sha256, ciphertext_sha256, spool_path)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(upload_id, part_number) DO UPDATE SET
            size=excluded.size, etag=excluded.etag, plaintext_sha256=excluded.plaintext_sha256,
            ciphertext_sha256=excluded.ciphertext_sha256, spool_path=excluded.spool_path, state='pending'",
        rusqlite::params![upload_id, part_number, size, etag, plaintext_sha256, ciphertext_sha256, spool_path],
    )
    .map_err(|e| format!("insert/update multipart_part: {e}"))?;
    Ok(())
}

/// Liệt kê các Part đã upload theo thứ tự part_number tăng dần.
pub fn list_multipart_parts(
    conn: &Connection,
    upload_id: &str,
) -> Result<Vec<MultipartPart>, String> {
    let mut stmt = conn
        .prepare("SELECT upload_id, part_number, size, etag, plaintext_sha256, ciphertext_sha256, spool_path, remote_locator_json, state, created_at
                  FROM multipart_parts WHERE upload_id = ? ORDER BY part_number ASC")
        .map_err(|e| format!("prepare list multipart_parts: {e}"))?;
    let rows = stmt
        .query_map([upload_id], |r| {
            Ok(MultipartPart {
                upload_id: r.get(0)?,
                part_number: r.get(1)?,
                size: r.get(2)?,
                etag: r.get(3)?,
                plaintext_sha256: r.get(4)?,
                ciphertext_sha256: r.get(5)?,
                spool_path: r.get(6)?,
                remote_locator_json: r.get(7)?,
                state: r.get(8)?,
                created_at: r.get(9)?,
            })
        })
        .map_err(|e| format!("query list multipart_parts: {e}"))?;
    let mut parts = Vec::new();
    for r in rows {
        parts.push(r.map_err(|e| format!("row multipart_part: {e}"))?);
    }
    Ok(parts)
}

/// Hủy Multipart Upload: xóa record DB và trả về danh sách spool_path để dọn đĩa.
pub fn abort_multipart_upload(
    conn: &mut Connection,
    upload_id: &str,
) -> Result<Vec<String>, String> {
    let parts = list_multipart_parts(conn, upload_id)?;
    let spool_paths: Vec<String> = parts.into_iter().filter_map(|p| p.spool_path).collect();

    let tx = conn.transaction().map_err(|e| format!("begin txn: {e}"))?;
    tx.execute(
        "DELETE FROM multipart_parts WHERE upload_id = ?",
        [upload_id],
    )
    .map_err(|e| format!("delete parts: {e}"))?;
    tx.execute(
        "DELETE FROM multipart_uploads WHERE upload_id = ?",
        [upload_id],
    )
    .map_err(|e| format!("delete upload: {e}"))?;
    tx.commit().map_err(|e| format!("commit: {e}"))?;

    Ok(spool_paths)
}

/// Liệt kê tất cả Multipart Uploads chưa hoàn thành của một bucket.
pub fn list_multipart_uploads(
    conn: &Connection,
    bucket: &str,
) -> Result<Vec<MultipartUpload>, String> {
    let mut stmt = conn
        .prepare("SELECT upload_id, bucket, key, content_type, metadata_json, created_at FROM multipart_uploads WHERE bucket = ? ORDER BY created_at ASC")
        .map_err(|e| format!("prepare list multipart_uploads: {e}"))?;
    let rows = stmt
        .query_map([bucket], |r| {
            Ok(MultipartUpload {
                upload_id: r.get(0)?,
                bucket: r.get(1)?,
                key: r.get(2)?,
                content_type: r.get(3)?,
                metadata_json: r.get(4)?,
                created_at: r.get(5)?,
            })
        })
        .map_err(|e| format!("query list multipart_uploads: {e}"))?;
    let mut uploads = Vec::new();
    for r in rows {
        uploads.push(r.map_err(|e| format!("row list multipart_uploads: {e}"))?);
    }
    Ok(uploads)
}

fn get_bucket_versioning_tx(tx: &rusqlite::Transaction, bucket: &str) -> Result<String, String> {
    let mut stmt = tx
        .prepare("SELECT versioning_status FROM buckets WHERE name = ?")
        .map_err(|e| format!("prepare: {e}"))?;
    let mut rows = stmt
        .query_map([bucket], |r| r.get(0))
        .map_err(|e| format!("query: {e}"))?;
    match rows.next() {
        Some(r) => r.map_err(|e| format!("row: {e}")),
        None => Ok("Disabled".to_string()),
    }
}

fn prepare_versioning_write_tx(
    tx: &rusqlite::Transaction,
    bucket: &str,
    key: &str,
    requested_version_id: &str,
) -> Result<(String, Vec<String>), String> {
    let v_status = get_bucket_versioning_tx(tx, bucket)?;
    let final_version_id = if v_status == "Suspended" {
        "null".to_string()
    } else if v_status == "Enabled" {
        if requested_version_id == "null" || requested_version_id.is_empty() {
            uuid::Uuid::new_v4().simple().to_string()
        } else {
            requested_version_id.to_string()
        }
    } else {
        requested_version_id.to_string()
    };

    let mut old_spools = Vec::new();
    if v_status == "Enabled" {
        // Preserves existing versions
    } else if v_status == "Suspended" {
        // Overwrite existing "null" version
        let null_spools: Vec<String> = tx
            .prepare("SELECT spool_path FROM chunks WHERE version_id = 'null' AND version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)")
            .map_err(|e| format!("prepare: {e}"))?
            .query_map(rusqlite::params![bucket, key], |r| r.get(0))
            .map_err(|e| format!("query: {e}"))?
            .collect::<Result<Vec<Option<String>>, _>>()
            .map_err(|e| format!("rows: {e}"))?
            .into_iter()
            .flatten()
            .collect();
        old_spools.extend(null_spools);
        tx.execute("DELETE FROM upload_jobs WHERE version_id = 'null' AND version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)", rusqlite::params![bucket, key]).ok();
        tx.execute("DELETE FROM chunks WHERE version_id = 'null' AND version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)", rusqlite::params![bucket, key]).ok();
        tx.execute(
            "DELETE FROM objects WHERE bucket = ? AND key = ? AND version_id = 'null'",
            rusqlite::params![bucket, key],
        )
        .ok();
    } else {
        // Disabled: delete all previous versions
        let spools: Vec<String> = tx
            .prepare("SELECT spool_path FROM chunks WHERE version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)")
            .map_err(|e| format!("prepare: {e}"))?
            .query_map(rusqlite::params![bucket, key], |r| r.get(0))
            .map_err(|e| format!("query: {e}"))?
            .collect::<Result<Vec<Option<String>>, _>>()
            .map_err(|e| format!("rows: {e}"))?
            .into_iter()
            .flatten()
            .collect();
        old_spools.extend(spools);
        tx.execute("DELETE FROM upload_jobs WHERE version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)", rusqlite::params![bucket, key]).ok();
        tx.execute("DELETE FROM chunks WHERE version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)", rusqlite::params![bucket, key]).ok();
        tx.execute(
            "DELETE FROM objects WHERE bucket = ? AND key = ?",
            rusqlite::params![bucket, key],
        )
        .ok();
    }
    Ok((final_version_id, old_spools))
}

/// Hoàn tất Multipart Upload trong 1 SQLite txn duy nhất.
pub fn complete_multipart_upload_txn(
    conn: &mut Connection,
    upload_id: &str,
    version_id: &str,
    requested_parts: &[(i32, String)],
    job_id: &str,
) -> Result<(Vec<String>, ObjectVersion), String> {
    let upload =
        get_multipart_upload(conn, upload_id)?.ok_or_else(|| "NoSuchUpload".to_string())?;

    let parts = list_multipart_parts(conn, upload_id)?;
    if parts.is_empty() {
        return Err("InvalidRequest".to_string());
    }

    if requested_parts.len() != parts.len() {
        return Err("InvalidPart".to_string());
    }

    let mut total_size: i64 = 0;
    let mut part_etags_raw: Vec<u8> = Vec::new();

    for (req_num, req_etag) in requested_parts {
        let db_part = parts
            .iter()
            .find(|p| p.part_number == *req_num)
            .ok_or_else(|| "InvalidPart".to_string())?;

        let db_etag_norm = db_part.etag.trim_matches('"').trim().to_lowercase();
        let req_etag_norm = req_etag.trim_matches('"').trim().to_lowercase();

        if db_etag_norm != req_etag_norm {
            return Err("InvalidPart".to_string());
        }

        total_size += db_part.size;

        let etag_bytes = hex::decode(&db_etag_norm).map_err(|_| "InvalidPart".to_string())?;
        part_etags_raw.extend_from_slice(&etag_bytes);
    }

    // Compute S3 Multipart ETag: md5(concat(part_etags_raw)) + "-" + num_parts
    let combined_md5 = format!("{:x}", md5::compute(&part_etags_raw));
    let multipart_etag = format!("\"{combined_md5}-{}\"", parts.len());

    let bucket = upload.bucket.clone();
    let key = upload.key.clone();

    let tx = conn.transaction().map_err(|e| format!("begin txn: {e}"))?;

    let (final_version_id, old_spools) =
        prepare_versioning_write_tx(&tx, &bucket, &key, version_id)?;

    tx.execute(
        "INSERT INTO objects(bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type, user_metadata_json) VALUES (?, ?, ?, 0, 'accepted-local', ?, ?, ?, ?)",
        rusqlite::params![bucket, key, final_version_id, total_size, multipart_etag, upload.content_type, upload.metadata_json],
    )
    .map_err(|e| format!("insert object: {e}"))?;

    let mut current_offset: i64 = 0;
    for (idx, part) in parts.iter().enumerate() {
        let spool_path = part.spool_path.as_deref().unwrap_or("");
        tx.execute(
            "INSERT INTO chunks(version_id, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, spool_path, state) VALUES (?, ?, ?, ?, ?, ?, 'none', ?, 'pending')",
            rusqlite::params![final_version_id, idx as i64, current_offset, part.size, part.plaintext_sha256, part.ciphertext_sha256, spool_path],
        )
        .map_err(|e| format!("insert chunk: {e}"))?;
        current_offset += part.size;
    }

    tx.execute(
        "INSERT INTO upload_jobs(job_id, version_id, state) VALUES (?, ?, 'pending')",
        rusqlite::params![job_id, final_version_id],
    )
    .map_err(|e| format!("insert job: {e}"))?;

    tx.execute(
        "DELETE FROM multipart_parts WHERE upload_id = ?",
        [upload_id],
    )
    .map_err(|e| format!("delete parts: {e}"))?;
    tx.execute(
        "DELETE FROM multipart_uploads WHERE upload_id = ?",
        [upload_id],
    )
    .map_err(|e| format!("delete upload: {e}"))?;

    tx.commit().map_err(|e| format!("commit: {e}"))?;

    let version = latest_version(conn, &bucket, &key)?
        .ok_or_else(|| "Failed to fetch created object version".to_string())?;

    Ok((old_spools, version))
}

/// Một bucket trong index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    pub name: String,
    pub region: String,
    pub versioning_status: String,
    pub created_at: String,
}

pub fn get_bucket_versioning(conn: &Connection, bucket: &str) -> Result<String, String> {
    let mut stmt = conn
        .prepare("SELECT versioning_status FROM buckets WHERE name = ?")
        .map_err(|e| format!("prepare: {e}"))?;
    let mut rows = stmt
        .query_map([bucket], |r| r.get(0))
        .map_err(|e| format!("query: {e}"))?;
    match rows.next() {
        Some(r) => r.map_err(|e| format!("row: {e}")),
        None => Ok("Disabled".to_string()),
    }
}

pub fn set_bucket_versioning(
    conn: &mut Connection,
    bucket: &str,
    status: &str,
) -> Result<(), String> {
    let affected = conn
        .execute(
            "UPDATE buckets SET versioning_status = ? WHERE name = ?",
            rusqlite::params![status, bucket],
        )
        .map_err(|e| format!("execute update bucket versioning: {e}"))?;
    if affected == 0 {
        return Err("NoSuchBucket".to_string());
    }
    Ok(())
}

/// Chuẩn S3 bucket naming (rút gọn M2: 3-63 ký tự, chữ thường/số/dấu chấm/gạch nối,
/// bắt đầu-kết thúc bằng chữ/số). Chi tiết đầy đủ ở M3+ cùng virtual-hosted-style.
pub fn valid_bucket_name(name: &str) -> bool {
    if name.len() < 3 || name.len() > 63 {
        return false;
    }
    let b = name.as_bytes();
    if !b[0].is_ascii_alphanumeric() || !b[b.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'.' || *c == b'-')
        && !name.contains("..")
}

/// Kết quả tạo bucket — phân biệt created/đã sở hữu để trả 200 vs 409 đúng S3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateBucketOutcome {
    Created,
    AlreadyOwned,
}

/// Tạo bucket. Trả `AlreadyOwned` khi bucket đã tồn tại (S3: 200 nếu cùng owner).
pub fn create_bucket(
    conn: &Connection,
    name: &str,
    region: &str,
) -> Result<CreateBucketOutcome, String> {
    if !valid_bucket_name(name) {
        return Err("InvalidBucketName".to_string());
    }
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM buckets WHERE name = ?", [name], |r| {
            r.get(0)
        })
        .map_err(|e| format!("lookup bucket: {e}"))?;
    if n > 0 {
        return Ok(CreateBucketOutcome::AlreadyOwned);
    }
    conn.execute(
        "INSERT INTO buckets(name, region) VALUES (?, ?)",
        rusqlite::params![name, region],
    )
    .map_err(|e| format!("insert bucket: {e}"))?;
    Ok(CreateBucketOutcome::Created)
}

pub fn head_bucket(conn: &Connection, name: &str) -> Result<bool, String> {
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM buckets WHERE name = ?", [name], |r| {
            r.get(0)
        })
        .map_err(|e| format!("lookup bucket: {e}"))?;
    Ok(n > 0)
}

/// Xóa bucket — từ chối khi còn object/version (S3: 409 BucketNotEmpty).
pub fn delete_bucket(conn: &Connection, name: &str) -> Result<DeleteBucketOutcome, String> {
    if !head_bucket(conn, name)? {
        return Ok(DeleteBucketOutcome::NoSuchBucket);
    }
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM objects WHERE bucket = ?",
            [name],
            |r| r.get(0),
        )
        .map_err(|e| format!("count objects: {e}"))?;
    if n > 0 {
        return Ok(DeleteBucketOutcome::NotEmpty);
    }
    conn.execute("DELETE FROM buckets WHERE name = ?", [name])
        .map_err(|e| format!("delete bucket: {e}"))?;
    Ok(DeleteBucketOutcome::Deleted)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteBucketOutcome {
    Deleted,
    NoSuchBucket,
    NotEmpty,
}

pub fn list_buckets(conn: &Connection) -> Result<Vec<Bucket>, String> {
    let mut stmt = conn
        .prepare("SELECT name, region, versioning_status, created_at FROM buckets ORDER BY name")
        .map_err(|e| format!("prepare: {e}"))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(Bucket {
                name: r.get(0)?,
                region: r.get(1)?,
                versioning_status: r.get(2)?,
                created_at: r.get(3)?,
            })
        })
        .map_err(|e| format!("query: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("rows: {e}"))
}

// --- Objects M2.2 & M3.5 Versioning ---

/// Một object version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectVersion {
    pub version_id: String,
    pub key: String,
    pub is_delete_marker: bool,
    pub size: i64,
    pub etag: String,
    pub content_type: String,
    pub storage_state: String,
    pub created_at: String,
    pub user_metadata_json: Option<String>,
    pub system_metadata_json: Option<String>,
}

/// Item cho ListObjectVersions.
#[derive(Debug, Clone)]
pub struct VersionListItem {
    pub key: String,
    pub version_id: String,
    pub is_latest: bool,
    pub is_delete_marker: bool,
    pub size: i64,
    pub etag: String,
    pub created_at: String,
}

/// Metadata chunk để worker/GC/GET dùng (không SELECT * bừa bãi).
#[derive(Debug, Clone)]
pub struct ChunkRow {
    pub idx: i64,
    pub length: i64,
    pub spool_path: Option<String>,
    pub state: String,
    pub encryption_mode: String,
    pub key_ref: Option<String>,
}

/// Chunk mới để ghi trong `put_object`. Tách bạch plaintext checksum / ciphertext
/// checksum / ETag S3 (ETag nằm ở object, = MD5 plaintext).
#[derive(Debug, Clone)]
pub struct NewChunk {
    pub offset: i64,
    pub length: i64,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub spool_path: String,
    /// `none` | `aead-v1`.
    pub mode: String,
    /// Key id (chỉ khi mã hóa) — tra KeyStore khi đọc.
    pub key_ref: Option<String>,
}

/// Ghi object: thay hàng cũ cùng (bucket,key) + chèn version/chunks/job mới — MỘT txn.
#[allow(clippy::too_many_arguments)]
pub fn put_object(
    conn: &mut Connection,
    bucket: &str,
    key: &str,
    version_id: &str,
    size: i64,
    etag: &str,
    content_type: &str,
    user_metadata_json: Option<&str>,
    system_metadata_json: Option<&str>,
    chunks: &[NewChunk],
    job_id: &str,
) -> Result<(Vec<String>, String), String> {
    let tx = conn.transaction().map_err(|e| format!("begin: {e}"))?;

    let (final_version_id, old_spools) = prepare_versioning_write_tx(&tx, bucket, key, version_id)?;

    tx.execute(
        "INSERT INTO objects(bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type, user_metadata_json, system_metadata_json) VALUES (?, ?, ?, 0, 'accepted-local', ?, ?, ?, ?, ?)",
        rusqlite::params![bucket, key, final_version_id, size, etag, content_type, user_metadata_json, system_metadata_json],
    )
    .map_err(|e| format!("insert object: {e}"))?;
    for (idx, c) in chunks.iter().enumerate() {
        tx.execute(
            "INSERT INTO chunks(version_id, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref, spool_path, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
            rusqlite::params![final_version_id, idx as i64, c.offset, c.length, c.plaintext_sha256, c.ciphertext_sha256, c.mode, c.key_ref, c.spool_path],
        )
        .map_err(|e| format!("insert chunk: {e}"))?;
    }
    tx.execute(
        "INSERT INTO upload_jobs(job_id, version_id, state) VALUES (?, ?, 'pending')",
        rusqlite::params![job_id, final_version_id],
    )
    .map_err(|e| format!("insert job: {e}"))?;
    tx.commit().map_err(|e| format!("commit: {e}"))?;
    Ok((old_spools, final_version_id))
}

/// CopyObject: Sao chép object từ (src_bucket, src_key) sang (dest_bucket, dest_key).
/// Hỗ trợ zero-duplicate spool bằng cách tạo version_id mới và trỏ cùng các chunks/locators từ DB.
#[allow(clippy::too_many_arguments)]
pub fn copy_object_txn(
    conn: &mut Connection,
    src_bucket: &str,
    src_key: &str,
    dest_bucket: &str,
    dest_key: &str,
    new_version_id: &str,
    new_job_id: &str,
    metadata_directive: &str,
    override_content_type: Option<&str>,
    user_metadata_json: Option<&str>,
    system_metadata_json: Option<&str>,
) -> Result<(Vec<String>, ObjectVersion), String> {
    if !head_bucket(conn, dest_bucket)? {
        return Err("NoSuchBucket".to_string());
    }

    let src_version =
        latest_version(conn, src_bucket, src_key)?.ok_or_else(|| "NoSuchKey".to_string())?;

    let src_chunks = chunks_of(conn, &src_version.version_id)?;

    let (final_content_type, final_user_meta, final_sys_meta) =
        if metadata_directive.eq_ignore_ascii_case("REPLACE") {
            (
                override_content_type
                    .unwrap_or(&src_version.content_type)
                    .to_string(),
                user_metadata_json.map(|s| s.to_string()),
                system_metadata_json.map(|s| s.to_string()),
            )
        } else {
            (
                src_version.content_type.clone(),
                src_version.user_metadata_json.clone(),
                src_version.system_metadata_json.clone(),
            )
        };

    let tx = conn.transaction().map_err(|e| format!("begin txn: {e}"))?;

    let (final_version_id, old_spools) =
        prepare_versioning_write_tx(&tx, dest_bucket, dest_key, new_version_id)?;

    tx.execute(
        "INSERT INTO objects(bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type, user_metadata_json, system_metadata_json) VALUES (?, ?, ?, 0, 'accepted-local', ?, ?, ?, ?, ?)",
        rusqlite::params![dest_bucket, dest_key, final_version_id, src_version.size, src_version.etag, final_content_type, final_user_meta, final_sys_meta],
    )
    .map_err(|e| format!("insert object: {e}"))?;

    let mut need_upload = false;
    for c in &src_chunks {
        tx.execute(
            "INSERT INTO chunks(version_id, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref, spool_path, remote_locator_json, state)
             SELECT ?, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref, spool_path, remote_locator_json, state
             FROM chunks WHERE version_id = ? AND idx = ?",
            rusqlite::params![final_version_id, src_version.version_id, c.idx],
        )
        .map_err(|e| format!("copy chunk: {e}"))?;

        if c.state == "pending" {
            need_upload = true;
        }
    }

    if need_upload {
        tx.execute(
            "INSERT INTO upload_jobs(job_id, version_id, state) VALUES (?, ?, 'pending')",
            rusqlite::params![new_job_id, final_version_id],
        )
        .map_err(|e| format!("insert job: {e}"))?;
    }

    tx.commit().map_err(|e| format!("commit: {e}"))?;

    let version = latest_version(conn, dest_bucket, dest_key)?
        .ok_or_else(|| "Failed to fetch copied object version".to_string())?;

    Ok((old_spools, version))
}

pub fn latest_version(
    conn: &Connection,
    bucket: &str,
    key: &str,
) -> Result<Option<ObjectVersion>, String> {
    let mut stmt = conn
        .prepare("SELECT version_id, key, is_delete_marker, size, etag, content_type, storage_state, created_at, user_metadata_json, system_metadata_json FROM objects WHERE bucket = ? AND key = ? ORDER BY created_at DESC, rowid DESC LIMIT 1")
        .map_err(|e| format!("prepare: {e}"))?;

    let mut rows = stmt
        .query_map(rusqlite::params![bucket, key], |r| {
            let is_dm: i64 = r.get(2)?;
            Ok(ObjectVersion {
                version_id: r.get(0)?,
                key: r.get(1)?,
                is_delete_marker: is_dm != 0,
                size: r.get(3)?,
                etag: r.get(4)?,
                content_type: r.get(5)?,
                storage_state: r.get(6)?,
                created_at: r.get(7)?,
                user_metadata_json: r.get(8)?,
                system_metadata_json: r.get(9)?,
            })
        })
        .map_err(|e| format!("query: {e}"))?;
    match rows.next() {
        Some(r) => r.map(Some).map_err(|e| format!("row: {e}")),
        None => Ok(None),
    }
}

pub fn get_version_by_id(
    conn: &Connection,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<Option<ObjectVersion>, String> {
    let mut stmt = conn
        .prepare("SELECT version_id, key, is_delete_marker, size, etag, content_type, storage_state, created_at, user_metadata_json, system_metadata_json FROM objects WHERE bucket = ? AND key = ? AND version_id = ?")
        .map_err(|e| format!("prepare: {e}"))?;
    let mut rows = stmt
        .query_map(rusqlite::params![bucket, key, version_id], |r| {
            let is_dm: i64 = r.get(2)?;
            Ok(ObjectVersion {
                version_id: r.get(0)?,
                key: r.get(1)?,
                is_delete_marker: is_dm != 0,
                size: r.get(3)?,
                etag: r.get(4)?,
                content_type: r.get(5)?,
                storage_state: r.get(6)?,
                created_at: r.get(7)?,
                user_metadata_json: r.get(8)?,
                system_metadata_json: r.get(9)?,
            })
        })
        .map_err(|e| format!("query: {e}"))?;
    match rows.next() {
        Some(r) => r.map(Some).map_err(|e| format!("row: {e}")),
        None => Ok(None),
    }
}

pub fn chunks_of(conn: &Connection, version_id: &str) -> Result<Vec<ChunkRow>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT idx, length, spool_path, state, encryption_mode, key_ref FROM chunks WHERE version_id = ? ORDER BY idx",
        )
        .map_err(|e| format!("prepare: {e}"))?;
    let rows = stmt
        .query_map([version_id], |r| {
            Ok(ChunkRow {
                idx: r.get(0)?,
                length: r.get(1)?,
                spool_path: r.get(2)?,
                state: r.get(3)?,
                encryption_mode: r.get(4)?,
                key_ref: r.get(5)?,
            })
        })
        .map_err(|e| format!("query: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("rows: {e}"))
}

/// Xóa object: trả spool paths để caller dọn + locators đã remote (caller best-effort xóa remote).
pub struct DeleteObjectResult {
    pub existed: bool,
    pub spool_paths: Vec<String>,
    pub remote_locators: Vec<crate::telegram::RemoteLocator>,
    pub is_delete_marker: bool,
    pub version_id: String,
}

pub fn create_delete_marker(
    conn: &mut Connection,
    bucket: &str,
    key: &str,
) -> Result<String, String> {
    let tx = conn.transaction().map_err(|e| format!("begin: {e}"))?;
    let (version_id, _) = prepare_versioning_write_tx(&tx, bucket, key, "null")?;
    tx.execute(
        "INSERT INTO objects(bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type) VALUES (?, ?, ?, 1, 'accepted-local', 0, '', '')",
        rusqlite::params![bucket, key, version_id],
    ).map_err(|e| format!("insert delete marker: {e}"))?;
    tx.commit().map_err(|e| format!("commit: {e}"))?;
    Ok(version_id)
}

pub fn delete_object_version(
    conn: &mut Connection,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<DeleteObjectResult, String> {
    use rusqlite::OptionalExtension;
    let tx = conn.transaction().map_err(|e| format!("begin: {e}"))?;

    let is_dm: Option<bool> = tx
        .prepare(
            "SELECT is_delete_marker FROM objects WHERE bucket = ? AND key = ? AND version_id = ?",
        )
        .map_err(|e| format!("prepare: {e}"))?
        .query_row(rusqlite::params![bucket, key, version_id], |r| {
            let dm: i64 = r.get(0)?;
            Ok(dm != 0)
        })
        .optional()
        .map_err(|e| format!("query: {e}"))?;

    let is_delete_marker = match is_dm {
        Some(b) => b,
        None => {
            return Ok(DeleteObjectResult {
                existed: false,
                spool_paths: Vec::new(),
                remote_locators: Vec::new(),
                is_delete_marker: false,
                version_id: version_id.to_string(),
            })
        }
    };

    let spool_paths: Vec<String> = tx
        .prepare("SELECT spool_path FROM chunks WHERE version_id = ?")
        .map_err(|e| format!("prepare: {e}"))?
        .query_map([version_id], |r| r.get(0))
        .map_err(|e| format!("query: {e}"))?
        .collect::<Result<Vec<Option<String>>, _>>()
        .map_err(|e| format!("rows: {e}"))?
        .into_iter()
        .flatten()
        .collect();

    tx.execute("DELETE FROM upload_jobs WHERE version_id = ?", [version_id])
        .ok();
    tx.execute("DELETE FROM chunks WHERE version_id = ?", [version_id])
        .ok();
    tx.execute(
        "DELETE FROM objects WHERE bucket = ? AND key = ? AND version_id = ?",
        rusqlite::params![bucket, key, version_id],
    )
    .map_err(|e| format!("delete version: {e}"))?;

    tx.commit().map_err(|e| format!("commit: {e}"))?;

    Ok(DeleteObjectResult {
        existed: true,
        spool_paths,
        remote_locators: Vec::new(),
        is_delete_marker,
        version_id: version_id.to_string(),
    })
}

pub fn delete_object(
    conn: &mut Connection,
    bucket: &str,
    key: &str,
) -> Result<DeleteObjectResult, String> {
    let tx = conn.transaction().map_err(|e| format!("begin: {e}"))?;
    let versions: Vec<String> = tx
        .prepare("SELECT version_id FROM objects WHERE bucket = ? AND key = ?")
        .map_err(|e| format!("prepare: {e}"))?
        .query_map(rusqlite::params![bucket, key], |r| r.get(0))
        .map_err(|e| format!("query: {e}"))?
        .collect::<Result<Vec<String>, _>>()
        .map_err(|e| format!("rows: {e}"))?;
    if versions.is_empty() {
        return Ok(DeleteObjectResult {
            existed: false,
            spool_paths: Vec::new(),
            remote_locators: Vec::new(),
            is_delete_marker: false,
            version_id: String::new(),
        });
    }
    let mut spool_paths = Vec::new();
    let mut remote_locators = Vec::new();
    for v in &versions {
        let chunk_rows: Vec<(Option<String>, String, Option<String>)> = tx
            .prepare(
                "SELECT spool_path, state, remote_locator_json FROM chunks WHERE version_id = ?",
            )
            .map_err(|e| format!("prepare: {e}"))?
            .query_map([v], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(|e| format!("query: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("rows: {e}"))?;
        for (spool, state, locator) in chunk_rows {
            if let Some(p) = spool {
                spool_paths.push(p);
            }
            if state == "remote" {
                if let Some(loc) = locator {
                    if let Ok(parsed) = serde_json::from_str(&loc) {
                        remote_locators.push(parsed);
                    }
                }
            }
        }
        tx.execute("DELETE FROM upload_jobs WHERE version_id = ?", [v])
            .map_err(|e| format!("delete jobs: {e}"))?;
        tx.execute("DELETE FROM chunks WHERE version_id = ?", [v])
            .map_err(|e| format!("delete chunks: {e}"))?;
    }
    tx.execute(
        "DELETE FROM objects WHERE bucket = ? AND key = ?",
        rusqlite::params![bucket, key],
    )
    .map_err(|e| format!("delete objects: {e}"))?;
    tx.commit().map_err(|e| format!("commit: {e}"))?;
    Ok(DeleteObjectResult {
        existed: true,
        spool_paths,
        remote_locators,
        is_delete_marker: false,
        version_id: String::new(),
    })
}

pub fn list_object_versions(
    conn: &Connection,
    bucket: &str,
    prefix: &str,
    key_marker: &str,
    version_id_marker: &str,
    limit: i64,
) -> Result<Vec<VersionListItem>, String> {
    let esc = prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let mut stmt = conn
        .prepare("SELECT key, version_id, is_delete_marker, size, etag, created_at FROM objects WHERE bucket = ? AND key LIKE ? || '%' ESCAPE '\\' AND (key > ? OR (key = ? AND version_id > ?)) ORDER BY key ASC, created_at DESC, rowid DESC LIMIT ?")
        .map_err(|e| format!("prepare: {e}"))?;

    let rows = stmt
        .query_map(
            rusqlite::params![
                bucket,
                esc,
                key_marker,
                key_marker,
                version_id_marker,
                limit
            ],
            |r| {
                let is_dm: i64 = r.get(2)?;
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    is_dm != 0,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
        )
        .map_err(|e| format!("query: {e}"))?;

    let mut result = Vec::new();
    let mut last_key: Option<String> = None;

    for row in rows {
        let (key, version_id, is_delete_marker, size, etag, created_at) =
            row.map_err(|e| format!("row: {e}"))?;
        let is_latest = !matches!(&last_key, Some(k) if k == &key);
        last_key = Some(key.clone());
        result.push(VersionListItem {
            key,
            version_id,
            is_latest,
            is_delete_marker,
            size,
            etag,
            created_at,
        });
    }

    Ok(result)
}

/// List keys phục vụ ListObjectsV2: lọc prefix, sắp xếp, cắt max-keys+1 để biết truncated.
pub fn list_keys(
    conn: &Connection,
    bucket: &str,
    prefix: &str,
    start_after: &str,
    limit_plus_one: i64,
) -> Result<Vec<(String, ObjectVersion)>, String> {
    let esc = prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let mut stmt = conn
        .prepare("SELECT key, version_id, is_delete_marker, size, etag, content_type, storage_state, created_at, user_metadata_json, system_metadata_json FROM objects o1 WHERE bucket = ? AND key LIKE ? || '%' ESCAPE '\\' AND key > ? AND rowid = (SELECT MAX(rowid) FROM objects o2 WHERE o2.bucket = o1.bucket AND o2.key = o1.key) AND is_delete_marker = 0 ORDER BY key LIMIT ?")
        .map_err(|e| format!("prepare: {e}"))?;

    let rows = stmt
        .query_map(
            rusqlite::params![bucket, esc, start_after, limit_plus_one],
            |r| {
                let is_dm: i64 = r.get(2)?;
                let key: String = r.get(0)?;
                Ok((
                    key.clone(),
                    ObjectVersion {
                        version_id: r.get(1)?,
                        key,
                        is_delete_marker: is_dm != 0,
                        size: r.get(3)?,
                        etag: r.get(4)?,
                        content_type: r.get(5)?,
                        storage_state: r.get(6)?,
                        created_at: r.get(7)?,
                        user_metadata_json: r.get(8)?,
                        system_metadata_json: r.get(9)?,
                    },
                ))
            },
        )
        .map_err(|e| format!("query: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("rows: {e}"))
}

/// Lấy tất cả đường dẫn spool_path đang active (không NULL) trong bảng chunks và multipart_parts.
pub fn active_spool_paths(
    conn: &Connection,
) -> Result<std::collections::HashSet<std::path::PathBuf>, String> {
    let sql = if schema_version(conn).unwrap_or(0) >= 2 {
        "SELECT spool_path FROM chunks WHERE spool_path IS NOT NULL UNION SELECT spool_path FROM multipart_parts WHERE spool_path IS NOT NULL"
    } else {
        "SELECT spool_path FROM chunks WHERE spool_path IS NOT NULL"
    };
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| format!("prepare active spool query: {e}"))?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| format!("query active spool: {e}"))?;
    let mut set = std::collections::HashSet::new();
    for p in rows.flatten() {
        let pb = std::path::PathBuf::from(p);
        set.insert(pb.clone());
        if let Ok(canon) = std::fs::canonicalize(&pb) {
            set.insert(canon);
        }
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_apply_from_zero_to_head() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("index.db");
        let mut conn = open(db_path.to_str().unwrap()).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 0);
        apply_migration(&mut conn, 1, MIGRATION_001).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 1);
        apply_migration(&mut conn, 2, MIGRATION_002).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 2);
    }

    fn test_db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = open(dir.path().join("index.db").to_str().unwrap()).unwrap();
        apply_all_migrations(&mut conn).unwrap();
        (dir, conn)
    }

    #[test]
    fn multipart_uploads_crud() {
        let (_d, mut conn) = test_db();
        create_bucket(&conn, "mybucket", "us-east-1").unwrap();

        // Create
        create_multipart_upload(
            &conn,
            "upload-123",
            "mybucket",
            "photo.jpg",
            "image/jpeg",
            Some(r#"{"x-amz-meta-author":"alice"}"#),
        )
        .unwrap();

        // Get
        let upload = get_multipart_upload(&conn, "upload-123").unwrap().unwrap();
        assert_eq!(upload.upload_id, "upload-123");
        assert_eq!(upload.bucket, "mybucket");
        assert_eq!(upload.key, "photo.jpg");
        assert_eq!(upload.content_type, "image/jpeg");
        assert_eq!(
            upload.metadata_json.as_deref(),
            Some(r#"{"x-amz-meta-author":"alice"}"#)
        );

        // Save part
        save_multipart_part(
            &conn,
            "upload-123",
            1,
            1024,
            "etag1",
            "sha1",
            "sha1",
            Some("spool/p1"),
        )
        .unwrap();
        save_multipart_part(
            &conn,
            "upload-123",
            2,
            2048,
            "etag2",
            "sha2",
            "sha2",
            Some("spool/p2"),
        )
        .unwrap();

        // List parts
        let parts = list_multipart_parts(&conn, "upload-123").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].part_number, 1);
        assert_eq!(parts[0].size, 1024);
        assert_eq!(parts[1].part_number, 2);
        assert_eq!(parts[1].size, 2048);

        // List uploads for bucket
        let uploads = list_multipart_uploads(&conn, "mybucket").unwrap();
        assert_eq!(uploads.len(), 1);

        // Active spool paths contains multipart parts
        let active = active_spool_paths(&conn).unwrap();
        assert!(active.contains(std::path::Path::new("spool/p1")));

        // Abort
        let spools = abort_multipart_upload(&mut conn, "upload-123").unwrap();
        assert_eq!(spools, vec!["spool/p1".to_string(), "spool/p2".to_string()]);
        assert!(get_multipart_upload(&conn, "upload-123").unwrap().is_none());
    }

    #[test]
    fn pragmas_wal_fk_busy_timeout() {
        let (_d, conn) = test_db();
        let journal: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(journal.to_lowercase(), "wal");
        let busy: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(busy, 5000);
    }

    #[test]
    fn bucket_crud_and_naming() {
        let (_d, conn) = test_db();
        assert!(!valid_bucket_name("AB"));
        assert!(!valid_bucket_name("Abc"));
        assert!(!valid_bucket_name("-abc"));
        assert!(valid_bucket_name("my-bucket.1"));
        assert_eq!(
            create_bucket(&conn, "my-bucket", "telecrate-1").unwrap(),
            CreateBucketOutcome::Created
        );
        assert_eq!(
            create_bucket(&conn, "my-bucket", "telecrate-1").unwrap(),
            CreateBucketOutcome::AlreadyOwned
        );
        assert!(head_bucket(&conn, "my-bucket").unwrap());
        assert!(!head_bucket(&conn, "nope").unwrap());
        assert!(create_bucket(&conn, "Bad_Name", "r").is_err());
        let list = list_buckets(&conn).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].region, "telecrate-1");
    }

    #[test]
    fn delete_bucket_denies_nonempty_and_missing() {
        let (_d, conn) = test_db();
        assert_eq!(
            delete_bucket(&conn, "ghost").unwrap(),
            DeleteBucketOutcome::NoSuchBucket
        );
        create_bucket(&conn, "bucket-1", "r").unwrap();
        assert_eq!(
            delete_bucket(&conn, "bucket-1").unwrap(),
            DeleteBucketOutcome::Deleted
        );
        // Bucket có object → 409 NotEmpty.
        create_bucket(&conn, "bucket-2", "r").unwrap();
        conn.execute(
            "INSERT INTO objects(bucket, key, version_id) VALUES ('bucket-2', 'k', 'v1')",
            [],
        )
        .unwrap();
        assert_eq!(
            delete_bucket(&conn, "bucket-2").unwrap(),
            DeleteBucketOutcome::NotEmpty
        );
    }

    #[test]
    fn object_put_get_delete_and_list() {
        let (_d, mut conn) = test_db();
        create_bucket(&conn, "bkt", "r").unwrap();
        let one = |spool: &str, sha: &str, len: i64| {
            vec![NewChunk {
                offset: 0,
                length: len,
                plaintext_sha256: sha.to_string(),
                ciphertext_sha256: sha.to_string(),
                spool_path: spool.to_string(),
                mode: crate::crypto::MODE_NONE.to_string(),
                key_ref: None,
            }]
        };
        // PUT 2 keys (1 key có % _ để kiểm LIKE escape).
        let (old, _) = put_object(
            &mut conn,
            "bkt",
            "a/b",
            "v1",
            3,
            "etag1",
            "text/plain",
            None,
            None,
            &one("/spool/x1", "ph1", 3),
            "job1",
        )
        .unwrap();
        assert!(old.is_empty());
        put_object(
            &mut conn,
            "bkt",
            "a%b_c",
            "v2",
            4,
            "etag2",
            "text/plain",
            None,
            None,
            &one("/spool/x2", "ph2", 4),
            "job2",
        )
        .unwrap();
        // PUT đè: thu spool cũ + version mới thấy ngay.
        let (old, _) = put_object(
            &mut conn,
            "bkt",
            "a/b",
            "v3",
            5,
            "etag3",
            "text/plain",
            None,
            None,
            &one("/spool/x3", "ph3", 5),
            "job3",
        )
        .unwrap();
        assert_eq!(old, vec!["/spool/x1".to_string()]);

        let v = latest_version(&conn, "bkt", "a/b").unwrap().unwrap();
        assert_eq!(v.version_id, "v3");
        assert_eq!(v.etag, "etag3");
        assert!(latest_version(&conn, "bkt", "ghost").unwrap().is_none());
        // PUT multi-chunk: chunks giữ đúng thứ tự offset.
        put_object(
            &mut conn,
            "bkt",
            "multi",
            "vm",
            30,
            "etagm",
            "bin",
            None,
            None,
            &[
                NewChunk {
                    offset: 0,
                    length: 10,
                    plaintext_sha256: "s0".into(),
                    ciphertext_sha256: "c0".into(),
                    spool_path: "/s/m0".into(),
                    mode: crate::crypto::MODE_AEAD_V1.into(),
                    key_ref: Some("k1".into()),
                },
                NewChunk {
                    offset: 10,
                    length: 10,
                    plaintext_sha256: "s1".into(),
                    ciphertext_sha256: "c1".into(),
                    spool_path: "/s/m1".into(),
                    mode: crate::crypto::MODE_AEAD_V1.into(),
                    key_ref: Some("k1".into()),
                },
                NewChunk {
                    offset: 20,
                    length: 10,
                    plaintext_sha256: "s2".into(),
                    ciphertext_sha256: "c2".into(),
                    spool_path: "/s/m2".into(),
                    mode: crate::crypto::MODE_AEAD_V1.into(),
                    key_ref: Some("k1".into()),
                },
            ],
            "jobm",
        )
        .unwrap();
        let chunks = chunks_of(&conn, "vm").unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[2].length, 10);
        assert_eq!(chunks[1].spool_path.as_deref(), Some("/s/m1"));
        assert_eq!(chunks[0].encryption_mode, crate::crypto::MODE_AEAD_V1);
        assert_eq!(chunks[0].key_ref.as_deref(), Some("k1"));
        // LIST prefix + LIKE escape.
        let keys = list_keys(&conn, "bkt", "a/", "", 10).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "a/b");
        let keys = list_keys(&conn, "bkt", "a%", "", 10).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "a%b_c");
        // Pagination (thứ tự byte: "a%b_c" < "a/b" < "multi").
        let keys = list_keys(&conn, "bkt", "", "", 2).unwrap();
        assert_eq!(keys.len(), 2);
        let keys = list_keys(&conn, "bkt", "", "a%b_c", 10).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].0, "a/b");
        assert_eq!(keys[1].0, "multi");
        // DELETE trả spool + existed; xóa lại → !existed.
        let r = delete_object(&mut conn, "bkt", "a/b").unwrap();
        assert!(r.existed);
        assert_eq!(r.spool_paths, vec!["/spool/x3".to_string()]);
        assert!(!delete_object(&mut conn, "bkt", "a/b").unwrap().existed);
        // Bucket còn object → vẫn NotEmpty; xóa hết → Deleted.
        assert_eq!(
            delete_bucket(&conn, "bkt").unwrap(),
            DeleteBucketOutcome::NotEmpty
        );
        delete_object(&mut conn, "bkt", "a%b_c").unwrap();
        delete_object(&mut conn, "bkt", "multi").unwrap();
        assert_eq!(
            delete_bucket(&conn, "bkt").unwrap(),
            DeleteBucketOutcome::Deleted
        );
    }
}

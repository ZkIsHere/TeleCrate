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
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
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

/// Một bucket trong index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    pub name: String,
    pub region: String,
    pub created_at: String,
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
        .prepare("SELECT name, region, created_at FROM buckets ORDER BY name")
        .map_err(|e| format!("prepare: {e}"))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(Bucket {
                name: r.get(0)?,
                region: r.get(1)?,
                created_at: r.get(2)?,
            })
        })
        .map_err(|e| format!("query: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("rows: {e}"))
}

// --- Objects M2.2 (chưa versioning: PUT thay thế hàng cũ cùng key trong cùng txn) ---

/// Một object version (M2.2: mỗi key một hàng hiện hành).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectVersion {
    pub version_id: String,
    pub size: i64,
    pub etag: String,
    pub content_type: String,
    pub storage_state: String,
    pub created_at: String,
}

/// Metadata chunk để worker/GC dùng (không SELECT * bừa bãi).
#[derive(Debug, Clone)]
pub struct ChunkRow {
    pub idx: i64,
    pub length: i64,
    pub spool_path: Option<String>,
    pub state: String,
}

/// Ghi object: thay hàng cũ cùng (bucket,key) + chèn version/chunk/job mới — MỘT txn.
#[allow(clippy::too_many_arguments)]
pub fn put_object(
    conn: &mut Connection,
    bucket: &str,
    key: &str,
    version_id: &str,
    size: i64,
    etag: &str,
    content_type: &str,
    plaintext_sha256: &str,
    spool_path: &str,
    job_id: &str,
) -> Result<Vec<String>, String> {
    let tx = conn.transaction().map_err(|e| format!("begin: {e}"))?;
    // Spool cũ mồ côi nếu PUT đè — thu gom để caller xóa sau commit.
    let old: Vec<String> = tx
        .prepare("SELECT spool_path FROM chunks WHERE version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)")
        .map_err(|e| format!("prepare: {e}"))?
        .query_map(rusqlite::params![bucket, key], |r| r.get(0))
        .map_err(|e| format!("query: {e}"))?
        .collect::<Result<Vec<Option<String>>, _>>()
        .map_err(|e| format!("rows: {e}"))?
        .into_iter()
        .flatten()
        .collect();
    tx.execute(
        "DELETE FROM upload_jobs WHERE version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)",
        rusqlite::params![bucket, key],
    )
    .map_err(|e| format!("delete jobs: {e}"))?;
    tx.execute(
        "DELETE FROM chunks WHERE version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)",
        rusqlite::params![bucket, key],
    )
    .map_err(|e| format!("delete chunks: {e}"))?;
    tx.execute(
        "DELETE FROM objects WHERE bucket = ? AND key = ?",
        rusqlite::params![bucket, key],
    )
    .map_err(|e| format!("delete objects: {e}"))?;
    tx.execute(
        "INSERT INTO objects(bucket, key, version_id, storage_state, size, etag, content_type) VALUES (?, ?, ?, 'accepted-local', ?, ?, ?)",
        rusqlite::params![bucket, key, version_id, size, etag, content_type],
    )
    .map_err(|e| format!("insert object: {e}"))?;
    tx.execute(
        "INSERT INTO chunks(version_id, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, spool_path, state) VALUES (?, 0, 0, ?, ?, ?, 'none', ?, 'pending')",
        rusqlite::params![version_id, size, plaintext_sha256, plaintext_sha256, spool_path],
    )
    .map_err(|e| format!("insert chunk: {e}"))?;
    tx.execute(
        "INSERT INTO upload_jobs(job_id, version_id, state) VALUES (?, ?, 'pending')",
        rusqlite::params![job_id, version_id],
    )
    .map_err(|e| format!("insert job: {e}"))?;
    tx.commit().map_err(|e| format!("commit: {e}"))?;
    Ok(old)
}

pub fn latest_version(
    conn: &Connection,
    bucket: &str,
    key: &str,
) -> Result<Option<ObjectVersion>, String> {
    let mut stmt = conn
        .prepare("SELECT version_id, size, etag, content_type, storage_state, created_at FROM objects WHERE bucket = ? AND key = ? ORDER BY created_at DESC LIMIT 1")
        .map_err(|e| format!("prepare: {e}"))?;
    let mut rows = stmt
        .query_map(rusqlite::params![bucket, key], |r| {
            Ok(ObjectVersion {
                version_id: r.get(0)?,
                size: r.get(1)?,
                etag: r.get(2)?,
                content_type: r.get(3)?,
                storage_state: r.get(4)?,
                created_at: r.get(5)?,
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
            "SELECT idx, length, spool_path, state FROM chunks WHERE version_id = ? ORDER BY idx",
        )
        .map_err(|e| format!("prepare: {e}"))?;
    let rows = stmt
        .query_map([version_id], |r| {
            Ok(ChunkRow {
                idx: r.get(0)?,
                length: r.get(1)?,
                spool_path: r.get(2)?,
                state: r.get(3)?,
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
        });
    }
    let mut spool_paths = Vec::new();
    let mut remote_locators = Vec::new();
    for v in &versions {
        let mut stmt = tx
            .prepare(
                "SELECT spool_path, state, remote_locator_json FROM chunks WHERE version_id = ?",
            )
            .map_err(|e| format!("prepare: {e}"))?;
        let rows = stmt
            .query_map([v], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(|e| format!("query: {e}"))?;
        for row in rows {
            let (spool, state, locator): (Option<String>, String, Option<String>) =
                row.map_err(|e| format!("row: {e}"))?;
            if let Some(p) = spool {
                spool_paths.push(p);
            }
            // Remote cleanup best-effort ở tầng route (M2.2); orphan dọn ở M5 GC.
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
    })
}

/// List keys phục vụ ListObjectsV2: lọc prefix, sắp xếp, cắt max-keys+1 để biết truncated.
pub fn list_keys(
    conn: &Connection,
    bucket: &str,
    prefix: &str,
    start_after: &str,
    limit_plus_one: i64,
) -> Result<Vec<(String, ObjectVersion)>, String> {
    // Escape LIKE wildcards trong prefix (key có thể chứa % _ \).
    let esc = prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let mut stmt = conn
        .prepare("SELECT key, version_id, size, etag, content_type, storage_state, created_at FROM objects WHERE bucket = ? AND key LIKE ? || '%' ESCAPE '\\' AND key > ? ORDER BY key LIMIT ?")
        .map_err(|e| format!("prepare: {e}"))?;
    let rows = stmt
        .query_map(
            rusqlite::params![bucket, esc, start_after, limit_plus_one],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    ObjectVersion {
                        version_id: r.get(1)?,
                        size: r.get(2)?,
                        etag: r.get(3)?,
                        content_type: r.get(4)?,
                        storage_state: r.get(5)?,
                        created_at: r.get(6)?,
                    },
                ))
            },
        )
        .map_err(|e| format!("query: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("rows: {e}"))
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
        // Apply tuần tự từng version đều pass — hiện chỉ có 1 version.
    }

    fn test_db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = open(dir.path().join("index.db").to_str().unwrap()).unwrap();
        apply_migration(&mut conn, 1, MIGRATION_001).unwrap();
        (dir, conn)
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
        // PUT 2 keys (1 key có % _ để kiểm LIKE escape).
        let old = put_object(
            &mut conn,
            "bkt",
            "a/b",
            "v1",
            3,
            "etag1",
            "text/plain",
            "ph1",
            "/spool/x1",
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
            "ph2",
            "/spool/x2",
            "job2",
        )
        .unwrap();
        // PUT đè: thu spool cũ + version mới thấy ngay.
        let old = put_object(
            &mut conn,
            "bkt",
            "a/b",
            "v3",
            5,
            "etag3",
            "text/plain",
            "ph3",
            "/spool/x3",
            "job3",
        )
        .unwrap();
        assert_eq!(old, vec!["/spool/x1".to_string()]);
        let v = latest_version(&conn, "bkt", "a/b").unwrap().unwrap();
        assert_eq!(v.version_id, "v3");
        assert_eq!(v.etag, "etag3");
        assert!(latest_version(&conn, "bkt", "ghost").unwrap().is_none());
        // LIST prefix + LIKE escape.
        let keys = list_keys(&conn, "bkt", "a/", "", 10).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "a/b");
        let keys = list_keys(&conn, "bkt", "a%", "", 10).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "a%b_c");
        // Pagination (thứ tự byte: "a%b_c" < "a/b" vì '%' < '/').
        let keys = list_keys(&conn, "bkt", "", "", 2).unwrap();
        assert_eq!(keys.len(), 2);
        let keys = list_keys(&conn, "bkt", "", "a%b_c", 10).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "a/b");
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
        assert_eq!(
            delete_bucket(&conn, "bkt").unwrap(),
            DeleteBucketOutcome::Deleted
        );
    }
}

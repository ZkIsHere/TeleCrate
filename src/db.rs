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
}

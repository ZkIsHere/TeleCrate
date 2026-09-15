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
        // Apply tuần tự từng version đều pass — M0 chỉ có 1 version.
    }
}

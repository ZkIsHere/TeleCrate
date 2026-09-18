//! DB layer — dual backend SQLite/Postgres trên sqlx, migrations forward-only.
//!
//! Mọi query viết placeholder `?` + bind một lần; sqlx tự rebind `$N` cho Postgres.
//! Datetime lưu TEXT `YYYY-MM-DD HH:MM:SS` UTC trên cả hai backend nên so sánh
//! chuỗi tương đương so sánh thời gian. Số nguyên đọc i64 trên cả hai
//! (DDL Postgres dùng BIGINT toàn bộ). Không giữ txn mở suốt network upload.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::query::Query;
use sqlx::sqlite::{
    SqliteArguments, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow,
};
use sqlx::{Pool, Postgres, Row as SqlxRow, Sqlite};
use std::path::Path;

/// Handle DB hợp nhất hai backend (ADR 0005 — Postgres giờ runnable).
#[derive(Debug, Clone)]
pub enum Db {
    Sqlite(Pool<Sqlite>),
    Postgres(Pool<Postgres>),
}

impl Db {
    pub fn backend(&self) -> DbBackend {
        match self {
            Db::Sqlite(_) => DbBackend::Sqlite,
            Db::Postgres(_) => DbBackend::Postgres,
        }
    }

    /// Mở SQLite file (tạo dirs, WAL + FK + busy timeout 5s).
    /// Daemon (HTTP + N worker) và CLI dùng chung DB, writer chờ nhau thay vì lỗi ngay.
    pub async fn open_sqlite(db_path: &str) -> Result<Db, String> {
        if let Some(parent) = Path::new(db_path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create db parent dir: {e}"))?;
            }
        }
        let opts = SqliteConnectOptions::new()
            .filename(Path::new(db_path))
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5))
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await
            .map_err(|e| format!("open db: {e}"))?;
        Ok(Db::Sqlite(pool))
    }

    /// Mở Postgres qua connection string (`postgres://...`).
    pub async fn open_postgres(url: &str) -> Result<Db, String> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(url)
            .await
            .map_err(|e| format!("open postgres: {e}"))?;
        Ok(Db::Postgres(pool))
    }

    /// Mở transaction backend-tương ứng (không giữ xuyên network upload).
    pub async fn begin(&self) -> Result<Tx<'_>, String> {
        match self {
            Db::Sqlite(p) => p.begin().await.map(Tx::Sqlite),
            Db::Postgres(p) => p.begin().await.map(|tx| Tx::Postgres(Box::new(tx))),
        }
        .map_err(|e| format!("begin txn: {e}"))
    }
}

/// Transaction backend-tương ứng (một txn mỗi hàm, không truyền xuyên hàm).
pub enum Tx<'a> {
    Sqlite(sqlx::Transaction<'a, Sqlite>),
    Postgres(Box<sqlx::Transaction<'a, Postgres>>),
}

impl Tx<'_> {
    pub async fn exec(&mut self, sql: &str, args: &[Val]) -> Result<u64, String> {
        match self {
            Tx::Sqlite(tx) => {
                let mut q = sqlx::query(sql);
                for a in args {
                    q = bind_sqlite(q, a);
                }
                q.execute(&mut **tx)
                    .await
                    .map(|r| r.rows_affected())
                    .map_err(|e| format!("exec: {e}"))
            }
            Tx::Postgres(tx) => {
                let mut q = sqlx::query(sql);
                for a in args {
                    q = bind_pg(q, a);
                }
                q.execute(&mut ***tx)
                    .await
                    .map(|r| r.rows_affected())
                    .map_err(|e| format!("exec: {e}"))
            }
        }
    }

    pub async fn fetch_all(&mut self, sql: &str, args: &[Val]) -> Result<Vec<Row>, String> {
        match self {
            Tx::Sqlite(tx) => {
                let mut q = sqlx::query(sql);
                for a in args {
                    q = bind_sqlite(q, a);
                }
                let rows = q
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(|e| format!("query: {e}"))?;
                rows.iter().map(decode_sqlite_row).collect()
            }
            Tx::Postgres(tx) => {
                let mut q = sqlx::query(sql);
                for a in args {
                    q = bind_pg(q, a);
                }
                let rows = q
                    .fetch_all(&mut ***tx)
                    .await
                    .map_err(|e| format!("query: {e}"))?;
                rows.iter().map(decode_pg_row).collect()
            }
        }
    }

    pub async fn fetch_opt(&mut self, sql: &str, args: &[Val]) -> Result<Option<Row>, String> {
        let mut rows = self.fetch_all(sql, args).await?;
        Ok(rows.pop())
    }

    pub async fn commit(self) -> Result<(), String> {
        match self {
            Tx::Sqlite(tx) => tx.commit().await,
            Tx::Postgres(tx) => tx.commit().await,
        }
        .map_err(|e| format!("commit: {e}"))
    }
}

/// Giá trị bind/decode tối giản. Schema chỉ dùng TEXT / BIGINT / NULL nên
/// decode thử TEXT trước (tránh TEXT số bị đọc nhầm thành Int).
#[derive(Debug, Clone)]
pub enum Val {
    Null,
    Int(i64),
    Text(String),
}

impl Val {
    pub fn int(v: i64) -> Self {
        Val::Int(v)
    }
    pub fn text(s: &str) -> Self {
        Val::Text(s.to_string())
    }
    pub fn opt_text(v: Option<&str>) -> Self {
        v.map(|s| Val::Text(s.to_string())).unwrap_or(Val::Null)
    }
}

/// Một hàng kết quả đã decode, đọc theo index như rusqlite trước đây.
#[derive(Debug, Clone)]
pub struct Row {
    vals: Vec<Val>,
}

impl Row {
    pub fn get_string(&self, i: usize) -> Result<String, String> {
        match self.vals.get(i) {
            Some(Val::Text(s)) => Ok(s.clone()),
            other => Err(format!("row col {i} is not text: {other:?}")),
        }
    }
    pub fn get_i64(&self, i: usize) -> Result<i64, String> {
        match self.vals.get(i) {
            Some(Val::Int(n)) => Ok(*n),
            other => Err(format!("row col {i} is not int: {other:?}")),
        }
    }
    pub fn get_i32(&self, i: usize) -> Result<i32, String> {
        let n = self.get_i64(i)?;
        n.try_into()
            .map_err(|_| format!("row col {i} out of i32 range: {n}"))
    }
    pub fn get_opt_i32(&self, i: usize) -> Result<Option<i32>, String> {
        match self.vals.get(i) {
            None => Err(format!("row col {i} out of range")),
            Some(Val::Null) => Ok(None),
            Some(Val::Int(n)) => {
                Ok(Some((*n).try_into().map_err(|_| {
                    format!("row col {i} out of i32 range: {n}")
                })?))
            }
            other => Err(format!("row col {i} is not nullable int: {other:?}")),
        }
    }
    pub fn get_bool(&self, i: usize) -> Result<bool, String> {
        self.get_i64(i).map(|n| n != 0)
    }
    pub fn get_opt_string(&self, i: usize) -> Result<Option<String>, String> {
        match self.vals.get(i) {
            None => Err(format!("row col {i} out of range")),
            Some(Val::Null) => Ok(None),
            Some(Val::Text(s)) => Ok(Some(s.clone())),
            other => Err(format!("row col {i} is not nullable text: {other:?}")),
        }
    }
}

fn bind_sqlite<'q>(
    q: Query<'q, Sqlite, SqliteArguments<'q>>,
    a: &Val,
) -> Query<'q, Sqlite, SqliteArguments<'q>> {
    match a {
        Val::Null => q.bind(Option::<String>::None),
        Val::Int(n) => q.bind(*n),
        Val::Text(s) => q.bind(s.clone()),
    }
}

fn bind_pg<'q>(
    q: Query<'q, Postgres, sqlx::postgres::PgArguments>,
    a: &Val,
) -> Query<'q, Postgres, sqlx::postgres::PgArguments> {
    match a {
        Val::Null => q.bind(Option::<String>::None),
        Val::Int(n) => q.bind(*n),
        Val::Text(s) => q.bind(s.clone()),
    }
}

fn decode_sqlite_row(r: &SqliteRow) -> Result<Row, String> {
    let mut vals = Vec::with_capacity(r.len());
    for i in 0..r.len() {
        if let Ok(Some(s)) = r.try_get::<Option<String>, _>(i) {
            vals.push(Val::Text(s));
        } else if let Ok(Some(n)) = r.try_get::<Option<i64>, _>(i) {
            vals.push(Val::Int(n));
        } else {
            vals.push(Val::Null);
        }
    }
    Ok(Row { vals })
}

fn decode_pg_row(r: &PgRow) -> Result<Row, String> {
    let mut vals = Vec::with_capacity(r.len());
    for i in 0..r.len() {
        if let Ok(Some(s)) = r.try_get::<Option<String>, _>(i) {
            vals.push(Val::Text(s));
        } else if let Ok(Some(n)) = r.try_get::<Option<i64>, _>(i) {
            vals.push(Val::Int(n));
        } else {
            vals.push(Val::Null);
        }
    }
    Ok(Row { vals })
}

/// SELECT nhiều hàng trên pool (không txn).
pub async fn fetch_all(db: &Db, sql: &str, args: &[Val]) -> Result<Vec<Row>, String> {
    match db {
        Db::Sqlite(p) => {
            let mut q = sqlx::query(sql);
            for a in args {
                q = bind_sqlite(q, a);
            }
            let rows = q.fetch_all(p).await.map_err(|e| format!("query: {e}"))?;
            rows.iter().map(decode_sqlite_row).collect()
        }
        Db::Postgres(p) => {
            let mut q = sqlx::query(sql);
            for a in args {
                q = bind_pg(q, a);
            }
            let rows = q.fetch_all(p).await.map_err(|e| format!("query: {e}"))?;
            rows.iter().map(decode_pg_row).collect()
        }
    }
}

/// SELECT 0..1 hàng trên pool.
pub async fn fetch_opt(db: &Db, sql: &str, args: &[Val]) -> Result<Option<Row>, String> {
    let mut rows = fetch_all(db, sql, args).await?;
    Ok(rows.pop())
}

/// SELECT COUNT(*) tiện lợi (thiếu hàng → 0).
pub async fn count(db: &Db, sql: &str, args: &[Val]) -> Result<i64, String> {
    match fetch_opt(db, sql, args).await? {
        Some(r) => r.get_i64(0),
        None => Ok(0),
    }
}

/// SELECT 1 dòng dạng chuỗi từ cột đầu tiên (tiện cho test & scalar query).
pub async fn query_scalar_string(db: &Db, sql: &str, args: &[Val]) -> Result<String, String> {
    match fetch_opt(db, sql, args).await? {
        Some(r) => r.get_string(0),
        None => Err("no row found for scalar query".into()),
    }
}

/// SELECT 1 dòng (tiện cho test).
pub async fn query_row(db: &Db, sql: &str, args: &[Val]) -> Result<Row, String> {
    fetch_opt(db, sql, args)
        .await?
        .ok_or_else(|| "no row returned".to_string())
}

/// INSERT/UPDATE/DELETE trên pool. Trả số hàng ảnh hưởng.
pub async fn exec(db: &Db, sql: &str, args: &[Val]) -> Result<u64, String> {
    match db {
        Db::Sqlite(p) => {
            let mut q = sqlx::query(sql);
            for a in args {
                q = bind_sqlite(q, a);
            }
            q.execute(p)
                .await
                .map(|r| r.rows_affected())
                .map_err(|e| format!("exec: {e}"))
        }
        Db::Postgres(p) => {
            let mut q = sqlx::query(sql);
            for a in args {
                q = bind_pg(q, a);
            }
            q.execute(p)
                .await
                .map(|r| r.rows_affected())
                .map_err(|e| format!("exec: {e}"))
        }
    }
}

/// Thời điểm UTC hiện tại dạng TEXT `YYYY-MM-DD HH:MM:SS` (khớp `datetime('now')` cũ).
pub fn now_str() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    fmt_epoch(secs)
}

/// `now + secs` cùng định dạng (thay `datetime('now', '+N seconds')`).
pub fn now_plus_str(secs: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    fmt_epoch(now + secs)
}

fn fmt_epoch(ts: i64) -> String {
    let days = ts.div_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let rem = ts.rem_euclid(86400);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since unix epoch → (year, month, day). Thuật toán Howard Hinnant.
fn civil_from_days(z: i64) -> (i32, u8, u8) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

/// Backend metadata DB (ADR 0005). Cả hai backend đều runnable.
/// Query DAL hợp nhất qua sqlx (`?` placeholder, tự rebind `$N` cho Postgres).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbBackend {
    Sqlite,
    Postgres,
}

impl DbBackend {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "sqlite" => Ok(Self::Sqlite),
            "postgres" => Ok(Self::Postgres),
            _ => Err(format!(
                "unknown db backend: '{s}' (expected 'sqlite' or 'postgres')"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

/// Guard khởi động: cả hai backend đều runnable (Postgres xong port DAL).
/// Giữ hàm để tương thích + làm điểm chặn tập trung nếu backend mới thêm sau.
pub fn ensure_backend_supported(backend: DbBackend) -> Result<(), String> {
    match backend {
        DbBackend::Sqlite | DbBackend::Postgres => Ok(()),
    }
}

/// DDL SQLite versioned, migrations forward-only.
pub const MIGRATION_001: &str = include_str!("../migrations/0001_init.sql");
pub const MIGRATION_002: &str = include_str!("../migrations/0002_m3_multipart_versioning.sql");
pub const MIGRATION_003: &str = include_str!("../migrations/0003_m4_auth_policy_cors_lock.sql");
pub const MIGRATION_004: &str = include_str!("../migrations/0004_dashboard_enhancements.sql");

/// DDL Postgres versioned, song song migrations SQLite 0001→0004
/// (cùng quy ước file SQL forward-only). Runtime apply theo version.
pub const PG_MIGRATION_001: &str = include_str!("../migrations/postgres/0001_init.sql");
pub const PG_MIGRATION_002: &str =
    include_str!("../migrations/postgres/0002_m3_multipart_versioning.sql");
pub const PG_MIGRATION_003: &str =
    include_str!("../migrations/postgres/0003_m4_auth_policy_cors_lock.sql");
pub const PG_MIGRATION_004: &str =
    include_str!("../migrations/postgres/0004_dashboard_enhancements.sql");

/// DDL Postgres đầy đủ cho DBA tạo schema trước (`telecrate db pg-schema`).
pub const POSTGRES_SCHEMA: &str = concat!(
    include_str!("../migrations/postgres/0001_init.sql"),
    include_str!("../migrations/postgres/0002_m3_multipart_versioning.sql"),
    include_str!("../migrations/postgres/0003_m4_auth_policy_cors_lock.sql"),
    include_str!("../migrations/postgres/0004_dashboard_enhancements.sql"),
);

/// Lấy version migration hiện tại (0 nếu chưa có bảng).
pub async fn schema_version(db: &Db) -> Result<i64, String> {
    match fetch_opt(
        db,
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        &[],
    )
    .await
    {
        Ok(Some(r)) => r.get_i64(0),
        Ok(None) => Ok(0),
        Err(e) if is_missing_table(&e) => Ok(0),
        Err(e) => Err(e),
    }
}

fn is_missing_table(e: &str) -> bool {
    e.contains("no such table") || e.contains("does not exist")
}

/// Tách file migration thành từng statement (bỏ rỗng). Loại bỏ comment `--` trước khi split ';'.
fn split_statements(sql: &str) -> Vec<String> {
    let mut cleaned = String::with_capacity(sql.len());
    for line in sql.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("--") {
            continue;
        }
        if let Some(idx) = line.find("--") {
            cleaned.push_str(&line[..idx]);
        } else {
            cleaned.push_str(line);
        }
        cleaned.push('\n');
    }
    cleaned
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Apply migration SQL một lần trong txn, ghi schema_version cùng txn.
pub async fn apply_migration(db: &Db, version: i64, sql: &str) -> Result<(), String> {
    let mut tx = db.begin().await?;
    for stmt in split_statements(sql) {
        tx.exec(&stmt, &[])
            .await
            .map_err(|e| format!("migration {version}: {e}"))?;
    }
    tx.exec(
        "INSERT INTO schema_version(version) VALUES (?)",
        &[Val::int(version)],
    )
    .await
    .map_err(|e| format!("record version: {e}"))?;
    tx.commit().await?;
    Ok(())
}

/// Apply tất cả migrations chưa apply từ 0 lên head (từng backend đúng dialect).
pub async fn apply_all_migrations(db: &Db) -> Result<i64, String> {
    let mut current = schema_version(db).await?;
    let steps: &[(i64, &str)] = match db.backend() {
        DbBackend::Sqlite => &[
            (1, MIGRATION_001),
            (2, MIGRATION_002),
            (3, MIGRATION_003),
            (4, MIGRATION_004),
        ],
        DbBackend::Postgres => &[
            (1, PG_MIGRATION_001),
            (2, PG_MIGRATION_002),
            (3, PG_MIGRATION_003),
            (4, PG_MIGRATION_004),
        ],
    };
    for (v, sql) in steps {
        if current < *v {
            apply_migration(db, *v, sql).await?;
            current = *v;
        }
    }
    Ok(current)
}

pub const ENC_DB_MAGIC: &[u8] = b"TELECRATE_ENC_DB_V1";

/// Backup DB online ra file.
/// SQLite: `VACUUM INTO` (snapshot nhất quán, không cần backup API cũ).
/// Postgres: dùng `pg_dump` ngoài (không có snapshot file tích hợp) — báo lỗi rõ + gợi ý.
pub async fn backup_db(db: &Db, target_path: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(target_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create backup parent dir: {e}"))?;
        }
    }
    if Path::new(target_path).exists() {
        std::fs::remove_file(target_path)
            .map_err(|e| format!("remove existing backup file: {e}"))?;
    }
    match db {
        Db::Sqlite(_) => {
            let escaped = target_path.replace('\'', "''");
            exec(db, &format!("VACUUM INTO '{escaped}'"), &[]).await?;
            Ok(())
        }
        Db::Postgres(_) => Err(
            "postgres backup: dùng `pg_dump \"$DATABASE_URL\" -Fc -f <file>` ngoài, \
             hoặc `telecrate recovery export` (JSON, chạy được cả hai backend)"
                .to_string(),
        ),
    }
}

/// Backup DB có mã hóa bằng passphrase.
pub async fn backup_db_encrypted(
    db: &Db,
    target_path: &str,
    passphrase: &str,
) -> Result<(), String> {
    let temp_dir = tempfile::tempdir().map_err(|e| format!("create temp dir: {e}"))?;
    let temp_backup = temp_dir.path().join("plain_backup.db");
    let temp_str = temp_backup.to_str().ok_or("invalid temp path")?;

    backup_db(db, temp_str).await?;
    let plain_bytes = std::fs::read(&temp_backup).map_err(|e| format!("read temp backup: {e}"))?;

    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut salt).map_err(|e| format!("getrandom salt: {e}"))?;
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("getrandom nonce: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(salt);
    let key_bytes = hasher.finalize();

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let mut buf = plain_bytes;
    cipher
        .encrypt_in_place(Nonce::from_slice(&nonce_bytes), ENC_DB_MAGIC, &mut buf)
        .map_err(|e| format!("encrypt db: {e}"))?;

    let mut out = Vec::with_capacity(ENC_DB_MAGIC.len() + 16 + 12 + buf.len());
    out.extend_from_slice(ENC_DB_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);

    if let Some(parent) = Path::new(target_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create enc backup parent dir: {e}"))?;
        }
    }
    std::fs::write(target_path, out).map_err(|e| format!("write encrypted backup: {e}"))?;
    Ok(())
}

/// Restore DB từ file backup SQLite (plain hoặc encrypted với passphrase).
/// File pg_dump không dùng được ở đây — restore Postgres bằng `pg_restore`/`psql` ngoài.
pub async fn restore_db(
    backup_path: &str,
    target_db_path: &str,
    passphrase: Option<&str>,
) -> Result<(), String> {
    let raw = std::fs::read(backup_path).map_err(|e| format!("read backup file: {e}"))?;
    if raw.is_empty() {
        return Err("backup file is empty".into());
    }

    let temp_dir = tempfile::tempdir().map_err(|e| format!("create temp dir: {e}"))?;
    let temp_restored = temp_dir.path().join("restored.db");

    if raw.starts_with(ENC_DB_MAGIC) {
        let pass = passphrase.ok_or("encrypted backup requires a passphrase")?;
        if raw.len() < ENC_DB_MAGIC.len() + 16 + 12 {
            return Err("encrypted backup file is corrupted or truncated".into());
        }
        let salt = &raw[ENC_DB_MAGIC.len()..ENC_DB_MAGIC.len() + 16];
        let nonce = &raw[ENC_DB_MAGIC.len() + 16..ENC_DB_MAGIC.len() + 28];
        let ciphertext = &raw[ENC_DB_MAGIC.len() + 28..];

        let mut hasher = Sha256::new();
        hasher.update(pass.as_bytes());
        hasher.update(salt);
        let key_bytes = hasher.finalize();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let mut buf = ciphertext.to_vec();
        cipher
            .decrypt_in_place(Nonce::from_slice(nonce), ENC_DB_MAGIC, &mut buf)
            .map_err(|_| "decrypt backup failed (wrong passphrase or tampered file)".to_string())?;

        std::fs::write(&temp_restored, buf).map_err(|e| format!("write restored temp: {e}"))?;
    } else {
        if !raw.starts_with(b"SQLite format 3\0") {
            return Err("invalid SQLite database backup format".into());
        }
        std::fs::write(&temp_restored, raw).map_err(|e| format!("write restored temp: {e}"))?;
    }

    // Kiểm tra integrity và schema_version của file DB sau giải mã
    let restored = Db::open_sqlite(temp_restored.to_str().unwrap()).await?;
    let integrity = fetch_opt(&restored, "PRAGMA integrity_check", &[])
        .await?
        .and_then(|r| r.get_string(0).ok())
        .unwrap_or_default();
    if integrity != "ok" {
        return Err(format!("backup DB integrity check failed: {integrity}"));
    }
    let ver = schema_version(&restored).await?;
    if ver < 1 {
        return Err(format!("invalid DB schema version in backup: {ver}"));
    }
    drop(restored);

    // Backup DB hiện tại (nếu có) trước khi ghi đè
    let target = Path::new(target_db_path);
    if target.exists() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let safety_backup = format!("{target_db_path}.bak_{ts}");
        let _ = std::fs::copy(target_db_path, &safety_backup);
    } else if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create target db parent dir: {e}"))?;
        }
    }

    // Ghi đè file DB đích
    std::fs::copy(&temp_restored, target_db_path).map_err(|e| format!("copy restored db: {e}"))?;

    // Verify DB đích mở được bình thường
    let target_db = Db::open_sqlite(target_db_path).await?;
    let target_ver = schema_version(&target_db).await?;
    if target_ver != ver {
        return Err(format!(
            "mismatch in schema version after restore: expected {ver}, got {target_ver}"
        ));
    }

    Ok(())
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
pub async fn create_multipart_upload(
    db: &Db,
    upload_id: &str,
    bucket: &str,
    key: &str,
    content_type: &str,
    metadata_json: Option<&str>,
) -> Result<(), String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    exec(
        db,
        "INSERT INTO multipart_uploads(upload_id, bucket, key, content_type, metadata_json) VALUES (?, ?, ?, ?, ?)",
        &[
            Val::text(upload_id),
            Val::text(bucket),
            Val::text(key),
            Val::text(content_type),
            Val::opt_text(metadata_json),
        ],
    )
    .await
    .map_err(|e| format!("insert multipart_upload: {e}"))?;
    Ok(())
}

/// Lấy thông tin Multipart Upload theo upload_id.
pub async fn get_multipart_upload(
    db: &Db,
    upload_id: &str,
) -> Result<Option<MultipartUpload>, String> {
    let row = fetch_opt(
        db,
        "SELECT upload_id, bucket, key, content_type, metadata_json, created_at FROM multipart_uploads WHERE upload_id = ?",
        &[Val::text(upload_id)],
    )
    .await
    .map_err(|e| format!("query get multipart_upload: {e}"))?;
    match row {
        Some(r) => Ok(Some(MultipartUpload {
            upload_id: r
                .get_string(0)
                .map_err(|e| format!("row multipart_upload: {e}"))?,
            bucket: r
                .get_string(1)
                .map_err(|e| format!("row multipart_upload: {e}"))?,
            key: r
                .get_string(2)
                .map_err(|e| format!("row multipart_upload: {e}"))?,
            content_type: r
                .get_string(3)
                .map_err(|e| format!("row multipart_upload: {e}"))?,
            metadata_json: r
                .get_opt_string(4)
                .map_err(|e| format!("row multipart_upload: {e}"))?,
            created_at: r
                .get_string(5)
                .map_err(|e| format!("row multipart_upload: {e}"))?,
        })),
        None => Ok(None),
    }
}

/// Lưu hoặc cập nhật một Part của Multipart Upload.
#[allow(clippy::too_many_arguments)]
pub async fn save_multipart_part(
    db: &Db,
    upload_id: &str,
    part_number: i32,
    size: i64,
    etag: &str,
    plaintext_sha256: &str,
    ciphertext_sha256: &str,
    spool_path: Option<&str>,
) -> Result<(), String> {
    exec(
        db,
        "INSERT INTO multipart_parts(upload_id, part_number, size, etag, plaintext_sha256, ciphertext_sha256, spool_path)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(upload_id, part_number) DO UPDATE SET
            size=excluded.size, etag=excluded.etag, plaintext_sha256=excluded.plaintext_sha256,
            ciphertext_sha256=excluded.ciphertext_sha256, spool_path=excluded.spool_path, state='pending'",
        &[
            Val::text(upload_id),
            Val::int(part_number as i64),
            Val::int(size),
            Val::text(etag),
            Val::text(plaintext_sha256),
            Val::text(ciphertext_sha256),
            Val::opt_text(spool_path),
        ],
    )
    .await
    .map_err(|e| format!("insert/update multipart_part: {e}"))?;
    Ok(())
}

/// Liệt kê các Part đã upload theo thứ tự part_number tăng dần.
pub async fn list_multipart_parts(db: &Db, upload_id: &str) -> Result<Vec<MultipartPart>, String> {
    let rows = fetch_all(
        db,
        "SELECT upload_id, part_number, size, etag, plaintext_sha256, ciphertext_sha256, spool_path, remote_locator_json, state, created_at
                  FROM multipart_parts WHERE upload_id = ? ORDER BY part_number ASC",
        &[Val::text(upload_id)],
    )
    .await
    .map_err(|e| format!("query list multipart_parts: {e}"))?;
    let mut parts = Vec::new();
    for r in rows {
        parts.push(MultipartPart {
            upload_id: r
                .get_string(0)
                .map_err(|e| format!("row multipart_part: {e}"))?,
            part_number: r
                .get_i32(1)
                .map_err(|e| format!("row multipart_part: {e}"))?,
            size: r
                .get_i64(2)
                .map_err(|e| format!("row multipart_part: {e}"))?,
            etag: r
                .get_string(3)
                .map_err(|e| format!("row multipart_part: {e}"))?,
            plaintext_sha256: r
                .get_string(4)
                .map_err(|e| format!("row multipart_part: {e}"))?,
            ciphertext_sha256: r
                .get_string(5)
                .map_err(|e| format!("row multipart_part: {e}"))?,
            spool_path: r
                .get_opt_string(6)
                .map_err(|e| format!("row multipart_part: {e}"))?,
            remote_locator_json: r
                .get_opt_string(7)
                .map_err(|e| format!("row multipart_part: {e}"))?,
            state: r
                .get_string(8)
                .map_err(|e| format!("row multipart_part: {e}"))?,
            created_at: r
                .get_string(9)
                .map_err(|e| format!("row multipart_part: {e}"))?,
        });
    }
    Ok(parts)
}

/// Hủy Multipart Upload: xóa record DB và trả về danh sách spool_path để dọn đĩa.
pub async fn abort_multipart_upload(db: &Db, upload_id: &str) -> Result<Vec<String>, String> {
    let parts = list_multipart_parts(db, upload_id).await?;
    let spool_paths: Vec<String> = parts.into_iter().filter_map(|p| p.spool_path).collect();

    let mut tx = db.begin().await?;
    tx.exec(
        "DELETE FROM multipart_parts WHERE upload_id = ?",
        &[Val::text(upload_id)],
    )
    .await
    .map_err(|e| format!("delete parts: {e}"))?;
    tx.exec(
        "DELETE FROM multipart_uploads WHERE upload_id = ?",
        &[Val::text(upload_id)],
    )
    .await
    .map_err(|e| format!("delete upload: {e}"))?;
    tx.commit().await?;

    Ok(spool_paths)
}

/// Liệt kê tất cả Multipart Uploads chưa hoàn thành của một bucket.
pub async fn list_multipart_uploads(db: &Db, bucket: &str) -> Result<Vec<MultipartUpload>, String> {
    let rows = fetch_all(
        db,
        "SELECT upload_id, bucket, key, content_type, metadata_json, created_at FROM multipart_uploads WHERE bucket = ? ORDER BY created_at ASC",
        &[Val::text(bucket)],
    )
    .await
    .map_err(|e| format!("query list multipart_uploads: {e}"))?;
    let mut uploads = Vec::new();
    for r in rows {
        uploads.push(MultipartUpload {
            upload_id: r
                .get_string(0)
                .map_err(|e| format!("row list multipart_uploads: {e}"))?,
            bucket: r
                .get_string(1)
                .map_err(|e| format!("row list multipart_uploads: {e}"))?,
            key: r
                .get_string(2)
                .map_err(|e| format!("row list multipart_uploads: {e}"))?,
            content_type: r
                .get_string(3)
                .map_err(|e| format!("row list multipart_uploads: {e}"))?,
            metadata_json: r
                .get_opt_string(4)
                .map_err(|e| format!("row list multipart_uploads: {e}"))?,
            created_at: r
                .get_string(5)
                .map_err(|e| format!("row list multipart_uploads: {e}"))?,
        });
    }
    Ok(uploads)
}

async fn get_bucket_versioning_tx(tx: &mut Tx<'_>, bucket: &str) -> Result<String, String> {
    let row = tx
        .fetch_opt(
            "SELECT versioning_status FROM buckets WHERE name = ?",
            &[Val::text(bucket)],
        )
        .await
        .map_err(|e| format!("query: {e}"))?;
    match row {
        Some(r) => r.get_string(0).map_err(|e| format!("row: {e}")),
        None => Ok("Disabled".to_string()),
    }
}

async fn prepare_versioning_write_tx(
    tx: &mut Tx<'_>,
    bucket: &str,
    key: &str,
    requested_version_id: &str,
) -> Result<(String, Vec<String>), String> {
    let v_status = get_bucket_versioning_tx(tx, bucket).await?;
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
        let rows = tx
            .fetch_all("SELECT spool_path FROM chunks WHERE version_id = 'null' AND version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)", &[Val::text(bucket), Val::text(key)])
            .await
            .map_err(|e| format!("query: {e}"))?;
        let null_spools: Vec<String> = rows
            .into_iter()
            .filter_map(|r| r.get_opt_string(0).unwrap_or(None))
            .collect();
        old_spools.extend(null_spools);
        tx.exec("DELETE FROM upload_jobs WHERE version_id = 'null' AND version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)", &[Val::text(bucket), Val::text(key)]).await.ok();
        tx.exec("DELETE FROM chunks WHERE version_id = 'null' AND version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)", &[Val::text(bucket), Val::text(key)]).await.ok();
        tx.exec(
            "DELETE FROM objects WHERE bucket = ? AND key = ? AND version_id = 'null'",
            &[Val::text(bucket), Val::text(key)],
        )
        .await
        .ok();
    } else {
        // Disabled: delete all previous versions
        let rows = tx
            .fetch_all("SELECT spool_path FROM chunks WHERE version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)", &[Val::text(bucket), Val::text(key)])
            .await
            .map_err(|e| format!("query: {e}"))?;
        let spools: Vec<String> = rows
            .into_iter()
            .filter_map(|r| r.get_opt_string(0).unwrap_or(None))
            .collect();
        old_spools.extend(spools);
        tx.exec("DELETE FROM upload_jobs WHERE version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)", &[Val::text(bucket), Val::text(key)]).await.ok();
        tx.exec("DELETE FROM chunks WHERE version_id IN (SELECT version_id FROM objects WHERE bucket = ? AND key = ?)", &[Val::text(bucket), Val::text(key)]).await.ok();
        tx.exec(
            "DELETE FROM objects WHERE bucket = ? AND key = ?",
            &[Val::text(bucket), Val::text(key)],
        )
        .await
        .ok();
    }
    Ok((final_version_id, old_spools))
}

/// Hoàn tất Multipart Upload trong 1 txn duy nhất.
pub async fn complete_multipart_upload_txn(
    db: &Db,
    upload_id: &str,
    version_id: &str,
    requested_parts: &[(i32, String)],
    job_id: &str,
) -> Result<(Vec<String>, ObjectVersion), String> {
    let upload = get_multipart_upload(db, upload_id)
        .await?
        .ok_or_else(|| "NoSuchUpload".to_string())?;

    let parts = list_multipart_parts(db, upload_id).await?;
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

    let mut tx = db.begin().await?;

    let (final_version_id, old_spools) =
        prepare_versioning_write_tx(&mut tx, &bucket, &key, version_id).await?;

    tx.exec(
        "INSERT INTO objects(bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type, user_metadata_json) VALUES (?, ?, ?, 0, 'accepted-local', ?, ?, ?, ?)",
        &[
            Val::text(&bucket),
            Val::text(&key),
            Val::text(&final_version_id),
            Val::int(total_size),
            Val::text(&multipart_etag),
            Val::text(&upload.content_type),
            Val::opt_text(upload.metadata_json.as_deref()),
        ],
    )
    .await
    .map_err(|e| format!("insert object: {e}"))?;

    let mut current_offset: i64 = 0;
    for (idx, part) in parts.iter().enumerate() {
        let spool_path = part.spool_path.as_deref().unwrap_or("");
        tx.exec(
            "INSERT INTO chunks(version_id, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, spool_path, state) VALUES (?, ?, ?, ?, ?, ?, 'none', ?, 'pending')",
            &[
                Val::text(&final_version_id),
                Val::int(idx as i64),
                Val::int(current_offset),
                Val::int(part.size),
                Val::text(&part.plaintext_sha256),
                Val::text(&part.ciphertext_sha256),
                Val::text(spool_path),
            ],
        )
        .await
        .map_err(|e| format!("insert chunk: {e}"))?;
        current_offset += part.size;
    }

    tx.exec(
        "INSERT INTO upload_jobs(job_id, version_id, state) VALUES (?, ?, 'pending')",
        &[Val::text(job_id), Val::text(&final_version_id)],
    )
    .await
    .map_err(|e| format!("insert job: {e}"))?;

    tx.exec(
        "DELETE FROM multipart_parts WHERE upload_id = ?",
        &[Val::text(upload_id)],
    )
    .await
    .map_err(|e| format!("delete parts: {e}"))?;
    tx.exec(
        "DELETE FROM multipart_uploads WHERE upload_id = ?",
        &[Val::text(upload_id)],
    )
    .await
    .map_err(|e| format!("delete upload: {e}"))?;

    tx.commit().await?;

    let version = latest_version(db, &bucket, &key)
        .await?
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

pub async fn get_bucket_versioning(db: &Db, bucket: &str) -> Result<String, String> {
    let row = fetch_opt(
        db,
        "SELECT versioning_status FROM buckets WHERE name = ?",
        &[Val::text(bucket)],
    )
    .await
    .map_err(|e| format!("query: {e}"))?;
    match row {
        Some(r) => r.get_string(0).map_err(|e| format!("row: {e}")),
        None => Ok("Disabled".to_string()),
    }
}

pub async fn set_bucket_versioning(db: &Db, bucket: &str, status: &str) -> Result<(), String> {
    let affected = exec(
        db,
        "UPDATE buckets SET versioning_status = ? WHERE name = ?",
        &[Val::text(status), Val::text(bucket)],
    )
    .await
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
pub async fn create_bucket(
    db: &Db,
    name: &str,
    region: &str,
) -> Result<CreateBucketOutcome, String> {
    if !valid_bucket_name(name) {
        return Err("InvalidBucketName".to_string());
    }
    let row = fetch_opt(
        db,
        "SELECT COUNT(*) FROM buckets WHERE name = ?",
        &[Val::text(name)],
    )
    .await
    .map_err(|e| format!("lookup bucket: {e}"))?;
    let n = row
        .map(|r| r.get_i64(0))
        .transpose()
        .map_err(|e| format!("lookup bucket: {e}"))?
        .unwrap_or(0);
    if n > 0 {
        return Ok(CreateBucketOutcome::AlreadyOwned);
    }
    exec(
        db,
        "INSERT INTO buckets(name, region) VALUES (?, ?)",
        &[Val::text(name), Val::text(region)],
    )
    .await
    .map_err(|e| format!("insert bucket: {e}"))?;
    Ok(CreateBucketOutcome::Created)
}

pub async fn head_bucket(db: &Db, name: &str) -> Result<bool, String> {
    let row = fetch_opt(
        db,
        "SELECT COUNT(*) FROM buckets WHERE name = ?",
        &[Val::text(name)],
    )
    .await
    .map_err(|e| format!("lookup bucket: {e}"))?;
    let n = row
        .map(|r| r.get_i64(0))
        .transpose()
        .map_err(|e| format!("lookup bucket: {e}"))?
        .unwrap_or(0);
    Ok(n > 0)
}

/// Xóa bucket — từ chối khi còn object/version (S3: 409 BucketNotEmpty).
pub async fn delete_bucket(db: &Db, name: &str) -> Result<DeleteBucketOutcome, String> {
    if !head_bucket(db, name).await? {
        return Ok(DeleteBucketOutcome::NoSuchBucket);
    }
    let row = fetch_opt(
        db,
        "SELECT COUNT(*) FROM objects WHERE bucket = ?",
        &[Val::text(name)],
    )
    .await
    .map_err(|e| format!("count objects: {e}"))?;
    let n = row
        .map(|r| r.get_i64(0))
        .transpose()
        .map_err(|e| format!("count objects: {e}"))?
        .unwrap_or(0);
    if n > 0 {
        return Ok(DeleteBucketOutcome::NotEmpty);
    }
    exec(db, "DELETE FROM buckets WHERE name = ?", &[Val::text(name)])
        .await
        .map_err(|e| format!("delete bucket: {e}"))?;
    Ok(DeleteBucketOutcome::Deleted)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteBucketOutcome {
    Deleted,
    NoSuchBucket,
    NotEmpty,
}

pub async fn list_buckets(db: &Db) -> Result<Vec<Bucket>, String> {
    let rows = fetch_all(
        db,
        "SELECT name, region, versioning_status, created_at FROM buckets ORDER BY name",
        &[],
    )
    .await
    .map_err(|e| format!("query: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(Bucket {
            name: r.get_string(0).map_err(|e| format!("rows: {e}"))?,
            region: r.get_string(1).map_err(|e| format!("rows: {e}"))?,
            versioning_status: r.get_string(2).map_err(|e| format!("rows: {e}"))?,
            created_at: r.get_string(3).map_err(|e| format!("rows: {e}"))?,
        });
    }
    Ok(out)
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
pub async fn put_object(
    conn: &Db,
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
    let mut tx = conn.begin().await?;

    let (final_version_id, old_spools) =
        prepare_versioning_write_tx(&mut tx, bucket, key, version_id).await?;

    tx.exec(
        "INSERT INTO objects(bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type, user_metadata_json, system_metadata_json) VALUES (?, ?, ?, 0, 'accepted-local', ?, ?, ?, ?, ?)",
        &[
            Val::text(bucket),
            Val::text(key),
            Val::text(&final_version_id),
            Val::int(size),
            Val::text(etag),
            Val::text(content_type),
            Val::opt_text(user_metadata_json),
            Val::opt_text(system_metadata_json),
        ],
    )
    .await
    .map_err(|e| format!("insert object: {e}"))?;
    for (idx, c) in chunks.iter().enumerate() {
        tx.exec(
            "INSERT INTO chunks(version_id, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref, spool_path, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
            &[
                Val::text(&final_version_id),
                Val::int(idx as i64),
                Val::int(c.offset),
                Val::int(c.length),
                Val::text(&c.plaintext_sha256),
                Val::text(&c.ciphertext_sha256),
                Val::text(&c.mode),
                Val::opt_text(c.key_ref.as_deref()),
                Val::text(&c.spool_path),
            ],
        )
        .await
        .map_err(|e| format!("insert chunk: {e}"))?;
    }
    tx.exec(
        "INSERT INTO upload_jobs(job_id, version_id, state) VALUES (?, ?, 'pending')",
        &[Val::text(job_id), Val::text(&final_version_id)],
    )
    .await
    .map_err(|e| format!("insert job: {e}"))?;
    tx.commit().await?;
    Ok((old_spools, final_version_id))
}

/// CopyObject: Sao chép object từ (src_bucket, src_key) sang (dest_bucket, dest_key).
/// Hỗ trợ zero-duplicate spool bằng cách tạo version_id mới và trỏ cùng các chunks/locators từ DB.
#[allow(clippy::too_many_arguments)]
pub async fn copy_object_txn(
    conn: &Db,
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
    if !head_bucket(conn, dest_bucket).await? {
        return Err("NoSuchBucket".to_string());
    }

    let src_version = latest_version(conn, src_bucket, src_key)
        .await?
        .ok_or_else(|| "NoSuchKey".to_string())?;

    let src_chunks = chunks_of(conn, &src_version.version_id).await?;

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

    let mut tx = conn.begin().await?;

    let (final_version_id, old_spools) =
        prepare_versioning_write_tx(&mut tx, dest_bucket, dest_key, new_version_id).await?;

    tx.exec(
        "INSERT INTO objects(bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type, user_metadata_json, system_metadata_json) VALUES (?, ?, ?, 0, 'accepted-local', ?, ?, ?, ?, ?)",
        &[
            Val::text(dest_bucket),
            Val::text(dest_key),
            Val::text(&final_version_id),
            Val::int(src_version.size),
            Val::text(&src_version.etag),
            Val::text(&final_content_type),
            Val::opt_text(final_user_meta.as_deref()),
            Val::opt_text(final_sys_meta.as_deref()),
        ],
    )
    .await
    .map_err(|e| format!("insert object: {e}"))?;

    let mut need_upload = false;
    for c in &src_chunks {
        tx.exec(
            "INSERT INTO chunks(version_id, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref, spool_path, remote_locator_json, state)
             SELECT ?, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref, spool_path, remote_locator_json, state
             FROM chunks WHERE version_id = ? AND idx = ?",
            &[Val::text(&final_version_id), Val::text(&src_version.version_id), Val::int(c.idx)],
        )
        .await
        .map_err(|e| format!("copy chunk: {e}"))?;

        if c.state == "pending" {
            need_upload = true;
        }
    }

    if need_upload {
        tx.exec(
            "INSERT INTO upload_jobs(job_id, version_id, state) VALUES (?, ?, 'pending')",
            &[Val::text(new_job_id), Val::text(&final_version_id)],
        )
        .await
        .map_err(|e| format!("insert job: {e}"))?;
    }

    tx.commit().await?;

    let version = latest_version(conn, dest_bucket, dest_key)
        .await?
        .ok_or_else(|| "Failed to fetch copied object version".to_string())?;

    Ok((old_spools, version))
}

/// Cột tiebreaker "bản ghi chèn sau" khi created_at trùng nhau:
/// `rowid` (SQLite) / `ctid` (Postgres). Không dùng version_id vì uuid ngẫu nhiên.
fn tiebreak_col(backend: DbBackend) -> &'static str {
    match backend {
        DbBackend::Sqlite => "rowid",
        DbBackend::Postgres => "ctid",
    }
}

pub async fn latest_version(
    db: &Db,
    bucket: &str,
    key: &str,
) -> Result<Option<ObjectVersion>, String> {
    let tb = tiebreak_col(db.backend());
    let sql = format!("SELECT version_id, key, is_delete_marker, size, etag, content_type, storage_state, created_at, user_metadata_json, system_metadata_json FROM objects WHERE bucket = ? AND key = ? ORDER BY created_at DESC, {tb} DESC LIMIT 1");
    let row = fetch_opt(db, &sql, &[Val::text(bucket), Val::text(key)])
        .await
        .map_err(|e| format!("query: {e}"))?;
    match row {
        Some(r) => Ok(Some(ObjectVersion {
            version_id: r.get_string(0).map_err(|e| format!("row: {e}"))?,
            key: r.get_string(1).map_err(|e| format!("row: {e}"))?,
            is_delete_marker: r.get_bool(2).map_err(|e| format!("row: {e}"))?,
            size: r.get_i64(3).map_err(|e| format!("row: {e}"))?,
            etag: r.get_string(4).map_err(|e| format!("row: {e}"))?,
            content_type: r.get_string(5).map_err(|e| format!("row: {e}"))?,
            storage_state: r.get_string(6).map_err(|e| format!("row: {e}"))?,
            created_at: r.get_string(7).map_err(|e| format!("row: {e}"))?,
            user_metadata_json: r.get_opt_string(8).map_err(|e| format!("row: {e}"))?,
            system_metadata_json: r.get_opt_string(9).map_err(|e| format!("row: {e}"))?,
        })),
        None => Ok(None),
    }
}

pub async fn get_version_by_id(
    db: &Db,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<Option<ObjectVersion>, String> {
    let row = fetch_opt(
        db,
        "SELECT version_id, key, is_delete_marker, size, etag, content_type, storage_state, created_at, user_metadata_json, system_metadata_json FROM objects WHERE bucket = ? AND key = ? AND version_id = ?",
        &[Val::text(bucket), Val::text(key), Val::text(version_id)],
    )
    .await
    .map_err(|e| format!("query: {e}"))?;
    match row {
        Some(r) => Ok(Some(ObjectVersion {
            version_id: r.get_string(0).map_err(|e| format!("row: {e}"))?,
            key: r.get_string(1).map_err(|e| format!("row: {e}"))?,
            is_delete_marker: r.get_bool(2).map_err(|e| format!("row: {e}"))?,
            size: r.get_i64(3).map_err(|e| format!("row: {e}"))?,
            etag: r.get_string(4).map_err(|e| format!("row: {e}"))?,
            content_type: r.get_string(5).map_err(|e| format!("row: {e}"))?,
            storage_state: r.get_string(6).map_err(|e| format!("row: {e}"))?,
            created_at: r.get_string(7).map_err(|e| format!("row: {e}"))?,
            user_metadata_json: r.get_opt_string(8).map_err(|e| format!("row: {e}"))?,
            system_metadata_json: r.get_opt_string(9).map_err(|e| format!("row: {e}"))?,
        })),
        None => Ok(None),
    }
}

pub async fn chunks_of(db: &Db, version_id: &str) -> Result<Vec<ChunkRow>, String> {
    let rows = fetch_all(
        db,
        "SELECT idx, length, spool_path, state, encryption_mode, key_ref FROM chunks WHERE version_id = ? ORDER BY idx",
        &[Val::text(version_id)],
    )
    .await
    .map_err(|e| format!("query: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(ChunkRow {
            idx: r.get_i64(0).map_err(|e| format!("rows: {e}"))?,
            length: r.get_i64(1).map_err(|e| format!("rows: {e}"))?,
            spool_path: r.get_opt_string(2).map_err(|e| format!("rows: {e}"))?,
            state: r.get_string(3).map_err(|e| format!("rows: {e}"))?,
            encryption_mode: r.get_string(4).map_err(|e| format!("rows: {e}"))?,
            key_ref: r.get_opt_string(5).map_err(|e| format!("rows: {e}"))?,
        });
    }
    Ok(out)
}

/// Xóa object: trả spool paths để caller dọn + locators đã remote (caller best-effort xóa remote).
pub struct DeleteObjectResult {
    pub existed: bool,
    pub spool_paths: Vec<String>,
    pub remote_locators: Vec<crate::telegram::RemoteLocator>,
    pub is_delete_marker: bool,
    pub version_id: String,
}

pub async fn create_delete_marker(db: &Db, bucket: &str, key: &str) -> Result<String, String> {
    let mut tx = db.begin().await?;
    let (version_id, _) = prepare_versioning_write_tx(&mut tx, bucket, key, "null").await?;
    tx.exec(
        "INSERT INTO objects(bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type) VALUES (?, ?, ?, 1, 'accepted-local', 0, '', '')",
        &[Val::text(bucket), Val::text(key), Val::text(&version_id)],
    ).await.map_err(|e| format!("insert delete marker: {e}"))?;
    tx.commit().await?;
    Ok(version_id)
}

pub async fn delete_object_version(
    db: &Db,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<DeleteObjectResult, String> {
    let mut tx = db.begin().await?;

    let is_dm = match tx
        .fetch_opt(
            "SELECT is_delete_marker FROM objects WHERE bucket = ? AND key = ? AND version_id = ?",
            &[Val::text(bucket), Val::text(key), Val::text(version_id)],
        )
        .await
        .map_err(|e| format!("query: {e}"))?
    {
        Some(r) => r.get_bool(0).map_err(|e| format!("row: {e}"))?,
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

    let rows = tx
        .fetch_all(
            "SELECT spool_path FROM chunks WHERE version_id = ?",
            &[Val::text(version_id)],
        )
        .await
        .map_err(|e| format!("query: {e}"))?;
    let spool_paths: Vec<String> = rows
        .into_iter()
        .filter_map(|r| r.get_opt_string(0).unwrap_or(None))
        .collect();

    tx.exec(
        "DELETE FROM upload_jobs WHERE version_id = ?",
        &[Val::text(version_id)],
    )
    .await
    .ok();
    tx.exec(
        "DELETE FROM chunks WHERE version_id = ?",
        &[Val::text(version_id)],
    )
    .await
    .ok();
    tx.exec(
        "DELETE FROM objects WHERE bucket = ? AND key = ? AND version_id = ?",
        &[Val::text(bucket), Val::text(key), Val::text(version_id)],
    )
    .await
    .map_err(|e| format!("delete version: {e}"))?;

    tx.commit().await?;

    Ok(DeleteObjectResult {
        existed: true,
        spool_paths,
        remote_locators: Vec::new(),
        is_delete_marker: is_dm,
        version_id: version_id.to_string(),
    })
}

pub async fn delete_object(db: &Db, bucket: &str, key: &str) -> Result<DeleteObjectResult, String> {
    let mut tx = db.begin().await?;
    let rows = tx
        .fetch_all(
            "SELECT version_id FROM objects WHERE bucket = ? AND key = ?",
            &[Val::text(bucket), Val::text(key)],
        )
        .await
        .map_err(|e| format!("query: {e}"))?;
    let versions: Vec<String> = rows
        .into_iter()
        .filter_map(|r| r.get_string(0).ok())
        .collect();
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
        let rows = tx
            .fetch_all(
                "SELECT spool_path, state, remote_locator_json FROM chunks WHERE version_id = ?",
                &[Val::text(v)],
            )
            .await
            .map_err(|e| format!("query: {e}"))?;
        for r in rows {
            let spool = r.get_opt_string(0).map_err(|e| format!("rows: {e}"))?;
            let state = r.get_string(1).map_err(|e| format!("rows: {e}"))?;
            let locator = r.get_opt_string(2).map_err(|e| format!("rows: {e}"))?;
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
        tx.exec(
            "DELETE FROM upload_jobs WHERE version_id = ?",
            &[Val::text(v)],
        )
        .await
        .map_err(|e| format!("delete jobs: {e}"))?;
        tx.exec("DELETE FROM chunks WHERE version_id = ?", &[Val::text(v)])
            .await
            .map_err(|e| format!("delete chunks: {e}"))?;
    }
    tx.exec(
        "DELETE FROM objects WHERE bucket = ? AND key = ?",
        &[Val::text(bucket), Val::text(key)],
    )
    .await
    .map_err(|e| format!("delete objects: {e}"))?;
    tx.commit().await?;
    Ok(DeleteObjectResult {
        existed: true,
        spool_paths,
        remote_locators,
        is_delete_marker: false,
        version_id: String::new(),
    })
}

pub async fn list_object_versions(
    db: &Db,
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
    let tb = tiebreak_col(db.backend());
    let sql = format!("SELECT key, version_id, is_delete_marker, size, etag, created_at FROM objects WHERE bucket = ? AND key LIKE ? || '%' ESCAPE '\\' AND (key > ? OR (key = ? AND version_id > ?)) ORDER BY key ASC, created_at DESC, {tb} DESC LIMIT ?");
    let rows = fetch_all(
        db,
        &sql,
        &[
            Val::text(bucket),
            Val::text(&esc),
            Val::text(key_marker),
            Val::text(key_marker),
            Val::text(version_id_marker),
            Val::int(limit),
        ],
    )
    .await
    .map_err(|e| format!("query: {e}"))?;

    let mut result = Vec::new();
    let mut last_key: Option<String> = None;

    for r in rows {
        let key = r.get_string(0).map_err(|e| format!("row: {e}"))?;
        let version_id = r.get_string(1).map_err(|e| format!("row: {e}"))?;
        let is_delete_marker = r.get_bool(2).map_err(|e| format!("row: {e}"))?;
        let size = r.get_i64(3).map_err(|e| format!("row: {e}"))?;
        let etag = r.get_string(4).map_err(|e| format!("row: {e}"))?;
        let created_at = r.get_string(5).map_err(|e| format!("row: {e}"))?;
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
pub async fn list_keys(
    db: &Db,
    bucket: &str,
    prefix: &str,
    start_after: &str,
    limit_plus_one: i64,
) -> Result<Vec<(String, ObjectVersion)>, String> {
    let esc = prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let tb = tiebreak_col(db.backend());
    let sql = format!("SELECT key, version_id, is_delete_marker, size, etag, content_type, storage_state, created_at, user_metadata_json, system_metadata_json FROM objects o1 WHERE bucket = ? AND key LIKE ? || '%' ESCAPE '\\' AND key > ? AND {tb} = (SELECT MAX({tb}) FROM objects o2 WHERE o2.bucket = o1.bucket AND o2.key = o1.key) AND is_delete_marker = 0 ORDER BY key LIMIT ?");

    let rows = fetch_all(
        db,
        &sql,
        &[
            Val::text(bucket),
            Val::text(&esc),
            Val::text(start_after),
            Val::int(limit_plus_one),
        ],
    )
    .await
    .map_err(|e| format!("query: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        let key = r.get_string(0).map_err(|e| format!("rows: {e}"))?;
        out.push((
            key.clone(),
            ObjectVersion {
                version_id: r.get_string(1).map_err(|e| format!("rows: {e}"))?,
                key,
                is_delete_marker: r.get_bool(2).map_err(|e| format!("rows: {e}"))?,
                size: r.get_i64(3).map_err(|e| format!("rows: {e}"))?,
                etag: r.get_string(4).map_err(|e| format!("rows: {e}"))?,
                content_type: r.get_string(5).map_err(|e| format!("rows: {e}"))?,
                storage_state: r.get_string(6).map_err(|e| format!("rows: {e}"))?,
                created_at: r.get_string(7).map_err(|e| format!("rows: {e}"))?,
                user_metadata_json: r.get_opt_string(8).map_err(|e| format!("rows: {e}"))?,
                system_metadata_json: r.get_opt_string(9).map_err(|e| format!("rows: {e}"))?,
            },
        ));
    }
    Ok(out)
}

/// Lấy tất cả đường dẫn spool_path đang active (không NULL) trong bảng chunks và multipart_parts.
pub async fn active_spool_paths(
    db: &Db,
) -> Result<std::collections::HashSet<std::path::PathBuf>, String> {
    let sql = if schema_version(db).await.unwrap_or(0) >= 2 {
        "SELECT spool_path FROM chunks WHERE spool_path IS NOT NULL UNION SELECT spool_path FROM multipart_parts WHERE spool_path IS NOT NULL"
    } else {
        "SELECT spool_path FROM chunks WHERE spool_path IS NOT NULL"
    };
    let rows = fetch_all(db, sql, &[])
        .await
        .map_err(|e| format!("query active spool: {e}"))?;
    let mut set = std::collections::HashSet::new();
    for r in rows {
        let p = r
            .get_string(0)
            .map_err(|e| format!("query active spool: {e}"))?;
        let pb = std::path::PathBuf::from(p);
        set.insert(pb.clone());
        if let Ok(canon) = std::fs::canonicalize(&pb) {
            set.insert(canon);
        }
    }
    Ok(set)
}

// ==========================================
// M4: Access Keys, Policy, CORS, BPA & Object Lock DAL
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKeyRecord {
    pub access_key_id: String,
    pub secret_key: String,
    pub status: String,
    pub description: Option<String>,
    pub created_at: String,
}

pub async fn create_access_key(
    db: &Db,
    access_key_id: &str,
    secret_key: &str,
    description: Option<&str>,
) -> Result<(), String> {
    exec(
        db,
        "INSERT INTO access_keys(access_key_id, secret_key, status, description) VALUES (?, ?, 'Active', ?)
         ON CONFLICT(access_key_id) DO UPDATE SET secret_key=excluded.secret_key, status='Active', description=excluded.description",
        &[Val::text(access_key_id), Val::text(secret_key), Val::opt_text(description)],
    )
    .await
    .map_err(|e| format!("insert access_key: {e}"))?;
    Ok(())
}

pub async fn get_access_key(
    db: &Db,
    access_key_id: &str,
) -> Result<Option<AccessKeyRecord>, String> {
    let row = fetch_opt(
        db,
        "SELECT access_key_id, secret_key, status, description, created_at FROM access_keys WHERE access_key_id = ?",
        &[Val::text(access_key_id)],
    )
    .await
    .map_err(|e| format!("query get access_key: {e}"))?;
    match row {
        Some(r) => Ok(Some(AccessKeyRecord {
            access_key_id: r
                .get_string(0)
                .map_err(|e| format!("row access_key: {e}"))?,
            secret_key: r
                .get_string(1)
                .map_err(|e| format!("row access_key: {e}"))?,
            status: r
                .get_string(2)
                .map_err(|e| format!("row access_key: {e}"))?,
            description: r
                .get_opt_string(3)
                .map_err(|e| format!("row access_key: {e}"))?,
            created_at: r
                .get_string(4)
                .map_err(|e| format!("row access_key: {e}"))?,
        })),
        None => Ok(None),
    }
}

pub async fn list_access_keys(db: &Db) -> Result<Vec<AccessKeyRecord>, String> {
    let rows = fetch_all(
        db,
        "SELECT access_key_id, secret_key, status, description, created_at FROM access_keys ORDER BY created_at ASC",
        &[],
    )
    .await
    .map_err(|e| format!("query list access_keys: {e}"))?;
    let mut list = Vec::new();
    for r in rows {
        list.push(AccessKeyRecord {
            access_key_id: r
                .get_string(0)
                .map_err(|e| format!("row access_key: {e}"))?,
            secret_key: r
                .get_string(1)
                .map_err(|e| format!("row access_key: {e}"))?,
            status: r
                .get_string(2)
                .map_err(|e| format!("row access_key: {e}"))?,
            description: r
                .get_opt_string(3)
                .map_err(|e| format!("row access_key: {e}"))?,
            created_at: r
                .get_string(4)
                .map_err(|e| format!("row access_key: {e}"))?,
        });
    }
    Ok(list)
}

pub async fn delete_access_key(db: &Db, access_key_id: &str) -> Result<bool, String> {
    let affected = exec(
        db,
        "DELETE FROM access_keys WHERE access_key_id = ?",
        &[Val::text(access_key_id)],
    )
    .await
    .map_err(|e| format!("delete access_key: {e}"))?;
    Ok(affected > 0)
}

pub async fn update_access_key_status(
    db: &Db,
    access_key_id: &str,
    status: &str,
) -> Result<bool, String> {
    let canonical_status = if status.eq_ignore_ascii_case("active") {
        "Active"
    } else if status.eq_ignore_ascii_case("inactive") {
        "Inactive"
    } else {
        return Err("status must be Active or Inactive".to_string());
    };
    let affected = exec(
        db,
        "UPDATE access_keys SET status = ? WHERE access_key_id = ?",
        &[Val::text(canonical_status), Val::text(access_key_id)],
    )
    .await
    .map_err(|e| format!("update access_key status: {e}"))?;
    Ok(affected > 0)
}

pub async fn update_access_key_description(
    db: &Db,
    access_key_id: &str,
    description: &str,
) -> Result<bool, String> {
    let affected = exec(
        db,
        "UPDATE access_keys SET description = ? WHERE access_key_id = ?",
        &[Val::text(description), Val::text(access_key_id)],
    )
    .await
    .map_err(|e| format!("update access_key description: {e}"))?;
    Ok(affected > 0)
}

pub async fn update_access_key_allowed_buckets(
    db: &Db,
    access_key_id: &str,
    allowed_buckets: Option<&str>,
) -> Result<bool, String> {
    let affected = exec(
        db,
        "UPDATE access_keys SET allowed_buckets = ? WHERE access_key_id = ?",
        &[Val::opt_text(allowed_buckets), Val::text(access_key_id)],
    )
    .await
    .map_err(|e| format!("update access_key allowed_buckets: {e}"))?;
    Ok(affected > 0)
}

pub async fn touch_access_key_last_used(db: &Db, access_key_id: &str) -> Result<(), String> {
    let now = now_str();
    exec(
        db,
        "UPDATE access_keys SET last_used_at = ? WHERE access_key_id = ?",
        &[Val::text(&now), Val::text(access_key_id)],
    )
    .await
    .map_err(|e| format!("touch access_key last_used: {e}"))?;
    Ok(())
}

/// Per-bucket stats: object count + total size.
#[derive(Debug, Clone)]
pub struct BucketStats {
    pub name: String,
    pub object_count: i64,
    pub total_size_bytes: i64,
}

pub async fn bucket_stats(db: &Db) -> Result<Vec<BucketStats>, String> {
    // Postgres: SUM(bigint) trả về NUMERIC nên phải cast về BIGINT để decode i64.
    let sql = match db.backend() {
        DbBackend::Sqlite => "SELECT b.name, \
             COALESCE((SELECT COUNT(*) FROM objects o WHERE o.bucket = b.name AND o.is_delete_marker = 0), 0), \
             COALESCE((SELECT SUM(o.size) FROM objects o WHERE o.bucket = b.name AND o.is_delete_marker = 0), 0) \
             FROM buckets b ORDER BY b.name",
        DbBackend::Postgres => "SELECT b.name, \
             COALESCE((SELECT COUNT(*) FROM objects o WHERE o.bucket = b.name AND o.is_delete_marker = 0), 0), \
             COALESCE((SELECT SUM(o.size) FROM objects o WHERE o.bucket = b.name AND o.is_delete_marker = 0)::BIGINT, 0) \
             FROM buckets b ORDER BY b.name",
    };
    let rows = fetch_all(db, sql, &[])
        .await
        .map_err(|e| format!("query bucket_stats: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(BucketStats {
            name: r
                .get_string(0)
                .map_err(|e| format!("rows bucket_stats: {e}"))?,
            object_count: r
                .get_i64(1)
                .map_err(|e| format!("rows bucket_stats: {e}"))?,
            total_size_bytes: r
                .get_i64(2)
                .map_err(|e| format!("rows bucket_stats: {e}"))?,
        });
    }
    Ok(out)
}

/// Upload job record for dashboard jobs viewer.
#[derive(Debug, Clone)]
pub struct JobRecord {
    pub job_id: String,
    pub version_id: String,
    pub bucket: String,
    pub key: String,
    pub state: String,
    pub retry_count: i64,
    pub next_attempt: String,
    pub lease_owner: Option<String>,
    pub lease_expires: Option<String>,
    pub last_error: Option<String>,
    pub generation: i64,
}

/// Job summary counts.
#[derive(Debug, Clone)]
pub struct JobSummary {
    pub pending: i64,
    pub uploading: i64,
    pub completed: i64,
    pub failed: i64,
}

pub async fn list_jobs(db: &Db) -> Result<(Vec<JobRecord>, JobSummary), String> {
    let rows = fetch_all(
        db,
        "SELECT j.job_id, j.version_id, o.bucket, o.key, j.state, j.retry_count, \
             j.next_attempt, j.lease_owner, j.lease_expires, j.last_error, j.generation \
             FROM upload_jobs j LEFT JOIN objects o ON j.version_id = o.version_id \
             ORDER BY j.next_attempt DESC LIMIT 200",
        &[],
    )
    .await
    .map_err(|e| format!("query list_jobs: {e}"))?;
    let mut jobs = Vec::new();
    for r in rows {
        jobs.push(JobRecord {
            job_id: r
                .get_string(0)
                .map_err(|e| format!("rows list_jobs: {e}"))?,
            version_id: r
                .get_string(1)
                .map_err(|e| format!("rows list_jobs: {e}"))?,
            bucket: r
                .get_opt_string(2)
                .map_err(|e| format!("rows list_jobs: {e}"))?
                .unwrap_or_default(),
            key: r
                .get_opt_string(3)
                .map_err(|e| format!("rows list_jobs: {e}"))?
                .unwrap_or_default(),
            state: r
                .get_string(4)
                .map_err(|e| format!("rows list_jobs: {e}"))?,
            retry_count: r.get_i64(5).map_err(|e| format!("rows list_jobs: {e}"))?,
            next_attempt: r
                .get_string(6)
                .map_err(|e| format!("rows list_jobs: {e}"))?,
            lease_owner: r
                .get_opt_string(7)
                .map_err(|e| format!("rows list_jobs: {e}"))?,
            lease_expires: r
                .get_opt_string(8)
                .map_err(|e| format!("rows list_jobs: {e}"))?,
            last_error: r
                .get_opt_string(9)
                .map_err(|e| format!("rows list_jobs: {e}"))?,
            generation: r.get_i64(10).map_err(|e| format!("rows list_jobs: {e}"))?,
        });
    }

    let summary = job_summary(db).await?;
    Ok((jobs, summary))
}

pub async fn job_summary(db: &Db) -> Result<JobSummary, String> {
    async fn count(db: &Db, state: &str) -> Result<i64, String> {
        match fetch_opt(
            db,
            "SELECT COUNT(*) FROM upload_jobs WHERE state = ?",
            &[Val::text(state)],
        )
        .await
        {
            Ok(Some(r)) => r.get_i64(0),
            Ok(None) => Ok(0),
            Err(e) => Err(format!("count jobs {state}: {e}")),
        }
    }
    Ok(JobSummary {
        pending: count(db, "pending").await?,
        uploading: count(db, "uploading").await?,
        completed: count(db, "completed").await.unwrap_or(0),
        failed: count(db, "failed").await.unwrap_or(0),
    })
}

// Bucket Policy
pub async fn set_bucket_policy(db: &Db, bucket: &str, policy_json: &str) -> Result<(), String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let now = now_str();
    exec(
        db,
        "INSERT INTO bucket_policies(bucket, policy_json) VALUES (?, ?)
         ON CONFLICT(bucket) DO UPDATE SET policy_json=excluded.policy_json, updated_at=?",
        &[Val::text(bucket), Val::text(policy_json), Val::text(&now)],
    )
    .await
    .map_err(|e| format!("set bucket policy: {e}"))?;
    Ok(())
}

pub async fn get_bucket_policy(db: &Db, bucket: &str) -> Result<Option<String>, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let row = fetch_opt(
        db,
        "SELECT policy_json FROM bucket_policies WHERE bucket = ?",
        &[Val::text(bucket)],
    )
    .await
    .map_err(|e| format!("query get bucket policy: {e}"))?;
    match row {
        Some(r) => Ok(Some(
            r.get_string(0)
                .map_err(|e| format!("row bucket policy: {e}"))?,
        )),
        None => Ok(None),
    }
}

pub async fn delete_bucket_policy(db: &Db, bucket: &str) -> Result<bool, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let affected = exec(
        db,
        "DELETE FROM bucket_policies WHERE bucket = ?",
        &[Val::text(bucket)],
    )
    .await
    .map_err(|e| format!("delete bucket policy: {e}"))?;
    Ok(affected > 0)
}

// Bucket CORS
pub async fn set_bucket_cors(db: &Db, bucket: &str, cors_json: &str) -> Result<(), String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let now = now_str();
    exec(
        db,
        "INSERT INTO bucket_cors(bucket, cors_json) VALUES (?, ?)
         ON CONFLICT(bucket) DO UPDATE SET cors_json=excluded.cors_json, updated_at=?",
        &[Val::text(bucket), Val::text(cors_json), Val::text(&now)],
    )
    .await
    .map_err(|e| format!("set bucket cors: {e}"))?;
    Ok(())
}

pub async fn get_bucket_cors(db: &Db, bucket: &str) -> Result<Option<String>, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let row = fetch_opt(
        db,
        "SELECT cors_json FROM bucket_cors WHERE bucket = ?",
        &[Val::text(bucket)],
    )
    .await
    .map_err(|e| format!("query get bucket cors: {e}"))?;
    match row {
        Some(r) => Ok(Some(
            r.get_string(0)
                .map_err(|e| format!("row bucket cors: {e}"))?,
        )),
        None => Ok(None),
    }
}

pub async fn delete_bucket_cors(db: &Db, bucket: &str) -> Result<bool, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let affected = exec(
        db,
        "DELETE FROM bucket_cors WHERE bucket = ?",
        &[Val::text(bucket)],
    )
    .await
    .map_err(|e| format!("delete bucket cors: {e}"))?;
    Ok(affected > 0)
}

// Block Public Access (BPA)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename = "PublicAccessBlockConfiguration", rename_all = "PascalCase")]
pub struct BucketBpa {
    #[serde(rename = "BlockPublicAcls", default)]
    pub block_public_acls: bool,
    #[serde(rename = "IgnorePublicAcls", default)]
    pub ignore_public_acls: bool,
    #[serde(rename = "BlockPublicPolicy", default)]
    pub block_public_policy: bool,
    #[serde(rename = "RestrictPublicBuckets", default)]
    pub restrict_public_buckets: bool,
}

pub async fn set_bucket_bpa(db: &Db, bucket: &str, bpa: &BucketBpa) -> Result<(), String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let now = now_str();
    exec(
        db,
        "INSERT INTO bucket_bpa(bucket, block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(bucket) DO UPDATE SET
            block_public_acls=excluded.block_public_acls,
            ignore_public_acls=excluded.ignore_public_acls,
            block_public_policy=excluded.block_public_policy,
            restrict_public_buckets=excluded.restrict_public_buckets,
            updated_at=?",
        &[
            Val::text(bucket),
            Val::int(bpa.block_public_acls as i64),
            Val::int(bpa.ignore_public_acls as i64),
            Val::int(bpa.block_public_policy as i64),
            Val::int(bpa.restrict_public_buckets as i64),
            Val::text(&now),
        ],
    )
    .await
    .map_err(|e| format!("set bucket bpa: {e}"))?;
    Ok(())
}

pub async fn get_bucket_bpa(db: &Db, bucket: &str) -> Result<BucketBpa, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let row = fetch_opt(
        db,
        "SELECT block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets FROM bucket_bpa WHERE bucket = ?",
        &[Val::text(bucket)],
    )
    .await
    .map_err(|e| format!("query get bucket bpa: {e}"))?;
    match row {
        Some(r) => Ok(BucketBpa {
            block_public_acls: r.get_bool(0).map_err(|e| format!("row bucket bpa: {e}"))?,
            ignore_public_acls: r.get_bool(1).map_err(|e| format!("row bucket bpa: {e}"))?,
            block_public_policy: r.get_bool(2).map_err(|e| format!("row bucket bpa: {e}"))?,
            restrict_public_buckets: r.get_bool(3).map_err(|e| format!("row bucket bpa: {e}"))?,
        }),
        None => Ok(BucketBpa::default()),
    }
}

pub async fn delete_bucket_bpa(db: &Db, bucket: &str) -> Result<bool, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let affected = exec(
        db,
        "DELETE FROM bucket_bpa WHERE bucket = ?",
        &[Val::text(bucket)],
    )
    .await
    .map_err(|e| format!("delete bucket bpa: {e}"))?;
    Ok(affected > 0)
}

// Object Lock Config
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ObjectLockConfig {
    pub status: String,
    pub default_retention_mode: Option<String>,
    pub default_retention_days: Option<i32>,
}

pub async fn set_bucket_object_lock_config(
    db: &Db,
    bucket: &str,
    cfg: &ObjectLockConfig,
) -> Result<(), String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let now = now_str();
    exec(
        db,
        "INSERT INTO bucket_lock_configs(bucket, status, default_retention_mode, default_retention_days)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(bucket) DO UPDATE SET
            status=excluded.status,
            default_retention_mode=excluded.default_retention_mode,
            default_retention_days=excluded.default_retention_days,
            updated_at=?",
        &[
            Val::text(bucket),
            Val::text(&cfg.status),
            Val::opt_text(cfg.default_retention_mode.as_deref()),
            cfg.default_retention_days.map(|d| Val::int(d as i64)).unwrap_or(Val::Null),
            Val::text(&now),
        ],
    )
    .await
    .map_err(|e| format!("set bucket object lock config: {e}"))?;
    Ok(())
}

pub async fn get_bucket_object_lock_config(
    db: &Db,
    bucket: &str,
) -> Result<Option<ObjectLockConfig>, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let row = fetch_opt(
        db,
        "SELECT status, default_retention_mode, default_retention_days FROM bucket_lock_configs WHERE bucket = ?",
        &[Val::text(bucket)],
    )
    .await
    .map_err(|e| format!("query get bucket lock config: {e}"))?;
    match row {
        Some(r) => Ok(Some(ObjectLockConfig {
            status: r
                .get_string(0)
                .map_err(|e| format!("row bucket lock config: {e}"))?,
            default_retention_mode: r
                .get_opt_string(1)
                .map_err(|e| format!("row bucket lock config: {e}"))?,
            // Cột BIGINT nhưng struct giữ i32 như cũ.
            default_retention_days: r
                .get_opt_i32(2)
                .map_err(|e| format!("row bucket lock config: {e}"))?,
        })),
        None => Ok(None),
    }
}

// Object Retention & Legal Hold
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRetention {
    pub mode: String,
    pub retain_until_date: String,
}

pub async fn set_object_retention(
    db: &Db,
    bucket: &str,
    key: &str,
    version_id: &str,
    mode: &str,
    retain_until_date: &str,
) -> Result<(), String> {
    let now = now_str();
    exec(
        db,
        "INSERT INTO object_locks(bucket, key, version_id, retain_until_date, mode, legal_hold)
         VALUES (?, ?, ?, ?, ?, 0)
         ON CONFLICT(bucket, key, version_id) DO UPDATE SET
            retain_until_date=excluded.retain_until_date,
            mode=excluded.mode,
            updated_at=?",
        &[
            Val::text(bucket),
            Val::text(key),
            Val::text(version_id),
            Val::text(retain_until_date),
            Val::text(mode),
            Val::text(&now),
        ],
    )
    .await
    .map_err(|e| format!("set object retention: {e}"))?;
    Ok(())
}

pub async fn get_object_retention(
    db: &Db,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<Option<ObjectRetention>, String> {
    let row = fetch_opt(
        db,
        "SELECT mode, retain_until_date FROM object_locks WHERE bucket = ? AND key = ? AND version_id = ? AND mode IS NOT NULL",
        &[Val::text(bucket), Val::text(key), Val::text(version_id)],
    )
    .await
    .map_err(|e| format!("query get object retention: {e}"))?;
    match row {
        Some(r) => {
            let m = r
                .get_opt_string(0)
                .map_err(|e| format!("row retention: {e}"))?;
            let d = r
                .get_opt_string(1)
                .map_err(|e| format!("row retention: {e}"))?;
            match (m, d) {
                (Some(mode), Some(retain_until_date)) => Ok(Some(ObjectRetention {
                    mode,
                    retain_until_date,
                })),
                _ => Ok(None),
            }
        }
        None => Ok(None),
    }
}

pub async fn set_object_legal_hold(
    db: &Db,
    bucket: &str,
    key: &str,
    version_id: &str,
    on: bool,
) -> Result<(), String> {
    let now = now_str();
    exec(
        db,
        "INSERT INTO object_locks(bucket, key, version_id, retain_until_date, mode, legal_hold)
         VALUES (?, ?, ?, NULL, NULL, ?)
         ON CONFLICT(bucket, key, version_id) DO UPDATE SET
            legal_hold=excluded.legal_hold,
            updated_at=?",
        &[
            Val::text(bucket),
            Val::text(key),
            Val::text(version_id),
            Val::int(on as i64),
            Val::text(&now),
        ],
    )
    .await
    .map_err(|e| format!("set object legal hold: {e}"))?;
    Ok(())
}

pub async fn get_object_legal_hold(
    db: &Db,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<bool, String> {
    let row = fetch_opt(
        db,
        "SELECT legal_hold FROM object_locks WHERE bucket = ? AND key = ? AND version_id = ?",
        &[Val::text(bucket), Val::text(key), Val::text(version_id)],
    )
    .await
    .map_err(|e| format!("query get object legal hold: {e}"))?;
    match row {
        Some(r) => r.get_bool(0).map_err(|e| format!("row legal hold: {e}")),
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_sqlite(dir.path().join("index.db").to_str().unwrap())
            .await
            .unwrap();
        apply_all_migrations(&db).await.unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn migrations_apply_from_zero_to_head() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("index.db");
        let db = Db::open_sqlite(db_path.to_str().unwrap()).await.unwrap();
        assert_eq!(schema_version(&db).await.unwrap(), 0);
        apply_migration(&db, 1, MIGRATION_001).await.unwrap();
        assert_eq!(schema_version(&db).await.unwrap(), 1);
        apply_migration(&db, 2, MIGRATION_002).await.unwrap();
        assert_eq!(schema_version(&db).await.unwrap(), 2);
        apply_migration(&db, 3, MIGRATION_003).await.unwrap();
        assert_eq!(schema_version(&db).await.unwrap(), 3);
        apply_migration(&db, 4, MIGRATION_004).await.unwrap();
        assert_eq!(schema_version(&db).await.unwrap(), 4);
    }

    #[test]
    fn backend_parse_and_guard() {
        assert_eq!(DbBackend::parse("sqlite").unwrap(), DbBackend::Sqlite);
        assert_eq!(DbBackend::parse("postgres").unwrap(), DbBackend::Postgres);
        assert!(DbBackend::parse("mysql").is_err());
        assert!(ensure_backend_supported(DbBackend::Sqlite).is_ok());
        // Postgres giờ runnable — guard phải trả Ok.
        assert!(ensure_backend_supported(DbBackend::Postgres).is_ok());
    }

    #[test]
    fn postgres_schema_covers_all_sqlite_tables_without_sqlite_dialect() {
        let ddl = POSTGRES_SCHEMA;
        for table in [
            "schema_version",
            "buckets",
            "objects",
            "chunks",
            "upload_jobs",
            "recovery_checkpoints",
            "kv",
            "multipart_uploads",
            "multipart_parts",
            "access_keys",
            "bucket_policies",
            "bucket_cors",
            "bucket_bpa",
            "bucket_lock_configs",
            "object_locks",
        ] {
            assert!(
                ddl.contains(&format!("CREATE TABLE IF NOT EXISTS {table}(")),
                "missing table {table}"
            );
        }
        // Không lẫn dialect SQLite.
        for sqliteism in ["AUTOINCREMENT", "datetime(", "PRAGMA", "VACUUM"] {
            assert!(
                !ddl.contains(sqliteism),
                "postgres DDL must not contain {sqliteism}"
            );
        }
        // Cột bổ sung từ migration 0002/0004 phải có mặt.
        for col in [
            "user_metadata_json",
            "system_metadata_json",
            "last_used_at",
            "allowed_buckets",
        ] {
            assert!(ddl.contains(col), "missing column {col}");
        }
    }

    #[tokio::test]
    async fn test_m4_dal_crud() {
        let (_dir, db) = test_db().await;
        create_bucket(&db, "m4-bkt", "telecrate-1").await.unwrap();

        // Access Keys CRUD
        create_access_key(&db, "AKIA123", "secret123", Some("test key"))
            .await
            .unwrap();
        let key = get_access_key(&db, "AKIA123").await.unwrap().unwrap();
        assert_eq!(key.access_key_id, "AKIA123");
        assert_eq!(key.secret_key, "secret123");
        assert_eq!(key.status, "Active");
        let keys = list_access_keys(&db).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert!(delete_access_key(&db, "AKIA123").await.unwrap());
        assert!(get_access_key(&db, "AKIA123").await.unwrap().is_none());

        // Bucket Policy CRUD
        set_bucket_policy(&db, "m4-bkt", "{\"Version\":\"2012-10-17\"}")
            .await
            .unwrap();
        assert_eq!(
            get_bucket_policy(&db, "m4-bkt").await.unwrap().unwrap(),
            "{\"Version\":\"2012-10-17\"}"
        );
        assert!(delete_bucket_policy(&db, "m4-bkt").await.unwrap());
        assert!(get_bucket_policy(&db, "m4-bkt").await.unwrap().is_none());

        // Bucket CORS CRUD
        set_bucket_cors(&db, "m4-bkt", "{\"CORSRules\":[]}")
            .await
            .unwrap();
        assert_eq!(
            get_bucket_cors(&db, "m4-bkt").await.unwrap().unwrap(),
            "{\"CORSRules\":[]}"
        );
        assert!(delete_bucket_cors(&db, "m4-bkt").await.unwrap());
        assert!(get_bucket_cors(&db, "m4-bkt").await.unwrap().is_none());

        // BPA CRUD
        let bpa = BucketBpa {
            block_public_acls: true,
            ignore_public_acls: true,
            block_public_policy: true,
            restrict_public_buckets: true,
        };
        set_bucket_bpa(&db, "m4-bkt", &bpa).await.unwrap();
        assert_eq!(get_bucket_bpa(&db, "m4-bkt").await.unwrap(), bpa);
        assert!(delete_bucket_bpa(&db, "m4-bkt").await.unwrap());

        // Object Lock Config CRUD
        let cfg = ObjectLockConfig {
            status: "Enabled".to_string(),
            default_retention_mode: Some("GOVERNANCE".to_string()),
            default_retention_days: Some(30),
        };
        set_bucket_object_lock_config(&db, "m4-bkt", &cfg)
            .await
            .unwrap();
        assert_eq!(
            get_bucket_object_lock_config(&db, "m4-bkt")
                .await
                .unwrap()
                .unwrap(),
            cfg
        );
    }

    #[tokio::test]
    async fn multipart_uploads_crud() {
        let (_d, db) = test_db().await;
        create_bucket(&db, "mybucket", "us-east-1").await.unwrap();

        // Create
        create_multipart_upload(
            &db,
            "upload-123",
            "mybucket",
            "photo.jpg",
            "image/jpeg",
            Some(r#"{"x-amz-meta-author":"alice"}"#),
        )
        .await
        .unwrap();

        // Get
        let upload = get_multipart_upload(&db, "upload-123")
            .await
            .unwrap()
            .unwrap();
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
            &db,
            "upload-123",
            1,
            1024,
            "etag1",
            "sha1",
            "sha1",
            Some("spool/p1"),
        )
        .await
        .unwrap();
        save_multipart_part(
            &db,
            "upload-123",
            2,
            2048,
            "etag2",
            "sha2",
            "sha2",
            Some("spool/p2"),
        )
        .await
        .unwrap();

        // List parts
        let parts = list_multipart_parts(&db, "upload-123").await.unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].part_number, 1);
        assert_eq!(parts[0].size, 1024);
        assert_eq!(parts[1].part_number, 2);
        assert_eq!(parts[1].size, 2048);

        // List uploads for bucket
        let uploads = list_multipart_uploads(&db, "mybucket").await.unwrap();
        assert_eq!(uploads.len(), 1);

        // Active spool paths contains multipart parts
        let active = active_spool_paths(&db).await.unwrap();
        assert!(active.contains(std::path::Path::new("spool/p1")));

        // Abort
        let spools = abort_multipart_upload(&db, "upload-123").await.unwrap();
        assert_eq!(spools, vec!["spool/p1".to_string(), "spool/p2".to_string()]);
        assert!(get_multipart_upload(&db, "upload-123")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn pragmas_wal_fk_busy_timeout() {
        let (_d, db) = test_db().await;
        // WAL mode kiểm tra qua sqlx query.
        let row = fetch_opt(&db, "PRAGMA journal_mode", &[])
            .await
            .unwrap()
            .unwrap();
        let journal = row.get_string(0).unwrap();
        assert_eq!(journal.to_lowercase(), "wal");
    }

    #[tokio::test]
    async fn bucket_crud_and_naming() {
        let (_d, db) = test_db().await;
        assert!(!valid_bucket_name("AB"));
        assert!(!valid_bucket_name("Abc"));
        assert!(!valid_bucket_name("-abc"));
        assert!(valid_bucket_name("my-bucket.1"));
        assert_eq!(
            create_bucket(&db, "my-bucket", "telecrate-1")
                .await
                .unwrap(),
            CreateBucketOutcome::Created
        );
        assert_eq!(
            create_bucket(&db, "my-bucket", "telecrate-1")
                .await
                .unwrap(),
            CreateBucketOutcome::AlreadyOwned
        );
        assert!(head_bucket(&db, "my-bucket").await.unwrap());
        assert!(!head_bucket(&db, "nope").await.unwrap());
        assert!(create_bucket(&db, "Bad_Name", "r").await.is_err());
        let list = list_buckets(&db).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].region, "telecrate-1");
    }

    #[tokio::test]
    async fn delete_bucket_denies_nonempty_and_missing() {
        let (_d, db) = test_db().await;
        assert_eq!(
            delete_bucket(&db, "ghost").await.unwrap(),
            DeleteBucketOutcome::NoSuchBucket
        );
        create_bucket(&db, "bucket-1", "r").await.unwrap();
        assert_eq!(
            delete_bucket(&db, "bucket-1").await.unwrap(),
            DeleteBucketOutcome::Deleted
        );
        // Bucket có object → 409 NotEmpty.
        create_bucket(&db, "bucket-2", "r").await.unwrap();
        exec(
            &db,
            "INSERT INTO objects(bucket, key, version_id) VALUES (?, ?, ?)",
            &[Val::text("bucket-2"), Val::text("k"), Val::text("v1")],
        )
        .await
        .unwrap();
        assert_eq!(
            delete_bucket(&db, "bucket-2").await.unwrap(),
            DeleteBucketOutcome::NotEmpty
        );
    }

    #[tokio::test]
    async fn object_put_get_delete_and_list() {
        let (_d, db) = test_db().await;
        create_bucket(&db, "bkt", "r").await.unwrap();
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
            &db,
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
        .await
        .unwrap();
        assert!(old.is_empty());
        put_object(
            &db,
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
        .await
        .unwrap();
        // PUT đè: thu spool cũ + version mới thấy ngay.
        let (old, _) = put_object(
            &db,
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
        .await
        .unwrap();
        assert_eq!(old, vec!["/spool/x1".to_string()]);

        let v = latest_version(&db, "bkt", "a/b").await.unwrap().unwrap();
        assert_eq!(v.version_id, "v3");
        assert_eq!(v.etag, "etag3");
        assert!(latest_version(&db, "bkt", "ghost").await.unwrap().is_none());
        // PUT multi-chunk: chunks giữ đúng thứ tự offset.
        put_object(
            &db,
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
        .await
        .unwrap();
        let chunks = chunks_of(&db, "vm").await.unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[2].length, 10);
        assert_eq!(chunks[1].spool_path.as_deref(), Some("/s/m1"));
        assert_eq!(chunks[0].encryption_mode, crate::crypto::MODE_AEAD_V1);
        assert_eq!(chunks[0].key_ref.as_deref(), Some("k1"));
        // LIST prefix + LIKE escape.
        let keys = list_keys(&db, "bkt", "a/", "", 10).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "a/b");
        let keys = list_keys(&db, "bkt", "a%", "", 10).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "a%b_c");
        // Pagination (thứ tự byte: "a%b_c" < "a/b" < "multi").
        let keys = list_keys(&db, "bkt", "", "", 2).await.unwrap();
        assert_eq!(keys.len(), 2);
        let keys = list_keys(&db, "bkt", "", "a%b_c", 10).await.unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].0, "a/b");
        assert_eq!(keys[1].0, "multi");
        // DELETE trả spool + existed; xóa lại → !existed.
        let r = delete_object(&db, "bkt", "a/b").await.unwrap();
        assert!(r.existed);
        assert_eq!(r.spool_paths, vec!["/spool/x3".to_string()]);
        assert!(!delete_object(&db, "bkt", "a/b").await.unwrap().existed);
        // Bucket còn object → vẫn NotEmpty; xóa hết → Deleted.
        assert_eq!(
            delete_bucket(&db, "bkt").await.unwrap(),
            DeleteBucketOutcome::NotEmpty
        );
        delete_object(&db, "bkt", "a%b_c").await.unwrap();
        delete_object(&db, "bkt", "multi").await.unwrap();
        assert_eq!(
            delete_bucket(&db, "bkt").await.unwrap(),
            DeleteBucketOutcome::Deleted
        );
    }

    #[tokio::test]
    async fn test_db_backup_and_restore() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("source.db");
        let plain_backup = temp_dir.path().join("plain_backup.db");
        let enc_backup = temp_dir.path().join("enc_backup.db");
        let restored_db = temp_dir.path().join("restored.db");

        let db = Db::open_sqlite(db_path.to_str().unwrap()).await.unwrap();
        apply_all_migrations(&db).await.unwrap();
        create_bucket(&db, "backup-bkt", "us-east-1").await.unwrap();

        // 1. Plain backup
        backup_db(&db, plain_backup.to_str().unwrap())
            .await
            .unwrap();
        assert!(plain_backup.exists());

        // Restore plain backup to restored_db
        restore_db(
            plain_backup.to_str().unwrap(),
            restored_db.to_str().unwrap(),
            None,
        )
        .await
        .unwrap();
        let restored_conn = Db::open_sqlite(restored_db.to_str().unwrap())
            .await
            .unwrap();
        assert!(head_bucket(&restored_conn, "backup-bkt").await.unwrap());
        drop(restored_conn);

        // 2. Encrypted backup
        backup_db_encrypted(&db, enc_backup.to_str().unwrap(), "my-secret-passphrase")
            .await
            .unwrap();
        assert!(enc_backup.exists());

        // Restore with wrong passphrase -> fails
        let res = restore_db(
            enc_backup.to_str().unwrap(),
            restored_db.to_str().unwrap(),
            Some("wrong-pass"),
        )
        .await;
        assert!(res.is_err());

        // Restore with correct passphrase -> succeeds
        restore_db(
            enc_backup.to_str().unwrap(),
            restored_db.to_str().unwrap(),
            Some("my-secret-passphrase"),
        )
        .await
        .unwrap();
        let _restored_conn2 = Db::open_sqlite(restored_db.to_str().unwrap())
            .await
            .unwrap();
    }
}

//! DB layer — dual backend SQLite/Postgres trên SeaORM + SeaQuery, migrations
//! forward-only (ADR 0006).
//!
//! Mọi query nghiệp vụ qua entities (`src/db/entities/` — single source of truth
//! cho cấu trúc bảng, test parity với DDL cả hai backend). Chỉ còn SQL text cho:
//! intrinsic backend (`rowid`/`ctid`, PRAGMA, `VACUUM INTO`, `datetime('now')`),
//! aggregate tương quan (bucket_stats, SUM) và DDL migrator.
//! Datetime lưu TEXT `YYYY-MM-DD HH:MM:SS` UTC trên cả hai backend nên so sánh
//! chuỗi tương đương so sánh thời gian. Số nguyên đọc i64 trên cả hai
//! (DDL Postgres dùng BIGINT toàn bộ). Không giữ txn mở suốt network upload.

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, JoinType, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, RelationTrait, Set, Statement, TransactionTrait, Value,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Pool, Postgres, Sqlite};
use std::path::Path;

pub mod entities;

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

    /// Kết nối SeaORM bọc cùng pool (ADR 0006). Rẻ (clone Arc + wrap) — mọi
    /// query DAL chạy qua kết nối này; pool sqlx gốc chỉ còn mở lúc khởi tạo.
    pub fn sea_conn(&self) -> sea_orm::DatabaseConnection {
        match self {
            Db::Sqlite(p) => sea_orm::SqlxSqliteConnector::from_sqlx_sqlite_pool(p.clone()),
            Db::Postgres(p) => sea_orm::SqlxPostgresConnector::from_sqlx_postgres_pool(p.clone()),
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
/// Query DAL hợp nhất qua SeaORM entities + SeaQuery (ADR 0006).
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
pub const MIGRATION_001: &str = include_str!("../../migrations/0001_init.sql");
pub const MIGRATION_002: &str = include_str!("../../migrations/0002_m3_multipart_versioning.sql");
pub const MIGRATION_003: &str = include_str!("../../migrations/0003_m4_auth_policy_cors_lock.sql");
pub const MIGRATION_004: &str = include_str!("../../migrations/0004_dashboard_enhancements.sql");
pub const MIGRATION_005: &str = include_str!("../../migrations/0005_gc_cleanup.sql");

/// DDL Postgres versioned, song song migrations SQLite 0001→0004
/// (cùng quy ước file SQL forward-only). Runtime apply theo version.
pub const PG_MIGRATION_001: &str = include_str!("../../migrations/postgres/0001_init.sql");
pub const PG_MIGRATION_002: &str =
    include_str!("../../migrations/postgres/0002_m3_multipart_versioning.sql");
pub const PG_MIGRATION_003: &str =
    include_str!("../../migrations/postgres/0003_m4_auth_policy_cors_lock.sql");
pub const PG_MIGRATION_004: &str =
    include_str!("../../migrations/postgres/0004_dashboard_enhancements.sql");
pub const PG_MIGRATION_005: &str = include_str!("../../migrations/postgres/0005_gc_cleanup.sql");

/// DDL Postgres đầy đủ cho DBA tạo schema trước (`telecrate db pg-schema`).
pub const POSTGRES_SCHEMA: &str = concat!(
    include_str!("../../migrations/postgres/0001_init.sql"),
    include_str!("../../migrations/postgres/0002_m3_multipart_versioning.sql"),
    include_str!("../../migrations/postgres/0003_m4_auth_policy_cors_lock.sql"),
    include_str!("../../migrations/postgres/0004_dashboard_enhancements.sql"),
    include_str!("../../migrations/postgres/0005_gc_cleanup.sql"),
);

/// Lấy version migration hiện tại (0 nếu chưa có bảng).
pub async fn schema_version(db: &Db) -> Result<i64, String> {
    match entities::schema_version::Entity::find()
        .all(&db.sea_conn())
        .await
    {
        Ok(rows) => Ok(rows.into_iter().map(|m| m.version).max().unwrap_or(0)),
        Err(e) => {
            let s = e.to_string();
            if is_missing_table(&s) {
                Ok(0)
            } else {
                Err(s)
            }
        }
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
/// DDL chạy qua `execute_unprepared` (không params) trên sea_conn.
pub async fn apply_migration(db: &Db, version: i64, sql: &str) -> Result<(), String> {
    let conn = db.sea_conn();
    let txn = conn.begin().await.map_err(|e| format!("begin txn: {e}"))?;
    for stmt in split_statements(sql) {
        txn.execute_unprepared(&stmt)
            .await
            .map_err(|e| format!("migration {version}: {e}"))?;
    }
    entities::schema_version::ActiveModel {
        version: Set(version),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| format!("record version: {e}"))?;
    txn.commit().await.map_err(|e| format!("commit: {e}"))?;
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
            (5, MIGRATION_005),
        ],
        DbBackend::Postgres => &[
            (1, PG_MIGRATION_001),
            (2, PG_MIGRATION_002),
            (3, PG_MIGRATION_003),
            (4, PG_MIGRATION_004),
            (5, PG_MIGRATION_005),
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
            db.sea_conn()
                .execute_unprepared(&format!("VACUUM INTO '{escaped}'"))
                .await
                .map(|_| ())
                .map_err(|e| format!("exec: {e}"))?;
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
    let integrity = sqlite_integrity_check(&restored).await.unwrap_or_default();
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
    let conn = db.sea_conn();
    entities::multipart_uploads::ActiveModel {
        upload_id: Set(upload_id.to_string()),
        bucket: Set(bucket.to_string()),
        key: Set(key.to_string()),
        content_type: Set(content_type.to_string()),
        metadata_json: Set(metadata_json.map(|s| s.to_string())),
        ..Default::default()
    }
    .insert(&conn)
    .await
    .map_err(|e| format!("insert multipart_upload: {e}"))?;
    Ok(())
}

/// Lấy thông tin Multipart Upload theo upload_id.
pub async fn get_multipart_upload(
    db: &Db,
    upload_id: &str,
) -> Result<Option<MultipartUpload>, String> {
    let conn = db.sea_conn();
    entities::multipart_uploads::Entity::find_by_id(upload_id)
        .one(&conn)
        .await
        .map_err(|e| format!("query get multipart_upload: {e}"))
        .map(|m| {
            m.map(|m| MultipartUpload {
                upload_id: m.upload_id,
                bucket: m.bucket,
                key: m.key,
                content_type: m.content_type,
                metadata_json: m.metadata_json,
                created_at: m.created_at,
            })
        })
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
    let conn = db.sea_conn();
    entities::multipart_parts::Entity::insert(entities::multipart_parts::ActiveModel {
        upload_id: Set(upload_id.to_string()),
        part_number: Set(part_number as i64),
        size: Set(size),
        etag: Set(etag.to_string()),
        plaintext_sha256: Set(plaintext_sha256.to_string()),
        ciphertext_sha256: Set(ciphertext_sha256.to_string()),
        spool_path: Set(spool_path.map(|s| s.to_string())),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::columns([
            entities::multipart_parts::Column::UploadId,
            entities::multipart_parts::Column::PartNumber,
        ])
        .update_columns([
            entities::multipart_parts::Column::Size,
            entities::multipart_parts::Column::Etag,
            entities::multipart_parts::Column::PlaintextSha256,
            entities::multipart_parts::Column::CiphertextSha256,
            entities::multipart_parts::Column::SpoolPath,
        ])
        .to_owned(),
    )
    .exec(&conn)
    .await
    .map_err(|e| format!("insert/update multipart_part: {e}"))?;
    Ok(())
}

/// Liệt kê các Part đã upload theo thứ tự part_number tăng dần.
pub async fn list_multipart_parts(db: &Db, upload_id: &str) -> Result<Vec<MultipartPart>, String> {
    use entities::multipart_parts::Column as P;
    let conn = db.sea_conn();
    let rows = entities::multipart_parts::Entity::find()
        .filter(P::UploadId.eq(upload_id))
        .order_by_asc(P::PartNumber)
        .all(&conn)
        .await
        .map_err(|e| format!("query list multipart_parts: {e}"))?;
    let mut parts = Vec::new();
    for m in rows {
        parts.push(MultipartPart {
            upload_id: m.upload_id,
            // Cột BIGINT nhưng struct giữ i32 như cũ.
            part_number: i32::try_from(m.part_number)
                .map_err(|_| "row multipart_part: part_number out of i32 range".to_string())?,
            size: m.size,
            etag: m.etag,
            plaintext_sha256: m.plaintext_sha256,
            ciphertext_sha256: m.ciphertext_sha256,
            spool_path: m.spool_path,
            created_at: m.created_at,
        });
    }
    Ok(parts)
}

/// Hủy Multipart Upload: xóa record DB và trả về danh sách spool_path để dọn đĩa.
pub async fn abort_multipart_upload(db: &Db, upload_id: &str) -> Result<Vec<String>, String> {
    let parts = list_multipart_parts(db, upload_id).await?;
    let spool_paths: Vec<String> = parts.into_iter().filter_map(|p| p.spool_path).collect();

    let sea = db.sea_conn();
    let txn = sea.begin().await.map_err(|e| format!("begin txn: {e}"))?;
    entities::multipart_parts::Entity::delete_many()
        .filter(entities::multipart_parts::Column::UploadId.eq(upload_id))
        .exec(&txn)
        .await
        .map_err(|e| format!("delete parts: {e}"))?;
    entities::multipart_uploads::Entity::delete_by_id(upload_id)
        .exec(&txn)
        .await
        .map_err(|e| format!("delete upload: {e}"))?;
    txn.commit().await.map_err(|e| format!("commit txn: {e}"))?;

    Ok(spool_paths)
}

/// Liệt kê tất cả Multipart Uploads chưa hoàn thành của một bucket.
pub async fn list_multipart_uploads(db: &Db, bucket: &str) -> Result<Vec<MultipartUpload>, String> {
    use entities::multipart_uploads::Column as U;
    let conn = db.sea_conn();
    let rows = entities::multipart_uploads::Entity::find()
        .filter(U::Bucket.eq(bucket))
        .order_by_asc(U::CreatedAt)
        .all(&conn)
        .await
        .map_err(|e| format!("query list multipart_uploads: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|m| MultipartUpload {
            upload_id: m.upload_id,
            bucket: m.bucket,
            key: m.key,
            content_type: m.content_type,
            metadata_json: m.metadata_json,
            created_at: m.created_at,
        })
        .collect())
}

/// Backend SeaORM tương ứng (cho `Statement::from_sql_and_values`).
pub(crate) fn sea_backend(db: &Db) -> sea_orm::DbBackend {
    match db.backend() {
        DbBackend::Sqlite => sea_orm::DbBackend::Sqlite,
        DbBackend::Postgres => sea_orm::DbBackend::Postgres,
    }
}

async fn prepare_versioning_write_tx(
    txn: &sea_orm::DatabaseTransaction,
    bucket: &str,
    key: &str,
    requested_version_id: &str,
) -> Result<(String, Vec<String>), String> {
    use entities::objects::Column as O;
    let v_status = entities::buckets::Entity::find_by_id(bucket)
        .one(txn)
        .await
        .map_err(|e| format!("query: {e}"))?
        .map(|m| m.versioning_status)
        .unwrap_or_else(|| "Disabled".to_string());
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
    } else {
        // Suspended: chỉ ghi đè version "null". Disabled: xóa mọi version cũ.
        let null_only = v_status == "Suspended";
        let mut q = entities::objects::Entity::find()
            .filter(O::Bucket.eq(bucket))
            .filter(O::Key.eq(key));
        if null_only {
            q = q.filter(O::VersionId.eq("null"));
        }
        let versions: Vec<String> = q
            .all(txn)
            .await
            .map_err(|e| format!("query: {e}"))?
            .into_iter()
            .map(|m| m.version_id)
            .collect();
        if !versions.is_empty() {
            use entities::chunks::Column as C;
            use entities::upload_jobs::Column as J;
            let spools: Vec<(Option<String>,)> = entities::chunks::Entity::find()
                .select_only()
                .column(C::SpoolPath)
                .filter(C::VersionId.is_in(versions.clone()))
                .into_tuple()
                .all(txn)
                .await
                .map_err(|e| format!("query: {e}"))?;
            old_spools.extend(spools.into_iter().filter_map(|(s,)| s));
            let _ = entities::upload_jobs::Entity::delete_many()
                .filter(J::VersionId.is_in(versions.clone()))
                .exec(txn)
                .await;
            let _ = entities::chunks::Entity::delete_many()
                .filter(C::VersionId.is_in(versions.clone()))
                .exec(txn)
                .await;
            let _ = entities::objects::Entity::delete_many()
                .filter(O::VersionId.is_in(versions))
                .exec(txn)
                .await;
        }
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

    let sea = db.sea_conn();
    let txn = sea.begin().await.map_err(|e| format!("begin txn: {e}"))?;

    let (final_version_id, old_spools) =
        prepare_versioning_write_tx(&txn, &bucket, &key, version_id).await?;

    entities::objects::ActiveModel {
        bucket: Set(bucket.clone()),
        key: Set(key.clone()),
        version_id: Set(final_version_id.clone()),
        is_delete_marker: Set(0),
        storage_state: Set("accepted-local".to_string()),
        size: Set(total_size),
        etag: Set(multipart_etag),
        content_type: Set(upload.content_type.clone()),
        user_metadata_json: Set(upload.metadata_json.clone()),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| format!("insert object: {e}"))?;

    for (idx, part) in parts.iter().enumerate() {
        let spool_path = part.spool_path.as_deref().unwrap_or("");
        entities::chunks::ActiveModel {
            version_id: Set(final_version_id.clone()),
            idx: Set(idx as i64),
            length: Set(part.size),
            plaintext_sha256: Set(part.plaintext_sha256.clone()),
            ciphertext_sha256: Set(part.ciphertext_sha256.clone()),
            encryption_mode: Set("none".to_string()),
            spool_path: Set(Some(spool_path.to_string())),
            state: Set("pending".to_string()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|e| format!("insert chunk: {e}"))?;
    }

    entities::upload_jobs::ActiveModel {
        job_id: Set(job_id.to_string()),
        version_id: Set(final_version_id.clone()),
        state: Set("pending".to_string()),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| format!("insert job: {e}"))?;

    entities::multipart_parts::Entity::delete_many()
        .filter(entities::multipart_parts::Column::UploadId.eq(upload_id))
        .exec(&txn)
        .await
        .map_err(|e| format!("delete parts: {e}"))?;
    entities::multipart_uploads::Entity::delete_by_id(upload_id)
        .exec(&txn)
        .await
        .map_err(|e| format!("delete upload: {e}"))?;

    txn.commit().await.map_err(|e| format!("commit txn: {e}"))?;

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
    let conn = db.sea_conn();
    let row = entities::buckets::Entity::find_by_id(bucket)
        .one(&conn)
        .await
        .map_err(|e| format!("query: {e}"))?;
    match row {
        Some(m) => Ok(m.versioning_status),
        None => Ok("Disabled".to_string()),
    }
}

pub async fn set_bucket_versioning(db: &Db, bucket: &str, status: &str) -> Result<(), String> {
    let conn = db.sea_conn();
    let res = entities::buckets::Entity::update_many()
        .col_expr(
            entities::buckets::Column::VersioningStatus,
            Expr::value(status.to_string()),
        )
        .filter(entities::buckets::Column::Name.eq(bucket))
        .exec(&conn)
        .await
        .map_err(|e| format!("execute update bucket versioning: {e}"))?;
    if res.rows_affected == 0 {
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
    let conn = db.sea_conn();
    let exists = entities::buckets::Entity::find_by_id(name)
        .one(&conn)
        .await
        .map_err(|e| format!("lookup bucket: {e}"))?
        .is_some();
    if exists {
        return Ok(CreateBucketOutcome::AlreadyOwned);
    }
    entities::buckets::ActiveModel {
        name: Set(name.to_string()),
        region: Set(region.to_string()),
        ..Default::default()
    }
    .insert(&conn)
    .await
    .map_err(|e| format!("insert bucket: {e}"))?;
    Ok(CreateBucketOutcome::Created)
}

pub async fn head_bucket(db: &Db, name: &str) -> Result<bool, String> {
    let conn = db.sea_conn();
    entities::buckets::Entity::find_by_id(name)
        .one(&conn)
        .await
        .map_err(|e| format!("lookup bucket: {e}"))
        .map(|m| m.is_some())
}

/// Xóa bucket — từ chối khi còn object/version (S3: 409 BucketNotEmpty).
pub async fn delete_bucket(db: &Db, name: &str) -> Result<DeleteBucketOutcome, String> {
    if !head_bucket(db, name).await? {
        return Ok(DeleteBucketOutcome::NoSuchBucket);
    }
    let conn = db.sea_conn();
    let n = entities::objects::Entity::find()
        .filter(entities::objects::Column::Bucket.eq(name))
        .count(&conn)
        .await
        .map_err(|e| format!("count objects: {e}"))?;
    if n > 0 {
        return Ok(DeleteBucketOutcome::NotEmpty);
    }
    // Multipart upload đang dở cũng tính là "có nội dung" (S3 trả 409 thay vì
    // để FK NỔ 500 khi xóa bucket còn upload dở dang).
    let uploads = list_multipart_uploads(db, name)
        .await
        .map_err(|e| format!("count uploads: {e}"))?;
    if !uploads.is_empty() {
        return Ok(DeleteBucketOutcome::NotEmpty);
    }
    entities::buckets::Entity::delete_by_id(name)
        .exec(&conn)
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
    let conn = db.sea_conn();
    let rows = entities::buckets::Entity::find()
        .order_by_asc(entities::buckets::Column::Name)
        .all(&conn)
        .await
        .map_err(|e| format!("query: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|m| Bucket {
            name: m.name,
            region: m.region,
            versioning_status: m.versioning_status,
            created_at: m.created_at,
        })
        .collect())
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
    pub remote_locator_json: Option<String>,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
}

/// Chunk mới để ghi trong `put_object`. Tách bạch plaintext checksum / ciphertext
/// checksum / ETag S3 (ETag nằm ở object, = MD5 plaintext).
#[derive(Debug, Clone)]
pub struct NewChunk {
    /// Offset dự kiến trong object. KHÔNG persist (cột `chunks.offset` đã xóa ở
    /// migration 0005) — đọc lắp chunk theo `idx` liên tục. Giữ field để ổn định
    /// API cho callers hiện tại.
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
    let sea = conn.sea_conn();
    let txn = sea.begin().await.map_err(|e| format!("begin txn: {e}"))?;

    let (final_version_id, old_spools) =
        prepare_versioning_write_tx(&txn, bucket, key, version_id).await?;

    entities::objects::ActiveModel {
        bucket: Set(bucket.to_string()),
        key: Set(key.to_string()),
        version_id: Set(final_version_id.clone()),
        is_delete_marker: Set(0),
        storage_state: Set("accepted-local".to_string()),
        size: Set(size),
        etag: Set(etag.to_string()),
        content_type: Set(content_type.to_string()),
        user_metadata_json: Set(user_metadata_json.map(|s| s.to_string())),
        system_metadata_json: Set(system_metadata_json.map(|s| s.to_string())),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| format!("insert object: {e}"))?;
    for (idx, c) in chunks.iter().enumerate() {
        entities::chunks::ActiveModel {
            version_id: Set(final_version_id.clone()),
            idx: Set(idx as i64),
            length: Set(c.length),
            plaintext_sha256: Set(c.plaintext_sha256.clone()),
            ciphertext_sha256: Set(c.ciphertext_sha256.clone()),
            encryption_mode: Set(c.mode.clone()),
            key_ref: Set(c.key_ref.clone()),
            spool_path: Set(Some(c.spool_path.clone())),
            state: Set("pending".to_string()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|e| format!("insert chunk: {e}"))?;
    }
    entities::upload_jobs::ActiveModel {
        job_id: Set(job_id.to_string()),
        version_id: Set(final_version_id.clone()),
        state: Set("pending".to_string()),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| format!("insert job: {e}"))?;
    txn.commit().await.map_err(|e| format!("commit txn: {e}"))?;
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

    let sea = conn.sea_conn();
    let txn = sea.begin().await.map_err(|e| format!("begin txn: {e}"))?;

    let (final_version_id, old_spools) =
        prepare_versioning_write_tx(&txn, dest_bucket, dest_key, new_version_id).await?;

    entities::objects::ActiveModel {
        bucket: Set(dest_bucket.to_string()),
        key: Set(dest_key.to_string()),
        version_id: Set(final_version_id.clone()),
        is_delete_marker: Set(0),
        storage_state: Set("accepted-local".to_string()),
        size: Set(src_version.size),
        etag: Set(src_version.etag.clone()),
        content_type: Set(final_content_type),
        user_metadata_json: Set(final_user_meta),
        system_metadata_json: Set(final_sys_meta),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| format!("insert object: {e}"))?;

    // Zero-copy spool reference: đọc chunk nguồn trong txn rồi chèn lại dưới
    // version mới (thay INSERT..SELECT raw như trước).
    let src_rows = entities::chunks::Entity::find()
        .filter(entities::chunks::Column::VersionId.eq(&src_version.version_id))
        .order_by_asc(entities::chunks::Column::Idx)
        .all(&txn)
        .await
        .map_err(|e| format!("copy chunk: {e}"))?;

    let mut need_upload = false;
    for s in &src_rows {
        // Mọi cột đều Set tường minh; `..Default` chỉ để đủ field.
        #[allow(clippy::needless_update)]
        let am = entities::chunks::ActiveModel {
            version_id: Set(final_version_id.clone()),
            idx: Set(s.idx),
            length: Set(s.length),
            plaintext_sha256: Set(s.plaintext_sha256.clone()),
            ciphertext_sha256: Set(s.ciphertext_sha256.clone()),
            encryption_mode: Set(s.encryption_mode.clone()),
            key_ref: Set(s.key_ref.clone()),
            spool_path: Set(s.spool_path.clone()),
            remote_locator_json: Set(s.remote_locator_json.clone()),
            state: Set(s.state.clone()),
            ..Default::default()
        };
        entities::chunks::Entity::insert(am)
            .exec(&txn)
            .await
            .map_err(|e| format!("copy chunk: {e}"))?;

        if s.state == "pending" {
            need_upload = true;
        }
    }

    if need_upload {
        entities::upload_jobs::ActiveModel {
            job_id: Set(new_job_id.to_string()),
            version_id: Set(final_version_id.clone()),
            state: Set("pending".to_string()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|e| format!("insert job: {e}"))?;
    }

    txn.commit().await.map_err(|e| format!("commit txn: {e}"))?;

    let version = latest_version(conn, dest_bucket, dest_key)
        .await?
        .ok_or_else(|| "Failed to fetch copied object version".to_string())?;

    Ok((old_spools, version))
}

fn object_version(m: entities::objects::Model) -> ObjectVersion {
    ObjectVersion {
        version_id: m.version_id,
        key: m.key,
        is_delete_marker: m.is_delete_marker != 0,
        size: m.size,
        etag: m.etag,
        content_type: m.content_type,
        storage_state: m.storage_state,
        created_at: m.created_at,
        user_metadata_json: m.user_metadata_json,
        system_metadata_json: m.system_metadata_json,
    }
}

pub async fn latest_version(
    db: &Db,
    bucket: &str,
    key: &str,
) -> Result<Option<ObjectVersion>, String> {
    use entities::objects::Column as O;
    let conn = db.sea_conn();
    // Tiebreaker "bản ghi chèn sau" khi created_at trùng: rowid/ctid là
    // intrinsic của backend (không phải schema) nên dùng Expr tường minh.
    let tb = match db.backend() {
        DbBackend::Sqlite => "rowid",
        DbBackend::Postgres => "ctid",
    };
    let row = entities::objects::Entity::find()
        .filter(O::Bucket.eq(bucket))
        .filter(O::Key.eq(key))
        .order_by_desc(O::CreatedAt)
        .order_by_desc(Expr::cust(tb))
        .one(&conn)
        .await
        .map_err(|e| format!("query: {e}"))?;
    Ok(row.map(object_version))
}

pub async fn get_version_by_id(
    db: &Db,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<Option<ObjectVersion>, String> {
    use entities::objects::Column as O;
    let conn = db.sea_conn();
    let row = entities::objects::Entity::find()
        .filter(O::Bucket.eq(bucket))
        .filter(O::Key.eq(key))
        .filter(O::VersionId.eq(version_id))
        .one(&conn)
        .await
        .map_err(|e| format!("query: {e}"))?;
    Ok(row.map(object_version))
}

pub async fn chunks_of(db: &Db, version_id: &str) -> Result<Vec<ChunkRow>, String> {
    use entities::chunks::Column as C;
    let conn = db.sea_conn();
    let rows = entities::chunks::Entity::find()
        .filter(C::VersionId.eq(version_id))
        .order_by_asc(C::Idx)
        .all(&conn)
        .await
        .map_err(|e| format!("query: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|m| ChunkRow {
            idx: m.idx,
            length: m.length,
            spool_path: m.spool_path,
            state: m.state,
            encryption_mode: m.encryption_mode,
            key_ref: m.key_ref,
            remote_locator_json: m.remote_locator_json,
            plaintext_sha256: m.plaintext_sha256,
            ciphertext_sha256: m.ciphertext_sha256,
        })
        .collect())
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
    let sea = db.sea_conn();
    let txn = sea.begin().await.map_err(|e| format!("begin txn: {e}"))?;
    let (version_id, _) = prepare_versioning_write_tx(&txn, bucket, key, "null").await?;
    entities::objects::ActiveModel {
        bucket: Set(bucket.to_string()),
        key: Set(key.to_string()),
        version_id: Set(version_id.clone()),
        is_delete_marker: Set(1),
        storage_state: Set("accepted-local".to_string()),
        size: Set(0),
        etag: Set(String::new()),
        content_type: Set(String::new()),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| format!("insert delete marker: {e}"))?;
    txn.commit().await.map_err(|e| format!("commit txn: {e}"))?;
    Ok(version_id)
}

pub async fn delete_object_version(
    db: &Db,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<DeleteObjectResult, String> {
    use entities::chunks::Column as C;
    use entities::objects::Column as O;
    use entities::upload_jobs::Column as J;
    let sea = db.sea_conn();
    let txn = sea.begin().await.map_err(|e| format!("begin txn: {e}"))?;

    let is_dm = match entities::objects::Entity::find()
        .filter(O::Bucket.eq(bucket))
        .filter(O::Key.eq(key))
        .filter(O::VersionId.eq(version_id))
        .one(&txn)
        .await
        .map_err(|e| format!("query: {e}"))?
    {
        Some(m) => m.is_delete_marker != 0,
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

    let spool_paths: Vec<String> = entities::chunks::Entity::find()
        .select_only()
        .column(C::SpoolPath)
        .filter(C::VersionId.eq(version_id))
        .into_tuple::<(Option<String>,)>()
        .all(&txn)
        .await
        .map_err(|e| format!("query: {e}"))?
        .into_iter()
        .filter_map(|(s,)| s)
        .collect();

    let _ = entities::upload_jobs::Entity::delete_many()
        .filter(J::VersionId.eq(version_id))
        .exec(&txn)
        .await;
    let _ = entities::chunks::Entity::delete_many()
        .filter(C::VersionId.eq(version_id))
        .exec(&txn)
        .await;
    entities::objects::Entity::delete_many()
        .filter(O::Bucket.eq(bucket))
        .filter(O::Key.eq(key))
        .filter(O::VersionId.eq(version_id))
        .exec(&txn)
        .await
        .map_err(|e| format!("delete version: {e}"))?;

    txn.commit().await.map_err(|e| format!("commit txn: {e}"))?;

    Ok(DeleteObjectResult {
        existed: true,
        spool_paths,
        remote_locators: Vec::new(),
        is_delete_marker: is_dm,
        version_id: version_id.to_string(),
    })
}

pub async fn delete_object(db: &Db, bucket: &str, key: &str) -> Result<DeleteObjectResult, String> {
    use entities::chunks::Column as C;
    use entities::objects::Column as O;
    use entities::upload_jobs::Column as J;
    let sea = db.sea_conn();
    let txn = sea.begin().await.map_err(|e| format!("begin txn: {e}"))?;
    let versions: Vec<String> = entities::objects::Entity::find()
        .select_only()
        .column(O::VersionId)
        .filter(O::Bucket.eq(bucket))
        .filter(O::Key.eq(key))
        .into_tuple::<(String,)>()
        .all(&txn)
        .await
        .map_err(|e| format!("query: {e}"))?
        .into_iter()
        .map(|(v,)| v)
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
        let rows = entities::chunks::Entity::find()
            .filter(C::VersionId.eq(v.as_str()))
            .all(&txn)
            .await
            .map_err(|e| format!("query: {e}"))?;
        for m in rows {
            if let Some(p) = m.spool_path {
                spool_paths.push(p);
            }
            if m.state == "remote" {
                if let Some(loc) = m.remote_locator_json {
                    if let Ok(parsed) = serde_json::from_str(&loc) {
                        remote_locators.push(parsed);
                    }
                }
            }
        }
        entities::upload_jobs::Entity::delete_many()
            .filter(J::VersionId.eq(v.as_str()))
            .exec(&txn)
            .await
            .map_err(|e| format!("delete jobs: {e}"))?;
        entities::chunks::Entity::delete_many()
            .filter(C::VersionId.eq(v.as_str()))
            .exec(&txn)
            .await
            .map_err(|e| format!("delete chunks: {e}"))?;
    }
    entities::objects::Entity::delete_many()
        .filter(O::Bucket.eq(bucket))
        .filter(O::Key.eq(key))
        .exec(&txn)
        .await
        .map_err(|e| format!("delete objects: {e}"))?;
    txn.commit().await.map_err(|e| format!("commit txn: {e}"))?;
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
    // rowid/ctid là intrinsic của backend (không phải schema) + LIKE..ESCAPE +
    // so sánh tuple — giữ nguyên SQL text, chỉ chuyển sang chạy trên sea_conn.
    let tb = match db.backend() {
        DbBackend::Sqlite => "rowid",
        DbBackend::Postgres => "ctid",
    };
    let sql = format!("SELECT key, version_id, is_delete_marker, size, etag, created_at FROM objects WHERE bucket = ? AND key LIKE ? || '%' ESCAPE '\\' AND (key > ? OR (key = ? AND version_id > ?)) ORDER BY key ASC, created_at DESC, {tb} DESC LIMIT ?");
    let stmt = Statement::from_sql_and_values(
        sea_backend(db),
        sql,
        [
            Value::from(bucket.to_string()),
            Value::from(esc),
            Value::from(key_marker.to_string()),
            Value::from(key_marker.to_string()),
            Value::from(version_id_marker.to_string()),
            Value::from(limit),
        ],
    );
    let rows = db
        .sea_conn()
        .query_all(stmt)
        .await
        .map_err(|e| format!("query: {e}"))?;

    let mut result = Vec::new();
    let mut last_key: Option<String> = None;

    for r in rows {
        let key: String = r.try_get("", "key").map_err(|e| format!("row: {e}"))?;
        let version_id: String = r
            .try_get("", "version_id")
            .map_err(|e| format!("row: {e}"))?;
        let is_delete_marker: bool = r
            .try_get::<i64>("", "is_delete_marker")
            .map(|v| v != 0)
            .map_err(|e| format!("row: {e}"))?;
        let size: i64 = r.try_get("", "size").map_err(|e| format!("row: {e}"))?;
        let etag: String = r.try_get("", "etag").map_err(|e| format!("row: {e}"))?;
        let created_at: String = r
            .try_get("", "created_at")
            .map_err(|e| format!("row: {e}"))?;
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
    // Subquery tương quan MAX(rowid/ctid) — intrinsic backend, giữ nguyên SQL text.
    let tb = match db.backend() {
        DbBackend::Sqlite => "rowid",
        DbBackend::Postgres => "ctid",
    };
    let sql = format!("SELECT key, version_id, is_delete_marker, size, etag, content_type, storage_state, created_at, user_metadata_json, system_metadata_json FROM objects o1 WHERE bucket = ? AND key LIKE ? || '%' ESCAPE '\\' AND key > ? AND {tb} = (SELECT MAX({tb}) FROM objects o2 WHERE o2.bucket = o1.bucket AND o2.key = o1.key) AND is_delete_marker = 0 ORDER BY key LIMIT ?");

    let stmt = Statement::from_sql_and_values(
        sea_backend(db),
        sql,
        [
            Value::from(bucket.to_string()),
            Value::from(esc),
            Value::from(start_after.to_string()),
            Value::from(limit_plus_one),
        ],
    );
    let rows = db
        .sea_conn()
        .query_all(stmt)
        .await
        .map_err(|e| format!("query: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        let key: String = r.try_get("", "key").map_err(|e| format!("rows: {e}"))?;
        out.push((
            key.clone(),
            ObjectVersion {
                version_id: r
                    .try_get("", "version_id")
                    .map_err(|e| format!("rows: {e}"))?,
                key,
                is_delete_marker: r
                    .try_get::<i64>("", "is_delete_marker")
                    .map(|v| v != 0)
                    .map_err(|e| format!("rows: {e}"))?,
                size: r.try_get("", "size").map_err(|e| format!("rows: {e}"))?,
                etag: r.try_get("", "etag").map_err(|e| format!("rows: {e}"))?,
                content_type: r
                    .try_get("", "content_type")
                    .map_err(|e| format!("rows: {e}"))?,
                storage_state: r
                    .try_get("", "storage_state")
                    .map_err(|e| format!("rows: {e}"))?,
                created_at: r
                    .try_get("", "created_at")
                    .map_err(|e| format!("rows: {e}"))?,
                user_metadata_json: r
                    .try_get("", "user_metadata_json")
                    .map_err(|e| format!("rows: {e}"))?,
                system_metadata_json: r
                    .try_get("", "system_metadata_json")
                    .map_err(|e| format!("rows: {e}"))?,
            },
        ));
    }
    Ok(out)
}

/// Lấy tất cả đường dẫn spool_path đang active (không NULL) trong bảng chunks và multipart_parts.
pub async fn active_spool_paths(
    db: &Db,
) -> Result<std::collections::HashSet<std::path::PathBuf>, String> {
    use entities::chunks::Column as C;
    use entities::multipart_parts::Column as P;
    let conn = db.sea_conn();
    let mut paths: Vec<Option<String>> = entities::chunks::Entity::find()
        .select_only()
        .column(C::SpoolPath)
        .filter(C::SpoolPath.is_not_null())
        .into_tuple::<(Option<String>,)>()
        .all(&conn)
        .await
        .map_err(|e| format!("query active spool: {e}"))?
        .into_iter()
        .map(|(s,)| s)
        .collect();
    // UNION với parts: chỉ khi schema đã có bảng multipart_parts (migration >= 2).
    if schema_version(db).await.unwrap_or(0) >= 2 {
        let more: Vec<(Option<String>,)> = entities::multipart_parts::Entity::find()
            .select_only()
            .column(P::SpoolPath)
            .filter(P::SpoolPath.is_not_null())
            .into_tuple()
            .all(&conn)
            .await
            .map_err(|e| format!("query active spool: {e}"))?;
        paths.extend(more.into_iter().map(|(s,)| s));
    }
    let mut set = std::collections::HashSet::new();
    for p in paths.into_iter().flatten() {
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
    let conn = db.sea_conn();
    entities::access_keys::Entity::insert(entities::access_keys::ActiveModel {
        access_key_id: Set(access_key_id.to_string()),
        secret_key: Set(secret_key.to_string()),
        status: Set("Active".to_string()),
        description: Set(description.map(|s| s.to_string())),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::columns([entities::access_keys::Column::AccessKeyId])
            .update_columns([
                entities::access_keys::Column::SecretKey,
                entities::access_keys::Column::Status,
                entities::access_keys::Column::Description,
            ])
            .to_owned(),
    )
    .exec(&conn)
    .await
    .map_err(|e| format!("insert access_key: {e}"))?;
    Ok(())
}

fn access_key_record(m: entities::access_keys::Model) -> AccessKeyRecord {
    AccessKeyRecord {
        access_key_id: m.access_key_id,
        secret_key: m.secret_key,
        status: m.status,
        description: m.description,
        created_at: m.created_at,
    }
}

pub async fn get_access_key(
    db: &Db,
    access_key_id: &str,
) -> Result<Option<AccessKeyRecord>, String> {
    let conn = db.sea_conn();
    entities::access_keys::Entity::find_by_id(access_key_id)
        .one(&conn)
        .await
        .map_err(|e| format!("query get access_key: {e}"))
        .map(|m| m.map(access_key_record))
}

pub async fn list_access_keys(db: &Db) -> Result<Vec<AccessKeyRecord>, String> {
    let conn = db.sea_conn();
    let rows = entities::access_keys::Entity::find()
        .order_by_asc(entities::access_keys::Column::CreatedAt)
        .all(&conn)
        .await
        .map_err(|e| format!("query list access_keys: {e}"))?;
    Ok(rows.into_iter().map(access_key_record).collect())
}

pub async fn delete_access_key(db: &Db, access_key_id: &str) -> Result<bool, String> {
    let conn = db.sea_conn();
    let res = entities::access_keys::Entity::delete_by_id(access_key_id)
        .exec(&conn)
        .await
        .map_err(|e| format!("delete access_key: {e}"))?;
    Ok(res.rows_affected > 0)
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
    let conn = db.sea_conn();
    let res = entities::access_keys::Entity::update_many()
        .col_expr(
            entities::access_keys::Column::Status,
            Expr::value(canonical_status.to_string()),
        )
        .filter(entities::access_keys::Column::AccessKeyId.eq(access_key_id))
        .exec(&conn)
        .await
        .map_err(|e| format!("update access_key status: {e}"))?;
    Ok(res.rows_affected > 0)
}

pub async fn update_access_key_description(
    db: &Db,
    access_key_id: &str,
    description: &str,
) -> Result<bool, String> {
    let conn = db.sea_conn();
    let res = entities::access_keys::Entity::update_many()
        .col_expr(
            entities::access_keys::Column::Description,
            Expr::value(Some(description.to_string())),
        )
        .filter(entities::access_keys::Column::AccessKeyId.eq(access_key_id))
        .exec(&conn)
        .await
        .map_err(|e| format!("update access_key description: {e}"))?;
    Ok(res.rows_affected > 0)
}

pub async fn update_access_key_allowed_buckets(
    db: &Db,
    access_key_id: &str,
    allowed_buckets: Option<&str>,
) -> Result<bool, String> {
    let conn = db.sea_conn();
    let res = entities::access_keys::Entity::update_many()
        .col_expr(
            entities::access_keys::Column::AllowedBuckets,
            Expr::value(allowed_buckets.map(|s| s.to_string())),
        )
        .filter(entities::access_keys::Column::AccessKeyId.eq(access_key_id))
        .exec(&conn)
        .await
        .map_err(|e| format!("update access_key allowed_buckets: {e}"))?;
    Ok(res.rows_affected > 0)
}

pub async fn touch_access_key_last_used(db: &Db, access_key_id: &str) -> Result<(), String> {
    let now = now_str();
    let conn = db.sea_conn();
    entities::access_keys::Entity::update_many()
        .col_expr(
            entities::access_keys::Column::LastUsedAt,
            Expr::value(Some(now)),
        )
        .filter(entities::access_keys::Column::AccessKeyId.eq(access_key_id))
        .exec(&conn)
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
    // Aggregate tương quan giữ nguyên SQL text, chạy trên sea_conn (có alias ổn
    // định cho QueryResult).
    let sql = match db.backend() {
        DbBackend::Sqlite => "SELECT b.name AS name, \
             COALESCE((SELECT COUNT(*) FROM objects o WHERE o.bucket = b.name AND o.is_delete_marker = 0), 0) AS object_count, \
             COALESCE((SELECT SUM(o.size) FROM objects o WHERE o.bucket = b.name AND o.is_delete_marker = 0), 0) AS total_size \
             FROM buckets b ORDER BY b.name",
        DbBackend::Postgres => "SELECT b.name AS name, \
             COALESCE((SELECT COUNT(*) FROM objects o WHERE o.bucket = b.name AND o.is_delete_marker = 0), 0) AS object_count, \
             COALESCE((SELECT SUM(o.size) FROM objects o WHERE o.bucket = b.name AND o.is_delete_marker = 0)::BIGINT, 0) AS total_size \
             FROM buckets b ORDER BY b.name",
    };
    let stmt = Statement::from_sql_and_values(sea_backend(db), sql, []);
    let rows = db
        .sea_conn()
        .query_all(stmt)
        .await
        .map_err(|e| format!("query bucket_stats: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(BucketStats {
            name: r
                .try_get("", "name")
                .map_err(|e| format!("rows bucket_stats: {e}"))?,
            object_count: r
                .try_get("", "object_count")
                .map_err(|e| format!("rows bucket_stats: {e}"))?,
            total_size_bytes: r
                .try_get("", "total_size")
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
    use entities::upload_jobs::Column as J;
    let conn = db.sea_conn();
    let rows = entities::upload_jobs::Entity::find()
        .select_only()
        .column(J::JobId)
        .column(J::VersionId)
        .column_as(entities::objects::Column::Bucket, "bucket")
        .column_as(entities::objects::Column::Key, "key")
        .column(J::State)
        .column(J::RetryCount)
        .column(J::NextAttempt)
        .column(J::LeaseOwner)
        .column(J::LeaseExpires)
        .column(J::LastError)
        .join(
            JoinType::LeftJoin,
            entities::upload_jobs::Relation::Objects.def(),
        )
        .order_by_desc(J::NextAttempt)
        .limit(200)
        .into_tuple::<(
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            i64,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        )>()
        .all(&conn)
        .await
        .map_err(|e| format!("query list_jobs: {e}"))?;
    let jobs = rows
        .into_iter()
        .map(
            |(
                job_id,
                version_id,
                bucket,
                key,
                state,
                retry_count,
                next_attempt,
                lease_owner,
                lease_expires,
                last_error,
            )| JobRecord {
                job_id,
                version_id,
                bucket: bucket.unwrap_or_default(),
                key: key.unwrap_or_default(),
                state,
                retry_count,
                next_attempt,
                lease_owner,
                lease_expires,
                last_error,
            },
        )
        .collect();

    let summary = job_summary(db).await?;
    Ok((jobs, summary))
}

pub async fn job_summary(db: &Db) -> Result<JobSummary, String> {
    let conn = db.sea_conn();
    async fn count(conn: &sea_orm::DatabaseConnection, state: &str) -> Result<i64, String> {
        use entities::upload_jobs::Column as J;
        entities::upload_jobs::Entity::find()
            .filter(J::State.eq(state))
            .count(conn)
            .await
            .map(|n| n as i64)
            .map_err(|e| format!("count jobs {state}: {e}"))
    }
    // Job xong ghi state 'done' (finish_upload_job) — 'completed' không bao giờ
    // được set nên đếm 'done' vào đây để dashboard "Hoàn tất" trung thực.
    Ok(JobSummary {
        pending: count(&conn, "pending").await?,
        uploading: count(&conn, "uploading").await?,
        completed: count(&conn, "done").await.unwrap_or(0),
        failed: count(&conn, "failed").await.unwrap_or(0),
    })
}

// Worker job-lease ops (M2.2) — SQL nguyên tử tập trung tại DAL (ADR 0006 Phase 3b).
// worker.rs chỉ gọi các hàm này, không viết SQL inline. Không giữ txn mở suốt
// network upload: mỗi op là 1 statement độc lập, lease chống giành nhau.

/// Job vừa claim được.
#[derive(Debug, Clone)]
pub struct ClaimedJob {
    pub job_id: String,
    pub version_id: String,
    pub retry_count: i64,
}

/// Claim 1 job sẵn sàng bằng lease. Lấy job `pending` tới hạn, hoặc job
/// `uploading` mà lease đã hết (worker cũ chết giữa chừng — reclaim).
/// `now` chấp nhận cả ISO-8601 và chuẩn TEXT, chuẩn hóa trước khi so sánh.
pub async fn claim_job(
    db: &Db,
    owner: &str,
    lease_secs: i64,
    now: &str,
) -> Result<Option<ClaimedJob>, String> {
    use entities::upload_jobs::Column as J;
    use sea_orm::Condition;
    let normalized = now.replace('T', " ").trim_end_matches('Z').to_string();
    let now = normalized.as_str();
    let conn = db.sea_conn();
    let row = entities::upload_jobs::Entity::find()
        .select_only()
        .column(J::JobId)
        .column(J::VersionId)
        .column(J::RetryCount)
        .filter(J::NextAttempt.lte(now))
        .filter(
            Condition::any().add(J::State.eq("pending")).add(
                Condition::all()
                    .add(J::State.eq("uploading"))
                    .add(J::LeaseExpires.is_not_null())
                    .add(J::LeaseExpires.lte(now)),
            ),
        )
        .order_by_asc(J::NextAttempt)
        .into_tuple::<(String, String, i64)>()
        .one(&conn)
        .await
        .map_err(|e| format!("poll: {e}"))?;
    let Some((job_id, version_id, retry_count)) = row else {
        return Ok(None);
    };
    // Claim nguyên tử: chỉ thắng khi job pending, hoặc uploading mà lease đã hết.
    let lease_until = now_plus_str(lease_secs);
    let res = entities::upload_jobs::Entity::update_many()
        .col_expr(J::State, Expr::value("uploading".to_string()))
        .col_expr(J::LeaseOwner, Expr::value(Some(owner.to_string())))
        .col_expr(J::LeaseExpires, Expr::value(Some(lease_until)))
        .filter(J::JobId.eq(job_id.as_str()))
        .filter(
            Condition::any().add(J::State.eq("pending")).add(
                Condition::all().add(J::State.eq("uploading")).add(
                    Condition::any()
                        .add(J::LeaseExpires.is_null())
                        .add(J::LeaseExpires.lte(now)),
                ),
            ),
        )
        .exec(&conn)
        .await
        .map_err(|e| format!("claim: {e}"))?;
    if res.rows_affected == 0 {
        return Ok(None); // worker khác claim trước.
    }
    Ok(Some(ClaimedJob {
        job_id,
        version_id,
        retry_count,
    }))
}

/// Version còn tồn tại không (có thể đã bị DELETE sau khi job tạo).
pub async fn object_version_exists(db: &Db, version_id: &str) -> Result<bool, String> {
    use entities::objects::Column as O;
    let conn = db.sea_conn();
    entities::objects::Entity::find()
        .select_only()
        .column(O::VersionId)
        .filter(O::VersionId.eq(version_id))
        .into_tuple::<(String,)>()
        .one(&conn)
        .await
        .map(|r| r.is_some())
        .map_err(|e| format!("version check: {e}"))
}

/// Commit locator 1 chunk (giữ spool_path để GC xóa file sau).
pub async fn commit_chunk_locator(
    db: &Db,
    version_id: &str,
    idx: i64,
    locator_json: &str,
) -> Result<(), String> {
    use entities::chunks::Column as C;
    let conn = db.sea_conn();
    entities::chunks::Entity::update_many()
        .col_expr(C::State, Expr::value("remote".to_string()))
        .col_expr(
            C::RemoteLocatorJson,
            Expr::value(Some(locator_json.to_string())),
        )
        .filter(C::VersionId.eq(version_id))
        .filter(C::Idx.eq(idx))
        .exec(&conn)
        .await
        .map_err(|e| format!("commit chunk: {e}"))?;
    Ok(())
}

/// Xóa file spool xong thì set `spool_path = NULL` (best-effort, caller bỏ qua lỗi).
pub async fn clear_chunk_spool_path(db: &Db, version_id: &str, idx: i64) -> Result<(), String> {
    use entities::chunks::Column as C;
    let conn = db.sea_conn();
    entities::chunks::Entity::update_many()
        .col_expr(C::SpoolPath, Expr::value(None::<String>))
        .filter(C::VersionId.eq(version_id))
        .filter(C::Idx.eq(idx))
        .exec(&conn)
        .await
        .map_err(|e| format!("clear spool: {e}"))?;
    Ok(())
}

/// Kết thúc job: version remote → objects `remote`; job `done` (hoặc `pending`
/// lại) + xóa lease.
pub async fn finish_upload_job(db: &Db, job_id: &str, done: bool) -> Result<(), String> {
    use entities::upload_jobs::Column as J;
    let conn = db.sea_conn();
    if done {
        if let Some(m) = entities::upload_jobs::Entity::find_by_id(job_id)
            .one(&conn)
            .await
            .map_err(|e| format!("finish lookup: {e}"))?
        {
            use entities::objects::Column as O;
            let _ = entities::objects::Entity::update_many()
                .col_expr(O::StorageState, Expr::value("remote".to_string()))
                .filter(O::VersionId.eq(m.version_id))
                .exec(&conn)
                .await;
        }
    }
    entities::upload_jobs::Entity::update_many()
        .col_expr(
            J::State,
            Expr::value(if done { "done" } else { "pending" }.to_string()),
        )
        .col_expr(J::LeaseOwner, Expr::value(None::<String>))
        .col_expr(J::LeaseExpires, Expr::value(None::<String>))
        .filter(J::JobId.eq(job_id))
        .exec(&conn)
        .await
        .map_err(|e| format!("finish job: {e}"))?;
    Ok(())
}

/// Job lỗi transient: pending lại + retry_count tăng + lùi next_attempt.
pub async fn fail_job_transient(
    db: &Db,
    job_id: &str,
    retry_count: i64,
    next_attempt: &str,
    err_debug: &str,
) -> Result<(), String> {
    use entities::upload_jobs::Column as J;
    let conn = db.sea_conn();
    entities::upload_jobs::Entity::update_many()
        .col_expr(J::State, Expr::value("pending".to_string()))
        .col_expr(J::LeaseOwner, Expr::value(None::<String>))
        .col_expr(J::LeaseExpires, Expr::value(None::<String>))
        .col_expr(J::RetryCount, Expr::value(retry_count + 1))
        .col_expr(J::NextAttempt, Expr::value(next_attempt.to_string()))
        .col_expr(J::LastError, Expr::value(Some(err_debug.to_string())))
        .filter(J::JobId.eq(job_id))
        .exec(&conn)
        .await
        .map_err(|e| format!("fail job: {e}"))?;
    Ok(())
}

/// Job lỗi permanent: `failed` + xóa lease, giữ last_error.
pub async fn fail_job_permanent(db: &Db, job_id: &str, err_debug: &str) -> Result<(), String> {
    use entities::upload_jobs::Column as J;
    let conn = db.sea_conn();
    entities::upload_jobs::Entity::update_many()
        .col_expr(J::State, Expr::value("failed".to_string()))
        .col_expr(J::LeaseOwner, Expr::value(None::<String>))
        .col_expr(J::LeaseExpires, Expr::value(None::<String>))
        .col_expr(J::LastError, Expr::value(Some(err_debug.to_string())))
        .filter(J::JobId.eq(job_id))
        .exec(&conn)
        .await
        .map_err(|e| format!("fail job: {e}"))?;
    Ok(())
}

/// Đưa mọi job `failed` về `pending` (worker reset khi có transport mới).
pub async fn reset_failed_jobs(db: &Db) -> Result<(), String> {
    use entities::upload_jobs::Column as J;
    let conn = db.sea_conn();
    entities::upload_jobs::Entity::update_many()
        .col_expr(J::State, Expr::value("pending".to_string()))
        .col_expr(J::RetryCount, Expr::value(0i64))
        .filter(J::State.eq("failed"))
        .exec(&conn)
        .await
        .map_err(|e| format!("reset failed jobs: {e}"))?;
    Ok(())
}

/// Giờ DB hiện tại ở chuẩn TEXT (SQLite `datetime('now')`, Postgres `to_char`
/// UTC) — cho worker/tests so sánh chuỗi với `next_attempt`/`lease_expires`.
pub async fn db_now_str(db: &Db) -> Result<String, String> {
    use sea_orm::{ConnectionTrait, Statement};
    let sql = match db.backend() {
        DbBackend::Sqlite => "SELECT datetime('now') AS now",
        DbBackend::Postgres => {
            "SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') AS now"
        }
    };
    db.sea_conn()
        .query_one(Statement::from_string(sea_backend(db), sql.to_string()))
        .await
        .map_err(|e| format!("db now: {e}"))?
        .ok_or_else(|| "db now: no row".to_string())?
        .try_get("", "now")
        .map_err(|e| format!("db now: {e}"))
}

/// Đọc state 1 job (cho tests/assert).
pub async fn job_state(db: &Db, job_id: &str) -> Result<String, String> {
    use entities::upload_jobs::Column as J;
    let conn = db.sea_conn();
    entities::upload_jobs::Entity::find()
        .select_only()
        .column(J::State)
        .filter(J::JobId.eq(job_id))
        .into_tuple::<(String,)>()
        .one(&conn)
        .await
        .map_err(|e| format!("job state: {e}"))?
        .map(|(s,)| s)
        .ok_or_else(|| "job state: not found".to_string())
}

/// Đọc (state, retry_count) 1 job (cho tests/assert).
pub async fn job_state_retry(db: &Db, job_id: &str) -> Result<(String, i64), String> {
    use entities::upload_jobs::Column as J;
    let conn = db.sea_conn();
    entities::upload_jobs::Entity::find()
        .select_only()
        .column(J::State)
        .column(J::RetryCount)
        .filter(J::JobId.eq(job_id))
        .into_tuple::<(String, i64)>()
        .one(&conn)
        .await
        .map_err(|e| format!("job state: {e}"))?
        .ok_or_else(|| "job state: not found".to_string())
}

/// State job bất kỳ (live_e2e poll daemon). Không ORDER BY — như SQL cũ.
pub async fn first_upload_job_state(db: &Db) -> Result<Option<String>, String> {
    use entities::upload_jobs::Column as J;
    let conn = db.sea_conn();
    entities::upload_jobs::Entity::find()
        .select_only()
        .column(J::State)
        .into_tuple::<(String,)>()
        .one(&conn)
        .await
        .map(|r| r.map(|(s,)| s))
        .map_err(|e| format!("first job state: {e}"))
}

/// Ép lease/state job (cho tests giả lập worker chết).
pub async fn force_job_lease(
    db: &Db,
    job_id: &str,
    state: &str,
    owner: Option<&str>,
    expires: Option<&str>,
    next_attempt: Option<&str>,
) -> Result<(), String> {
    use entities::upload_jobs::Column as J;
    let conn = db.sea_conn();
    let mut q = entities::upload_jobs::Entity::update_many()
        .col_expr(J::State, Expr::value(state.to_string()))
        .col_expr(J::LeaseOwner, Expr::value(owner.map(|s| s.to_string())))
        .col_expr(J::LeaseExpires, Expr::value(expires.map(|s| s.to_string())))
        .filter(J::JobId.eq(job_id));
    if let Some(n) = next_attempt {
        q = q.col_expr(J::NextAttempt, Expr::value(n.to_string()));
    }
    q.exec(&conn)
        .await
        .map_err(|e| format!("force lease: {e}"))?;
    Ok(())
}

// GC/doctor helpers — SQL dọn dẹp/kiểm tra tập trung tại DAL (ADR 0006 Phase 4a).

/// Set state 1 version (GC/tests).
pub async fn set_chunk_state(db: &Db, version_id: &str, state: &str) -> Result<(), String> {
    use entities::chunks::Column as C;
    let conn = db.sea_conn();
    entities::chunks::Entity::update_many()
        .col_expr(C::State, Expr::value(state.to_string()))
        .filter(C::VersionId.eq(version_id))
        .exec(&conn)
        .await
        .map_err(|e| format!("set chunk state: {e}"))?;
    Ok(())
}

/// Set locator remote 1 chunk (không đổi state — khác commit_chunk_locator).
pub async fn set_chunk_locator(
    db: &Db,
    version_id: &str,
    idx: i64,
    locator_json: &str,
) -> Result<(), String> {
    use entities::chunks::Column as C;
    let conn = db.sea_conn();
    entities::chunks::Entity::update_many()
        .col_expr(
            C::RemoteLocatorJson,
            Expr::value(Some(locator_json.to_string())),
        )
        .filter(C::VersionId.eq(version_id))
        .filter(C::Idx.eq(idx))
        .exec(&conn)
        .await
        .map_err(|e| format!("set chunk locator: {e}"))?;
    Ok(())
}

/// Gắn/bỏ cờ delete-marker trên version (GC/tests tombstone).
pub async fn flag_object_delete_marker(
    db: &Db,
    version_id: &str,
    is_delete_marker: bool,
) -> Result<(), String> {
    use entities::objects::Column as O;
    let conn = db.sea_conn();
    entities::objects::Entity::update_many()
        .col_expr(O::IsDeleteMarker, Expr::value(is_delete_marker as i64))
        .filter(O::VersionId.eq(version_id))
        .exec(&conn)
        .await
        .map_err(|e| format!("flag delete marker: {e}"))?;
    Ok(())
}

/// Các chunk đã upload remote xong (`state = 'remote'`) nhưng vẫn còn
/// `spool_path` (worker crash giữa remote-commit và spool-cleanup, hoặc GC chưa
/// chạy). Xóa file các chunk này an toàn vì blob remote đã tồn tại.
/// (Trước đây lọc state `telegram-committed` — giá trị không bao giờ được set ở
/// production nên GC bỏ sót, spool rò rỉ.)
pub async fn remote_spool_chunks(db: &Db) -> Result<Vec<(String, i64, String)>, String> {
    use entities::chunks::Column as C;
    let conn = db.sea_conn();
    let out: Vec<(String, i64, String)> = entities::chunks::Entity::find()
        .select_only()
        .column(C::VersionId)
        .column(C::Idx)
        .column(C::SpoolPath)
        .filter(C::State.eq("remote"))
        .filter(C::SpoolPath.is_not_null())
        .into_tuple::<(String, i64, Option<String>)>()
        .all(&conn)
        .await
        .map_err(|e| format!("query map: {e}"))?
        .into_iter()
        .filter_map(|(v, i, s)| s.map(|s| (v, i, s)))
        .collect::<Vec<_>>();
    Ok(out)
}

/// Locator remote của chunk thuộc version đã xóa, KHÔNG bị Object Lock
/// retention/legal-hold bảo vệ. Join 3 bảng qua relations (version_id duy nhất
/// toàn cục nên 1:1).
pub async fn deletable_telegram_locators(
    db: &Db,
    now_iso: &str,
) -> Result<Vec<(String, i64, String)>, String> {
    use entities::chunks::Column as C;
    use entities::object_locks::Column as L;
    use entities::objects::Column as O;
    use sea_orm::Condition;
    let conn = db.sea_conn();
    let rows = entities::chunks::Entity::find()
        .select_only()
        .column(C::VersionId)
        .column(C::Idx)
        .column(C::RemoteLocatorJson)
        .join(
            JoinType::InnerJoin,
            entities::chunks::Relation::Objects.def(),
        )
        .join(
            JoinType::LeftJoin,
            entities::chunks::Relation::ObjectLocks.def(),
        )
        .filter(C::RemoteLocatorJson.is_not_null())
        .filter(O::IsDeleteMarker.eq(1))
        .filter(
            Condition::any()
                .add(L::LegalHold.is_null())
                .add(L::LegalHold.eq(0)),
        )
        .filter(
            Condition::any()
                .add(L::RetainUntilDate.is_null())
                .add(L::RetainUntilDate.lte(now_iso)),
        )
        .into_tuple::<(String, i64, Option<String>)>()
        .all(&conn)
        .await
        .map_err(|e| format!("query map locators: {e}"))?;
    let out: Vec<(String, i64, String)> = rows
        .into_iter()
        .filter_map(|(v, i, l)| l.map(|l| (v, i, l)))
        .collect();
    Ok(out)
}

/// Spool path của part mồ côi (upload đã abort/mất) + xóa rows mồ côi.
/// Trả số rows đã xóa.
pub async fn clean_orphan_multipart_parts(db: &Db) -> Result<usize, String> {
    use entities::multipart_parts::Column as P;
    use entities::multipart_uploads::Column as U;
    let conn = db.sea_conn();
    let spools: Vec<(Option<String>,)> = entities::multipart_parts::Entity::find()
        .select_only()
        .column(P::SpoolPath)
        .filter(P::SpoolPath.is_not_null())
        .join(
            JoinType::LeftJoin,
            entities::multipart_parts::Relation::Uploads.def(),
        )
        .filter(U::UploadId.is_null())
        .into_tuple()
        .all(&conn)
        .await
        .map_err(|e| format!("query map multipart clean: {e}"))?;
    for (s,) in &spools {
        if let Some(p) = s {
            let p = std::path::Path::new(p);
            if p.exists() {
                let _ = std::fs::remove_file(p);
            }
        }
    }
    // NOT IN subquery là SQL chuẩn, portable cả hai backend.
    let res = entities::multipart_parts::Entity::delete_many()
        .filter(Expr::cust(
            "upload_id NOT IN (SELECT upload_id FROM multipart_uploads)",
        ))
        .exec(&conn)
        .await
        .map_err(|e| format!("delete orphan parts: {e}"))?;
    Ok(res.rows_affected as usize)
}

/// Đọc verify spool: mọi chunk còn `spool_path` (kèm checksum + mode).
pub async fn spool_verify_rows(
    db: &Db,
) -> Result<Vec<(String, i64, String, String, String, String)>, String> {
    use entities::chunks::Column as C;
    let conn = db.sea_conn();
    let rows = entities::chunks::Entity::find()
        .select_only()
        .column(C::VersionId)
        .column(C::Idx)
        .column(C::SpoolPath)
        .column(C::PlaintextSha256)
        .column(C::CiphertextSha256)
        .column(C::EncryptionMode)
        .filter(C::SpoolPath.is_not_null())
        .into_tuple::<(String, i64, Option<String>, String, String, String)>()
        .all(&conn)
        .await
        .map_err(|e| format!("query verify spool: {e}"))?;
    let out: Vec<(String, i64, String, String, String, String)> = rows
        .into_iter()
        .filter_map(|(v, i, s, p, c, e)| s.map(|s| (v, i, s, p, c, e)))
        .collect();
    Ok(out)
}

/// Đọc scrub remote: mọi chunk còn `remote_locator_json`.
pub async fn remote_scrub_rows(db: &Db) -> Result<Vec<(String, i64, String)>, String> {
    use entities::chunks::Column as C;
    let conn = db.sea_conn();
    let rows = entities::chunks::Entity::find()
        .select_only()
        .column(C::VersionId)
        .column(C::Idx)
        .column(C::RemoteLocatorJson)
        .filter(C::RemoteLocatorJson.is_not_null())
        .into_tuple::<(String, i64, Option<String>)>()
        .all(&conn)
        .await
        .map_err(|e| format!("query scrub rows: {e}"))?;
    let out: Vec<(String, i64, String)> = rows
        .into_iter()
        .filter_map(|(v, i, l)| l.map(|l| (v, i, l)))
        .collect();
    Ok(out)
}

/// Xóa locator remote sau khi GC xóa message (best-effort, caller bỏ qua lỗi).
pub async fn clear_chunk_locator(db: &Db, version_id: &str, idx: i64) -> Result<(), String> {
    use entities::chunks::Column as C;
    let conn = db.sea_conn();
    entities::chunks::Entity::update_many()
        .col_expr(C::RemoteLocatorJson, Expr::value(None::<String>))
        .filter(C::VersionId.eq(version_id))
        .filter(C::Idx.eq(idx))
        .exec(&conn)
        .await
        .map_err(|e| format!("clear locator: {e}"))?;
    Ok(())
}

/// PRAGMA SQLite (intrinsic backend — giữ raw Statement trên sea_conn).
/// Trả chuỗi `integrity_check` ("ok" khi sạch).
pub async fn sqlite_integrity_check(db: &Db) -> Result<String, String> {
    use sea_orm::{ConnectionTrait, Statement};
    db.sea_conn()
        .query_one(Statement::from_string(
            sea_orm::DbBackend::Sqlite,
            "PRAGMA integrity_check".to_string(),
        ))
        .await
        .map_err(|e| format!("pragma: {e}"))?
        .ok_or_else(|| "pragma: no row".to_string())?
        .try_get("", "integrity_check")
        .map_err(|e| format!("pragma: {e}"))
}

/// PRAGMA foreign_key_check — danh sách "table ... rowid ..." vi phạm.
pub async fn sqlite_fk_violations(db: &Db) -> Result<Vec<String>, String> {
    use sea_orm::{ConnectionTrait, Statement};
    let rows = db
        .sea_conn()
        .query_all(Statement::from_string(
            sea_orm::DbBackend::Sqlite,
            "PRAGMA foreign_key_check".to_string(),
        ))
        .await
        .map_err(|e| format!("pragma: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        let t: String = r.try_get("", "table").map_err(|e| format!("pragma: {e}"))?;
        let id: i64 = r.try_get("", "rowid").map_err(|e| format!("pragma: {e}"))?;
        out.push(format!("table {t} rowid {id}"));
    }
    Ok(out)
}

/// Đếm (buckets, objects, chunks) cho doctor.
pub async fn table_counts(db: &Db) -> (i64, i64, i64) {
    use sea_orm::{EntityTrait, PaginatorTrait};
    let conn = db.sea_conn();
    let b = entities::buckets::Entity::find()
        .count(&conn)
        .await
        .unwrap_or(0) as i64;
    let o = entities::objects::Entity::find()
        .count(&conn)
        .await
        .unwrap_or(0) as i64;
    let c = entities::chunks::Entity::find()
        .count(&conn)
        .await
        .unwrap_or(0) as i64;
    (b, o, c)
}

// Bucket Policy
pub async fn set_bucket_policy(db: &Db, bucket: &str, policy_json: &str) -> Result<(), String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let now = now_str();
    let conn = db.sea_conn();
    entities::bucket_policies::Entity::insert(entities::bucket_policies::ActiveModel {
        bucket: Set(bucket.to_string()),
        policy_json: Set(policy_json.to_string()),
        updated_at: Set(now),
    })
    .on_conflict(
        OnConflict::columns([entities::bucket_policies::Column::Bucket])
            .update_columns([
                entities::bucket_policies::Column::PolicyJson,
                entities::bucket_policies::Column::UpdatedAt,
            ])
            .to_owned(),
    )
    .exec(&conn)
    .await
    .map_err(|e| format!("set bucket policy: {e}"))?;
    Ok(())
}

pub async fn get_bucket_policy(db: &Db, bucket: &str) -> Result<Option<String>, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let conn = db.sea_conn();
    entities::bucket_policies::Entity::find_by_id(bucket)
        .one(&conn)
        .await
        .map_err(|e| format!("query get bucket policy: {e}"))
        .map(|m| m.map(|m| m.policy_json))
}

pub async fn delete_bucket_policy(db: &Db, bucket: &str) -> Result<bool, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let conn = db.sea_conn();
    let res = entities::bucket_policies::Entity::delete_by_id(bucket)
        .exec(&conn)
        .await
        .map_err(|e| format!("delete bucket policy: {e}"))?;
    Ok(res.rows_affected > 0)
}

// Bucket CORS
pub async fn set_bucket_cors(db: &Db, bucket: &str, cors_json: &str) -> Result<(), String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let now = now_str();
    let conn = db.sea_conn();
    entities::bucket_cors::Entity::insert(entities::bucket_cors::ActiveModel {
        bucket: Set(bucket.to_string()),
        cors_json: Set(cors_json.to_string()),
        updated_at: Set(now),
    })
    .on_conflict(
        OnConflict::columns([entities::bucket_cors::Column::Bucket])
            .update_columns([
                entities::bucket_cors::Column::CorsJson,
                entities::bucket_cors::Column::UpdatedAt,
            ])
            .to_owned(),
    )
    .exec(&conn)
    .await
    .map_err(|e| format!("set bucket cors: {e}"))?;
    Ok(())
}

pub async fn get_bucket_cors(db: &Db, bucket: &str) -> Result<Option<String>, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let conn = db.sea_conn();
    entities::bucket_cors::Entity::find_by_id(bucket)
        .one(&conn)
        .await
        .map_err(|e| format!("query get bucket cors: {e}"))
        .map(|m| m.map(|m| m.cors_json))
}

pub async fn delete_bucket_cors(db: &Db, bucket: &str) -> Result<bool, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let conn = db.sea_conn();
    let res = entities::bucket_cors::Entity::delete_by_id(bucket)
        .exec(&conn)
        .await
        .map_err(|e| format!("delete bucket cors: {e}"))?;
    Ok(res.rows_affected > 0)
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
    let conn = db.sea_conn();
    entities::bucket_bpa::Entity::insert(entities::bucket_bpa::ActiveModel {
        bucket: Set(bucket.to_string()),
        block_public_acls: Set(bpa.block_public_acls as i64),
        ignore_public_acls: Set(bpa.ignore_public_acls as i64),
        block_public_policy: Set(bpa.block_public_policy as i64),
        restrict_public_buckets: Set(bpa.restrict_public_buckets as i64),
        updated_at: Set(now),
    })
    .on_conflict(
        OnConflict::columns([entities::bucket_bpa::Column::Bucket])
            .update_columns([
                entities::bucket_bpa::Column::BlockPublicAcls,
                entities::bucket_bpa::Column::IgnorePublicAcls,
                entities::bucket_bpa::Column::BlockPublicPolicy,
                entities::bucket_bpa::Column::RestrictPublicBuckets,
                entities::bucket_bpa::Column::UpdatedAt,
            ])
            .to_owned(),
    )
    .exec(&conn)
    .await
    .map_err(|e| format!("set bucket bpa: {e}"))?;
    Ok(())
}

pub async fn get_bucket_bpa(db: &Db, bucket: &str) -> Result<BucketBpa, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let conn = db.sea_conn();
    let row = entities::bucket_bpa::Entity::find_by_id(bucket)
        .one(&conn)
        .await
        .map_err(|e| format!("query get bucket bpa: {e}"))?;
    match row {
        Some(m) => Ok(BucketBpa {
            block_public_acls: m.block_public_acls != 0,
            ignore_public_acls: m.ignore_public_acls != 0,
            block_public_policy: m.block_public_policy != 0,
            restrict_public_buckets: m.restrict_public_buckets != 0,
        }),
        None => Ok(BucketBpa::default()),
    }
}

pub async fn delete_bucket_bpa(db: &Db, bucket: &str) -> Result<bool, String> {
    if !head_bucket(db, bucket).await? {
        return Err("NoSuchBucket".to_string());
    }
    let conn = db.sea_conn();
    let res = entities::bucket_bpa::Entity::delete_by_id(bucket)
        .exec(&conn)
        .await
        .map_err(|e| format!("delete bucket bpa: {e}"))?;
    Ok(res.rows_affected > 0)
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
    let conn = db.sea_conn();
    entities::bucket_lock_configs::Entity::insert(entities::bucket_lock_configs::ActiveModel {
        bucket: Set(bucket.to_string()),
        status: Set(cfg.status.clone()),
        default_retention_mode: Set(cfg.default_retention_mode.clone()),
        default_retention_days: Set(cfg.default_retention_days.map(|d| d as i64)),
        updated_at: Set(now),
    })
    .on_conflict(
        OnConflict::columns([entities::bucket_lock_configs::Column::Bucket])
            .update_columns([
                entities::bucket_lock_configs::Column::Status,
                entities::bucket_lock_configs::Column::DefaultRetentionMode,
                entities::bucket_lock_configs::Column::DefaultRetentionDays,
                entities::bucket_lock_configs::Column::UpdatedAt,
            ])
            .to_owned(),
    )
    .exec(&conn)
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
    let conn = db.sea_conn();
    let row = entities::bucket_lock_configs::Entity::find_by_id(bucket)
        .one(&conn)
        .await
        .map_err(|e| format!("query get bucket lock config: {e}"))?;
    match row {
        Some(m) => Ok(Some(ObjectLockConfig {
            status: m.status,
            default_retention_mode: m.default_retention_mode,
            // Cột BIGINT nhưng struct giữ i32 như cũ.
            default_retention_days: m
                .default_retention_days
                .map(|d| {
                    i32::try_from(d).map_err(|_| {
                        "row bucket lock config: default_retention_days out of i32 range"
                            .to_string()
                    })
                })
                .transpose()?,
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
    let conn = db.sea_conn();
    entities::object_locks::Entity::insert(entities::object_locks::ActiveModel {
        bucket: Set(bucket.to_string()),
        key: Set(key.to_string()),
        version_id: Set(version_id.to_string()),
        retain_until_date: Set(Some(retain_until_date.to_string())),
        mode: Set(Some(mode.to_string())),
        legal_hold: Set(0),
        updated_at: Set(now),
    })
    .on_conflict(
        OnConflict::columns([
            entities::object_locks::Column::Bucket,
            entities::object_locks::Column::Key,
            entities::object_locks::Column::VersionId,
        ])
        .update_columns([
            entities::object_locks::Column::RetainUntilDate,
            entities::object_locks::Column::Mode,
            entities::object_locks::Column::UpdatedAt,
        ])
        .to_owned(),
    )
    .exec(&conn)
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
    let conn = db.sea_conn();
    let row = entities::object_locks::Entity::find()
        .filter(entities::object_locks::Column::Bucket.eq(bucket))
        .filter(entities::object_locks::Column::Key.eq(key))
        .filter(entities::object_locks::Column::VersionId.eq(version_id))
        .filter(entities::object_locks::Column::Mode.is_not_null())
        .one(&conn)
        .await
        .map_err(|e| format!("query get object retention: {e}"))?;
    match row {
        Some(m) => match (m.mode, m.retain_until_date) {
            (Some(mode), Some(retain_until_date)) => Ok(Some(ObjectRetention {
                mode,
                retain_until_date,
            })),
            _ => Ok(None),
        },
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
    let conn = db.sea_conn();
    entities::object_locks::Entity::insert(entities::object_locks::ActiveModel {
        bucket: Set(bucket.to_string()),
        key: Set(key.to_string()),
        version_id: Set(version_id.to_string()),
        retain_until_date: Set(None),
        mode: Set(None),
        legal_hold: Set(on as i64),
        updated_at: Set(now),
    })
    .on_conflict(
        OnConflict::columns([
            entities::object_locks::Column::Bucket,
            entities::object_locks::Column::Key,
            entities::object_locks::Column::VersionId,
        ])
        .update_columns([
            entities::object_locks::Column::LegalHold,
            entities::object_locks::Column::UpdatedAt,
        ])
        .to_owned(),
    )
    .exec(&conn)
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
    let conn = db.sea_conn();
    let row = entities::object_locks::Entity::find()
        .filter(entities::object_locks::Column::Bucket.eq(bucket))
        .filter(entities::object_locks::Column::Key.eq(key))
        .filter(entities::object_locks::Column::VersionId.eq(version_id))
        .one(&conn)
        .await
        .map_err(|e| format!("query get object legal hold: {e}"))?;
    match row {
        Some(m) => Ok(m.legal_hold != 0),
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
        apply_migration(&db, 5, MIGRATION_005).await.unwrap();
        assert_eq!(schema_version(&db).await.unwrap(), 5);
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
        // Bảng/cột chết phải được DROP ở migration 0005 (CREATE ở 0001 vẫn còn
        // trong text nối — kiểm tra statement DROP thay vì vắng mặt CREATE).
        for gone_table in ["recovery_checkpoints", "kv"] {
            assert!(
                PG_MIGRATION_005.contains(&format!("DROP TABLE IF EXISTS {gone_table}")),
                "0005 must drop dead table {gone_table}"
            );
        }
        for gone_col in [
            "DROP COLUMN IF EXISTS nonce",
            "DROP COLUMN IF EXISTS \"offset\"",
            "DROP COLUMN IF EXISTS encryption_override",
            "DROP COLUMN IF EXISTS generation",
            "DROP COLUMN IF EXISTS remote_locator_json",
            "DROP COLUMN IF EXISTS state",
        ] {
            assert!(
                PG_MIGRATION_005.contains(gone_col),
                "0005 must contain {gone_col}"
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

    /// Mô phỏng nâng cấp production v4 → 5: DB cũ có dữ liệu + bảng chết,
    /// apply_all_migrations phải lên 5, giữ dữ liệu, xóa đúng schema thừa.
    #[tokio::test]
    async fn migration_0005_upgrades_v4_db_keeps_data() {
        use sea_orm::{ConnectionTrait, Statement};
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("v4.db");
        let db = Db::open_sqlite(db_path.to_str().unwrap()).await.unwrap();
        // Dừng ở version 4 như production beta.7.
        apply_migration(&db, 1, MIGRATION_001).await.unwrap();
        apply_migration(&db, 2, MIGRATION_002).await.unwrap();
        apply_migration(&db, 3, MIGRATION_003).await.unwrap();
        apply_migration(&db, 4, MIGRATION_004).await.unwrap();
        assert_eq!(schema_version(&db).await.unwrap(), 4);

        create_bucket(&db, "up-bkt", "us-east-1").await.unwrap();
        // Ghi dữ liệu bằng đúng schema v4 (gồm cột `offset` sắp bị xóa) —
        // mô phỏng DB production do binary beta.7 ghi.
        db.sea_conn()
            .execute_unprepared(
                "INSERT INTO objects(bucket, key, version_id, is_delete_marker, storage_state, size, etag, content_type) \
                 VALUES ('up-bkt', 'k', 'v1', 0, 'accepted-local', 3, 'etag', 'text/plain')",
            )
            .await
            .unwrap();
        db.sea_conn()
            .execute_unprepared(
                "INSERT INTO chunks(version_id, idx, \"offset\", length, plaintext_sha256, ciphertext_sha256, encryption_mode, spool_path, state) \
                 VALUES ('v1', 0, 0, 3, 'p', 'c', 'none', 'spool/x.chunk', 'pending')",
            )
            .await
            .unwrap();
        db.sea_conn()
            .execute_unprepared(
                "INSERT INTO upload_jobs(job_id, version_id, state) VALUES ('job-up', 'v1', 'pending')",
            )
            .await
            .unwrap();
        // Hàng trong bảng chết (sẽ bị DROP cùng bảng).
        db.sea_conn()
            .execute_unprepared("INSERT INTO kv(key, value) VALUES ('a', 'b')")
            .await
            .unwrap();

        // Nâng cấp: chỉ apply đúng delta 4 → 5.
        assert_eq!(apply_all_migrations(&db).await.unwrap(), 5);
        assert_eq!(schema_version(&db).await.unwrap(), 5);

        // Dữ liệu thật còn nguyên, đọc được qua DAL mới.
        assert!(head_bucket(&db, "up-bkt").await.unwrap());
        let v = latest_version(&db, "up-bkt", "k").await.unwrap().unwrap();
        assert_eq!(v.version_id, "v1");
        assert_eq!(v.size, 3);
        let (jobs, _) = list_jobs(&db).await.unwrap();
        assert_eq!(jobs.len(), 1);

        // Bảng chết đã mất.
        let tables: Vec<String> = db
            .sea_conn()
            .query_all(Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                "SELECT name AS name FROM sqlite_master WHERE type = 'table'".to_string(),
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.try_get::<String>("", "name").unwrap())
            .collect();
        assert!(!tables
            .iter()
            .any(|t| t == "kv" || t == "recovery_checkpoints"));

        // Cột chết đã mất, cột sống còn đủ.
        let cols: Vec<String> = db
            .sea_conn()
            .query_all(Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                "SELECT name AS name FROM pragma_table_info('chunks')".to_string(),
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.try_get::<String>("", "name").unwrap())
            .collect();
        for gone in ["nonce", "offset"] {
            assert!(
                !cols.iter().any(|c| c == gone),
                "column chunks.{gone} should be gone"
            );
        }
        for kept in [
            "version_id",
            "idx",
            "length",
            "spool_path",
            "remote_locator_json",
            "state",
        ] {
            assert!(
                cols.iter().any(|c| c == kept),
                "column chunks.{kept} must survive"
            );
        }

        // Index mới cho worker claim poll.
        let idx: Vec<String> = db
            .sea_conn()
            .query_all(Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                "SELECT name AS name FROM sqlite_master WHERE type = 'index' AND name = 'idx_upload_jobs_state_next'".to_string(),
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.try_get::<String>("", "name").unwrap())
            .collect();
        assert_eq!(idx.len(), 1);
    }

    #[tokio::test]
    async fn pragmas_wal_fk_busy_timeout() {
        let (_d, db) = test_db().await;
        // WAL mode kiểm tra qua sea Statement (PRAGMA là intrinsic SQLite).
        use sea_orm::{ConnectionTrait, Statement};
        let journal: String = db
            .sea_conn()
            .query_one(Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                "PRAGMA journal_mode".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "journal_mode")
            .unwrap();
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
        put_object(
            &db,
            "bucket-2",
            "k",
            "v1",
            0,
            "",
            "application/octet-stream",
            None,
            None,
            &[],
            "job-notempty",
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

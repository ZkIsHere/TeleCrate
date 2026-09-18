//! Config TeleCrate — validate trước apply, biết trường nào cần restart.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Một access key S3 (danh sách tĩnh M2; phân quyền prefix → M4).
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessKey {
    pub access_key_id: String,
    /// Secret dùng kiểm HMAC — không bao giờ log/in. File config phải 0600.
    pub secret_key: String,
}

impl fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessKey")
            .field("access_key_id", &self.access_key_id)
            .field("secret_key", &"***")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Đường dẫn SQLite index. Thay đổi cần restart.
    pub db_path: String,
    /// Thư mục spool. Thay đổi cần restart.
    pub spool_dir: String,
    /// Backend metadata DB: "sqlite" (default, duy nhất runnable) | "postgres"
    /// (partial — xem ADR 0005). Thay đổi cần restart + migrate dữ liệu thủ công.
    #[serde(default = "default_db_backend")]
    pub db_backend: String,
    /// Connection string Postgres, chỉ dùng khi db_backend="postgres".
    /// Chứa password — redact mọi nơi như bot token. None = không dùng.
    #[serde(default)]
    pub database_url: Option<String>,
    /// Port HTTP S3 + admin + dashboard. Thay đổi cần restart.
    pub listen_port: u16,
    /// Mã hóa nội dung: "off" | "on". Chỉ áp dụng ghi mới; dữ liệu cũ giữ chế độ cũ.
    pub encryption: String,
    /// Access keys tĩnh (M2). Thay đổi cần restart/reload.
    #[serde(default)]
    pub access_keys: Vec<AccessKey>,
    /// Bot token Telegram cho worker upload (M2.2+). Rỗng = worker idle.
    #[serde(default)]
    pub telegram_bot_token: String,
    /// Chat id nhận blob (group/channel test). 0 = worker idle.
    #[serde(default)]
    pub telegram_chat_id: i64,
    /// Kích thước chunk upload Telegram (bytes). Mặc định 8 MiB (dưới ngưỡng download 20 MB).
    #[serde(default = "default_chunk_size")]
    pub chunk_size_bytes: usize,
    /// Số worker upload đồng thời (lease atomic nên an toàn). 1..=8.
    #[serde(default = "default_worker_concurrency")]
    pub worker_concurrency: usize,
    /// Danh sách khóa mã hóa nội dung (file 32 bytes thô, quyền 0600). Chỉ đường dẫn vào config.
    #[serde(default)]
    pub content_keys: Vec<ContentKeyRef>,
    /// Key id dùng cho ghi mới (rỗng = key đầu tiên). Đổi id = rotation cho ghi mới.
    #[serde(default)]
    pub content_key_id: String,
    /// Mật khẩu đăng nhập Web Dashboard & Admin API (tùy chọn).
    #[serde(default)]
    pub admin_password: Option<String>,
    /// Mức log daemon: trace|debug|info|warn|error (áp dụng cả stdout và file).
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Ghi log ra file daily-rotation (giữ stdout cho journald trong mọi trường hợp).
    #[serde(default)]
    pub log_to_file: bool,
    /// Thư mục log file. Thay đổi cần restart.
    #[serde(default = "default_log_dir")]
    pub log_dir: String,
    /// Giữ file log N ngày gần nhất, xóa file cũ hơn ở startup.
    #[serde(default = "default_log_retention")]
    pub log_retention_days: u64,
}

/// Một khóa mã hóa: chỉ id + đường dẫn file (không bao giờ chứa key material).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContentKeyRef {
    pub id: String,
    pub file: String,
}

fn default_chunk_size() -> usize {
    8 * 1024 * 1024
}

fn default_db_backend() -> String {
    "sqlite".to_string()
}

fn default_worker_concurrency() -> usize {
    2
}

/// Nhãn region mặc định cho bucket tạo không kèm LocationConstraint.
/// Server SigV4 chấp nhận mọi region (auto-region); nhãn này chỉ để hiển thị/GetBucketLocation.
pub const DEFAULT_REGION: &str = "us-east-1";

/// Base URL Bot API Telegram (cố định hosted; Local Bot API tính sau, không cấu hình).
pub const TELEGRAM_API_BASE: &str = "https://api.telegram.org";

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_dir() -> String {
    "/var/lib/telecrate/logs".to_string()
}

fn default_log_retention() -> u64 {
    14
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("db_path", &self.db_path)
            .field("spool_dir", &self.spool_dir)
            .field("db_backend", &self.db_backend)
            .field("database_url", &self.database_url.as_ref().map(|_| "***"))
            .field("listen_port", &self.listen_port)
            .field("encryption", &self.encryption)
            .field("access_keys", &self.access_keys)
            .field("telegram_bot_token", &"***")
            .field("telegram_chat_id", &self.telegram_chat_id)
            .field("chunk_size_bytes", &self.chunk_size_bytes)
            .field("worker_concurrency", &self.worker_concurrency)
            // content_keys chỉ chứa id + đường dẫn file (không có key material).
            .field("content_keys", &self.content_keys)
            .field("content_key_id", &self.content_key_id)
            .field("log_level", &self.log_level)
            .field("log_to_file", &self.log_to_file)
            .field("log_dir", &self.log_dir)
            .field("log_retention_days", &self.log_retention_days)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: "/var/lib/telecrate/index.db".to_string(),
            spool_dir: "/var/lib/telecrate/spool".to_string(),
            db_backend: default_db_backend(),
            database_url: None,
            listen_port: 7070,
            encryption: "off".to_string(),
            access_keys: Vec::new(),
            telegram_bot_token: String::new(),
            telegram_chat_id: 0,
            chunk_size_bytes: default_chunk_size(),
            worker_concurrency: default_worker_concurrency(),
            content_keys: Vec::new(),
            content_key_id: String::new(),
            admin_password: None,
            log_level: default_log_level(),
            log_to_file: false,
            log_dir: default_log_dir(),
            log_retention_days: default_log_retention(),
        }
    }
}

impl Config {
    /// Cập nhật giá trị cấu hình theo key string từ CLI hoặc Admin API.
    pub fn update_key(&mut self, key: &str, val: &str) -> Result<(), String> {
        self.apply_key(key, val)?;
        validate(self)?;
        Ok(())
    }

    /// Gán field theo key mà KHÔNG validate — dùng cho batch apply nhiều key
    /// rồi validate 1 lần (đổi db_backend cần backend+URL cùng lúc; validate
    /// từng key riêng lẻ sẽ kẹt ở trạng thái trung gian không hợp lệ).
    pub fn apply_key(&mut self, key: &str, val: &str) -> Result<(), String> {
        match key {
            "listen_port" => {
                self.listen_port = val
                    .parse::<u16>()
                    .map_err(|_| "invalid listen_port".to_string())?;
            }
            "encryption" => {
                if val != "off" && val != "on" {
                    return Err("encryption must be 'off' or 'on'".to_string());
                }
                self.encryption = val.to_string();
            }
            "admin_password" => {
                self.admin_password = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                };
            }
            "telegram_bot_token" => {
                self.telegram_bot_token = val.to_string();
            }
            "telegram_chat_id" => {
                self.telegram_chat_id = val
                    .parse::<i64>()
                    .map_err(|_| "invalid telegram_chat_id".to_string())?;
            }
            "chunk_size_bytes" => {
                self.chunk_size_bytes = val
                    .parse::<usize>()
                    .map_err(|_| "invalid chunk_size_bytes".to_string())?;
            }
            "worker_concurrency" => {
                self.worker_concurrency = val
                    .parse::<usize>()
                    .map_err(|_| "invalid worker_concurrency".to_string())?;
            }
            "db_path" => {
                self.db_path = val.to_string();
            }
            "spool_dir" => {
                self.spool_dir = val.to_string();
            }
            "db_backend" => {
                if val != "sqlite" && val != "postgres" {
                    return Err("db_backend must be 'sqlite' or 'postgres'".to_string());
                }
                self.db_backend = val.to_string();
            }
            "database_url" => {
                self.database_url = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                };
            }
            _ => return Err(format!("unknown config key: '{key}'")),
        }
        Ok(())
    }

    /// Lưu cấu hình hiện tại trở lại file TOML mà không cần rebuild binary.
    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let toml_str =
            toml::to_string_pretty(self).map_err(|e| format!("serialize config: {e}"))?;
        std::fs::write(path, toml_str).map_err(|e| format!("write config {path}: {e}"))?;
        Ok(())
    }

    /// Tìm secret theo access key id (so sánh hằng thời gian ở tầng SigV4).
    pub fn find_secret(&self, access_key_id: &str) -> Option<&str> {
        self.access_keys
            .iter()
            .find(|k| k.access_key_id == access_key_id)
            .map(|k| k.secret_key.as_str())
    }

    /// Key id dùng cho ghi mới: cấu hình hoặc key đầu tiên.
    pub fn write_key_id(&self) -> Option<&str> {
        if !self.content_key_id.is_empty() {
            return Some(&self.content_key_id);
        }
        self.content_keys.first().map(|k| k.id.as_str())
    }

    /// Nạp KeyStore từ file (gọi ngoài async context, 1 lần ở startup).
    pub fn load_keystore(&self) -> Result<crate::crypto::KeyStore, String> {
        let pairs: Vec<(String, String)> = self
            .content_keys
            .iter()
            .map(|k| (k.id.clone(), k.file.clone()))
            .collect();
        crate::crypto::KeyStore::load(&pairs).map_err(|e| format!("content keys: {e}"))
    }
}

/// Đọc file TOML và validate. Không bao giờ in secret ra log.
pub fn load(path: &str) -> anyhow::Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read config {path}: {e}"))?;
    let cfg: Config = toml::from_str(&text).map_err(|e| format!("parse config {path}: {e}"))?;
    validate(&cfg)?;
    Ok(cfg)
}

pub fn validate(cfg: &Config) -> Result<(), String> {
    if cfg.listen_port == 0 {
        return Err("listen_port must be > 0".to_string());
    }
    if cfg.db_path.is_empty() || cfg.spool_dir.is_empty() {
        return Err("db_path/spool_dir must not be empty".to_string());
    }
    // Spool/DB/log là đường dẫn local daemon ghi trực tiếp: bắt buộc absolute,
    // cấm `..` để chặn traversal/confusion. Đổi spool_dir chỉ có hiệu lực sau restart
    // (S3 foreground clone config lúc startup, worker đọc lock động) nên dashboard
    // đánh dấu ⟳ restart; file spool pending cũ không tự migrate.
    // Note: chấp nhận cả Unix-absolute (`/...`) khi chạy test trên Windows
    // (production là Linux native; `Path::is_absolute` trên Windows từ chối `/...`).
    for (name, p) in [
        ("db_path", cfg.db_path.as_str()),
        ("spool_dir", cfg.spool_dir.as_str()),
        ("log_dir", cfg.log_dir.as_str()),
    ] {
        let path = std::path::Path::new(p);
        if !(path.is_absolute() || p.starts_with('/')) {
            return Err(format!("{name} must be an absolute path"));
        }
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(format!("{name} must not contain '..'"));
        }
    }
    // Backend DB (ADR 0005): sqlite = runnable duy nhất; postgres = partial
    // (chọn + schema xong, query port blocked). sqlite cấm database_url để
    // tránh secret mồ côi trong file config gây hiểu nhầm.
    match cfg.db_backend.as_str() {
        "sqlite" => {
            if cfg.database_url.as_ref().is_some_and(|u| !u.is_empty()) {
                return Err("database_url must be empty when db_backend='sqlite'".to_string());
            }
        }
        "postgres" => match cfg.database_url.as_deref() {
            Some(u) if u.starts_with("postgres://") || u.starts_with("postgresql://") => {}
            _ => {
                return Err(
                    "db_backend='postgres' requires database_url starting with 'postgres://' or 'postgresql://'"
                        .to_string(),
                );
            }
        },
        _ => return Err("db_backend must be 'sqlite' or 'postgres'".to_string()),
    }
    if cfg.encryption != "off" && cfg.encryption != "on" {
        return Err("encryption must be 'off' or 'on'".to_string());
    }
    // Chunk vừa đủ nhỏ để getFile tải lại 1 lần (< 20 MB Bot API), vừa đủ lớn để ít message.
    if !(256 * 1024..=16 * 1024 * 1024).contains(&cfg.chunk_size_bytes) {
        return Err("chunk_size_bytes must be 256 KiB..16 MiB".to_string());
    }
    if !(1..=8).contains(&cfg.worker_concurrency) {
        return Err("worker_concurrency must be 1..=8".to_string());
    }
    // Content keys: id duy nhất, file phải có path; nội dung file kiểm khi load KeyStore.
    {
        let mut seen_keys = std::collections::HashSet::new();
        for k in &cfg.content_keys {
            if k.id.is_empty() || k.file.is_empty() {
                return Err("content_keys entries must have non-empty id and file".to_string());
            }
            if !seen_keys.insert(k.id.as_str()) {
                return Err(format!("duplicate content key id: {}", k.id));
            }
        }
        if cfg.encryption == "on" {
            if cfg.content_keys.is_empty() {
                return Err(
                    "encryption=on cần ít nhất một [[content_keys]] (file 32 bytes)".to_string(),
                );
            }
            if !cfg.content_key_id.is_empty()
                && !cfg.content_keys.iter().any(|k| k.id == cfg.content_key_id)
            {
                return Err(format!(
                    "content_key_id '{}' không có trong content_keys",
                    cfg.content_key_id
                ));
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    for k in &cfg.access_keys {
        if k.access_key_id.is_empty() || k.secret_key.is_empty() {
            return Err("access_keys entries must have non-empty id and secret".to_string());
        }
        if !seen.insert(k.access_key_id.as_str()) {
            return Err(format!("duplicate access_key_id: {}", k.access_key_id));
        }
    }
    match cfg.log_level.as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => {}
        _ => return Err("log_level must be trace|debug|info|warn|error".to_string()),
    }
    if cfg.log_to_file && cfg.log_dir.is_empty() {
        return Err("log_dir must not be empty when log_to_file is true".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        validate(&Config::default()).unwrap();
    }

    #[test]
    fn rejects_bad_encryption() {
        let c = Config {
            encryption: "aes-quantum".to_string(),
            ..Config::default()
        };
        assert!(validate(&c).is_err());
    }

    #[test]
    fn rejects_duplicate_or_empty_keys() {
        let c = Config {
            access_keys: vec![
                AccessKey {
                    access_key_id: "AK".to_string(),
                    secret_key: "s".to_string(),
                },
                AccessKey {
                    access_key_id: "AK".to_string(),
                    secret_key: "s2".to_string(),
                },
            ],
            ..Config::default()
        };
        assert!(validate(&c).is_err());
        let c2 = Config {
            access_keys: vec![
                AccessKey {
                    access_key_id: "AK".to_string(),
                    secret_key: "s".to_string(),
                },
                AccessKey {
                    access_key_id: "AK2".to_string(),
                    secret_key: String::new(),
                },
            ],
            ..Config::default()
        };
        assert!(validate(&c2).is_err());
    }

    #[test]
    fn debug_redacts_secrets() {
        let c = Config {
            access_keys: vec![AccessKey {
                access_key_id: "AKID".to_string(),
                secret_key: "SUPER-SECRET".to_string(),
            }],
            telegram_bot_token: "BOT-TOKEN-XYZ".to_string(),
            ..Config::default()
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("AKID"));
        assert!(!dbg.contains("SUPER-SECRET"), "secret leaked: {dbg}");
        assert!(!dbg.contains("BOT-TOKEN-XYZ"), "token leaked: {dbg}");
    }

    #[test]
    fn sample_config_parses() {
        let text = std::fs::read_to_string("configs/telecrate.example.toml").unwrap();
        let cfg: Config = toml::from_str(&text).unwrap();
        validate(&cfg).unwrap();
        assert_eq!(DEFAULT_REGION, "us-east-1");
    }

    #[test]
    fn packaging_sample_config_parses() {
        let text = std::fs::read_to_string("packaging/telecrate.sample.toml").unwrap();
        let cfg: Config = toml::from_str(&text).unwrap();
        validate(&cfg).unwrap();
        assert_eq!(cfg.log_level, "info");
        assert!(!cfg.log_to_file);
    }

    #[test]
    fn db_backend_selection_validates() {
        // Mặc định sqlite, không URL.
        assert!(validate(&Config::default()).is_ok());
        // Backend lạ (literal vì update_key từ chối ngay).
        let c = Config {
            db_backend: "mysql".to_string(),
            ..Config::default()
        };
        assert!(validate(&c).is_err());
        assert!(Config::default().update_key("db_backend", "mysql").is_err());
        // sqlite + URL mồ côi → lỗi.
        let c = Config {
            database_url: Some("postgresql://u:p@h:5432/db".to_string()),
            ..Config::default()
        };
        assert!(validate(&c).is_err());
        // postgres thiếu URL / sai scheme → lỗi.
        let c = Config {
            db_backend: "postgres".to_string(),
            ..Config::default()
        };
        assert!(validate(&c).is_err());
        let c = Config {
            db_backend: "postgres".to_string(),
            database_url: Some("mysql://h/db".to_string()),
            ..Config::default()
        };
        assert!(validate(&c).is_err());
        // postgres + URL đúng → qua validate config (runtime vẫn blocked — ADR 0005).
        let mut c = Config {
            db_backend: "postgres".to_string(),
            database_url: Some("postgresql://u:p@h:5432/db".to_string()),
            ..Config::default()
        };
        assert!(validate(&c).is_ok());
        // Xóa URL bằng chuỗi rỗng qua update_key khi đã về sqlite.
        c.apply_key("database_url", "").unwrap();
        c.apply_key("db_backend", "sqlite").unwrap();
        assert!(validate(&c).is_ok());
        assert!(c.database_url.is_none());
        // Debug không lộ URL.
        c.apply_key("database_url", "postgresql://u:s3cret@h/db")
            .unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("s3cret"), "url leaked: {dbg}");
    }

    #[test]
    fn db_backend_switch_needs_atomic_batch() {
        // Đổi sqlite→postgres phải apply backend+URL rồi validate 1 lần:
        // update_key từng key riêng lẻ kẹt ở trạng thái trung gian.
        let mut staged = Config::default();
        assert!(staged.update_key("db_backend", "postgres").is_err());
        staged.apply_key("db_backend", "postgres").unwrap();
        staged
            .apply_key("database_url", "postgresql://u:p@h:5432/db")
            .unwrap();
        assert!(validate(&staged).is_ok());
        // Chiều ngược lại: xóa URL rồi về sqlite, validate 1 lần.
        staged.apply_key("database_url", "").unwrap();
        staged.apply_key("db_backend", "sqlite").unwrap();
        assert!(validate(&staged).is_ok());
        // Unknown key vẫn lỗi ngay ở apply.
        assert!(staged.apply_key("nope", "x").is_err());
    }

    #[test]
    fn storage_paths_must_be_absolute_without_dotdot() {
        let rel = Config {
            spool_dir: "var/lib/telecrate/spool".to_string(),
            ..Config::default()
        };
        assert!(validate(&rel).is_err());
        let dotdot = Config {
            spool_dir: "/var/lib/telecrate/../etc".to_string(),
            ..Config::default()
        };
        assert!(validate(&dotdot).is_err());
        let ok = Config {
            spool_dir: "/mnt/data/telecrate-spool".to_string(),
            ..Config::default()
        };
        assert!(validate(&ok).is_ok());
    }

    #[test]
    fn encryption_on_requires_keys() {
        let c = Config {
            encryption: "on".to_string(),
            ..Config::default()
        };
        assert!(validate(&c).is_err());
        let c = Config {
            encryption: "on".to_string(),
            content_keys: vec![ContentKeyRef {
                id: "k1".into(),
                file: "/tmp/k1.key".into(),
            }],
            content_key_id: "ghost".into(),
            ..Config::default()
        };
        assert!(validate(&c).is_err());
    }
}

// `anyhow` không có trong deps M0 — dùng String error để giữ ít thành phần.
// Cung cấp alias tương thích tối thiểu:
mod anyhow {
    pub type Result<T, E = String> = std::result::Result<T, E>;
}

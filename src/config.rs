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
    /// Port HTTP S3 + admin + dashboard. Thay đổi cần restart.
    pub listen_port: u16,
    /// Mã hóa nội dung: "off" | "on". Chỉ áp dụng ghi mới; dữ liệu cũ giữ chế độ cũ.
    pub encryption: String,
    /// Region phục vụ SigV4 scope. Thay đổi cần restart.
    #[serde(default = "default_region")]
    pub region: String,
    /// Access keys tĩnh (M2). Thay đổi cần restart/reload.
    #[serde(default)]
    pub access_keys: Vec<AccessKey>,
    /// Bot token Telegram cho worker upload (M2.2+). Rỗng = worker idle.
    #[serde(default)]
    pub telegram_bot_token: String,
    /// Chat id nhận blob (group/channel test). 0 = worker idle.
    #[serde(default)]
    pub telegram_chat_id: i64,
    /// Base URL Bot API (mặc định hosted; Local Bot API tự host khi cần).
    #[serde(default = "default_telegram_base")]
    pub telegram_base_url: String,
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

fn default_worker_concurrency() -> usize {
    2
}

fn default_telegram_base() -> String {
    "https://api.telegram.org".to_string()
}

fn default_region() -> String {
    "*".to_string()
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("db_path", &self.db_path)
            .field("spool_dir", &self.spool_dir)
            .field("listen_port", &self.listen_port)
            .field("encryption", &self.encryption)
            .field("region", &self.region)
            .field("access_keys", &self.access_keys)
            .field("telegram_bot_token", &"***")
            .field("telegram_chat_id", &self.telegram_chat_id)
            .field("telegram_base_url", &self.telegram_base_url)
            .field("chunk_size_bytes", &self.chunk_size_bytes)
            .field("worker_concurrency", &self.worker_concurrency)
            // content_keys chỉ chứa id + đường dẫn file (không có key material).
            .field("content_keys", &self.content_keys)
            .field("content_key_id", &self.content_key_id)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: "/var/lib/telecrate/index.db".to_string(),
            spool_dir: "/var/lib/telecrate/spool".to_string(),
            listen_port: 7070,
            encryption: "off".to_string(),
            region: default_region(),
            access_keys: Vec::new(),
            telegram_bot_token: String::new(),
            telegram_chat_id: 0,
            telegram_base_url: default_telegram_base(),
            chunk_size_bytes: default_chunk_size(),
            worker_concurrency: default_worker_concurrency(),
            content_keys: Vec::new(),
            content_key_id: String::new(),
            admin_password: None,
        }
    }
}

impl Config {
    /// Cập nhật giá trị cấu hình theo key string từ CLI hoặc Admin API.
    pub fn update_key(&mut self, key: &str, val: &str) -> Result<(), String> {
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
            "region" => {
                self.region = if val.is_empty() {
                    "*".to_string()
                } else {
                    val.to_string()
                };
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
            "telegram_base_url" => {
                self.telegram_base_url = val.to_string();
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
            _ => return Err(format!("unknown config key: '{key}'")),
        }
        validate(self)?;
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
        assert!(!cfg.region.is_empty());
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

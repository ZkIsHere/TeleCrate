//! Config TeleCrate — validate trước apply, biết trường nào cần restart.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Đường dẫn SQLite index. Thay đổi cần restart.
    pub db_path: String,
    /// Thư mục spool. Thay đổi cần restart.
    pub spool_dir: String,
    /// Port HTTP S3 + admin + dashboard. Thay đổi cần restart.
    pub listen_port: u16,
    /// Mã hóa nội dung: "off" | "on". Chỉ áp dụng ghi mới; dữ liệu cũ giữ chế độ cũ.
    pub encryption: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: "/var/lib/telecrate/index.db".to_string(),
            spool_dir: "/var/lib/telecrate/spool".to_string(),
            listen_port: 7070,
            encryption: "off".to_string(),
        }
    }
}

/// Đọc file TOML và validate. Không bao giờ in secret ra log (M0 chưa có secret field).
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
        let mut c = Config::default();
        c.encryption = "aes-quantum".to_string();
        assert!(validate(&c).is_err());
    }
}

// `anyhow` không có trong deps M0 — dùng String error để giữ ít thành phần.
// Cung cấp alias tương thích tối thiểu:
mod anyhow {
    pub type Result<T, E = String> = std::result::Result<T, E>;
}

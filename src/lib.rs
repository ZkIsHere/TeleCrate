//! TeleCrate library — dùng chung giữa daemon và CLI (không sửa DB trực tiếp khi daemon chạy).

pub mod app;
pub mod config;
pub mod cors;
pub mod crypto;
pub mod db;
pub mod doctor;
pub mod gc;
pub mod policy;
pub mod recovery;
pub mod s3;
pub mod sigv4;
pub mod spool;
pub mod telegram;
pub mod worker;

/// Phiên bản crate, dùng cho health/version endpoint.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Health status thật: daemon chạy + kiểm tra DB/spool mở được (M0: kiểm tra config hợp lệ).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    pub ok: bool,
    pub version: String,
    pub detail: String,
}

pub fn health_check(config_path: &str) -> Health {
    match config::load(config_path) {
        Ok(cfg) => match db::open(&cfg.db_path) {
            Ok(_) => Health {
                ok: true,
                version: VERSION.to_string(),
                detail: format!("config ok, db open ok: {}", cfg.db_path),
            },
            Err(e) => Health {
                ok: false,
                version: VERSION.to_string(),
                detail: format!("db open failed: {e}"),
            },
        },
        Err(e) => Health {
            ok: false,
            version: VERSION.to_string(),
            detail: format!("config invalid: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }
}

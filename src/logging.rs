//! Daemon logging: stdout (journald) + file daily-rotation tùy chọn.
//!
//! - Mức log duy nhất `log_level` áp dụng cho cả hai đầu ra.
//! - File: `telecrate.log.YYYY-MM-DD` trong `log_dir`, dọn file quá `log_retention_days` ở startup.
//! - Không bao giờ ghi secret/token/key material: các module đã redact ở tầng gọi;
//!   hàm này không nhận thêm field nào chứa secret.

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Khởi tạo subscriber toàn cục. Trả guard giữ worker file sống đến khi daemon dừng.
/// Gọi đúng 1 lần ở đầu `main` (trước mọi `tracing::...!`).
pub fn init(cfg: &crate::config::Config) -> Result<Option<WorkerGuard>, String> {
    let filter = EnvFilter::new(cfg.log_level.clone())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("reqwest=warn".parse().unwrap());

    if cfg.log_to_file {
        std::fs::create_dir_all(&cfg.log_dir)
            .map_err(|e| format!("create log_dir {}: {e}", cfg.log_dir))?;
        cleanup_old_logs(&cfg.log_dir, cfg.log_retention_days)?;
        let appender = RollingFileAppender::new(Rotation::DAILY, &cfg.log_dir, "telecrate.log");
        let (file_writer, guard) = tracing_appender::non_blocking(appender);
        tracing_subscriber::registry()
            .with(fmt::layer().with_writer(std::io::stdout))
            .with(fmt::layer().with_writer(file_writer).with_ansi(false))
            .with(filter)
            .try_init()
            .map_err(|e| format!("init tracing: {e}"))?;
        Ok(Some(guard))
    } else {
        tracing_subscriber::registry()
            .with(fmt::layer().with_writer(std::io::stdout))
            .with(filter)
            .try_init()
            .map_err(|e| format!("init tracing: {e}"))?;
        Ok(None)
    }
}

/// Xóa file `telecrate.log.YYYY-MM-DD` cũ hơn retention (tính theo tên file, không stat mtime
/// để tránh lệ thuộc đồng hồ FS). Bỏ qua file không đúng pattern — không xóa bừa.
pub fn cleanup_old_logs(dir: &str, retention_days: u64) -> Result<usize, String> {
    let today = days_since_epoch();
    let cutoff = today.saturating_sub(retention_days);
    let mut removed = 0;
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read log_dir {dir}: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(date) = name.strip_prefix("telecrate.log.") {
            if let Some(days) = parse_log_date(date) {
                if days < cutoff {
                    std::fs::remove_file(entry.path())
                        .map_err(|e| format!("remove old log {name}: {e}"))?;
                    removed += 1;
                }
            }
        }
    }
    Ok(removed)
}

fn days_since_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86400)
        .unwrap_or(0)
}

/// `YYYY-MM-DD` → số ngày từ epoch (thuần std, không thêm dep chrono).
fn parse_log_date(s: &str) -> Option<u64> {
    let mut it = s.split('-');
    let (y, mo, d): (i64, i64, i64) = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    if it.next().is_some() || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let mp = ((mo + 9).rem_euclid(12)) as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era as u64 * 146097 + doe - 719468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_removes_only_old_dated_logs() {
        let dir = tempfile::tempdir().unwrap();
        let today = days_since_epoch();
        // Dựng tên file từ số ngày (không phụ thuộc ngày chạy test).
        let name_for = |days_ago: u64| {
            let days = today - days_ago;
            // Đổi ngược days → civil (Howard Hinnant).
            let z = days as i64 + 719468;
            let era = z.div_euclid(146097);
            let doe = (z - era * 146097) as u64;
            let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
            let y = yoe as i64 + era * 400;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let d = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            let y = if m <= 2 { y + 1 } else { y };
            format!("telecrate.log.{y:04}-{m:02}-{d:02}")
        };
        for f in [
            name_for(20),
            name_for(0),
            "telecrate.log.current".to_string(),
            "other.txt".to_string(),
        ] {
            std::fs::write(dir.path().join(&f), "x").unwrap();
        }
        let removed = cleanup_old_logs(dir.path().to_str().unwrap(), 14).unwrap();
        assert_eq!(removed, 1);
        assert!(!dir.path().join(name_for(20)).exists());
        assert!(dir.path().join(name_for(0)).exists());
        assert!(dir.path().join("telecrate.log.current").exists());
        assert!(dir.path().join("other.txt").exists());
    }

    #[test]
    fn bad_log_level_rejected() {
        let c = crate::config::Config {
            log_level: "verbose".to_string(),
            ..crate::config::Config::default()
        };
        assert!(crate::config::validate(&c).is_err());
    }
}

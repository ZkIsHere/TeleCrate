//! TLS native cho TeleCrate: load cert/key PEM, tự sinh self-signed (pure Rust),
//! fingerprint SHA-256 cho PBS (self-signed cần khai fingerprint).
//!
//! Không bao giờ đọc/ghi key material ra log — API chỉ trả metadata + fingerprint.

use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Metadata cert đọc từ PEM/DER — đủ cho dashboard hiển thị bất cứ lúc nào.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub subject: String,
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    /// SHA-256 DER, dạng `AA:BB:...` (PBS fingerprint).
    pub fingerprint: String,
}

/// Chuẩn hóa fingerprint DER → `AA:BB:CC...` (uppercase, cách nhau `:`).
pub fn fingerprint_der(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    hex::encode(digest)
        .to_uppercase()
        .as_bytes()
        .chunks(2)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default()
        .join(":")
}

fn epoch_to_display(ts: i64) -> String {
    // Epoch → YYYY-MM-DD hh:mm:ss UTC bằng thuật toán civil-date (không cần crate time).
    let days = ts.div_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (
        ts.rem_euclid(86400) / 3600,
        (ts.rem_euclid(86400) % 3600) / 60,
        ts.rem_euclid(86400) % 60,
    );
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} UTC")
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

/// Parse cert DER đầu tiên trong blob → CertInfo.
pub fn cert_info_der(der: &[u8]) -> Result<CertInfo, String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| format!("parse cert: {e}"))?;
    let validity = cert.validity();
    let nb = validity.not_before.timestamp();
    let na = validity.not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut sans: Vec<String> = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(s) => sans.push(s.to_string()),
                GeneralName::IPAddress(b) => {
                    if b.len() == 4 {
                        sans.push(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]));
                    } else {
                        sans.push(hex::encode(b));
                    }
                }
                other => sans.push(format!("{other:?}")),
            }
        }
    }
    Ok(CertInfo {
        subject: cert.subject().to_string(),
        sans,
        not_before: epoch_to_display(nb),
        not_after: epoch_to_display(na),
        days_left: (na - now) / 86400,
        fingerprint: fingerprint_der(der),
    })
}

/// Lấy DER cert đầu tiên từ file PEM (chain) rồi parse.
pub fn cert_info_pem_file(cert_path: &str) -> Result<CertInfo, String> {
    let pem_bytes = std::fs::read(cert_path).map_err(|e| format!("read cert {cert_path}: {e}"))?;
    let (pem, _) = x509_parser::pem::Pem::read(std::io::Cursor::new(&pem_bytes))
        .map_err(|e| format!("parse PEM {cert_path}: {e}"))?;
    cert_info_der(&pem.contents)
}

/// Load RustlsConfig cho axum-server từ file PEM. Fail-closed khi file lỗi.
pub async fn load_rustls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<axum_server::tls_rustls::RustlsConfig, String> {
    axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|e| format!("load TLS cert/key: {e}"))
}

/// Đảm bảo TLS chạy được khi `tls_enabled` mà chưa cấu hình cert/key:
/// dùng file có sẵn, hoặc tự sinh self-signed (CN "telecrate",
/// SAN localhost/127.0.0.1/::1) vào `default_dir/tls.crt|tls.key`,
/// rồi gán ngược vào config. Tắt TLS → Ok(None), không chạm FS.
/// Trả Ok(Some(info)) khi vừa sinh mới (caller in fingerprint cho operator).
pub fn ensure_auto_tls_in(
    cfg: &mut crate::config::Config,
    default_dir: &str,
) -> Result<Option<CertInfo>, String> {
    if !cfg.tls_enabled {
        return Ok(None);
    }
    let (cert_path, key_path) = match (&cfg.tls_cert_file, &cfg.tls_key_file) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        // None/None hợp lệ ở validate (chế độ tự sinh); cặp lệch đã bị validate chặn.
        _ => (
            format!("{default_dir}/tls.crt"),
            format!("{default_dir}/tls.key"),
        ),
    };
    if std::path::Path::new(&cert_path).is_file() && std::path::Path::new(&key_path).is_file() {
        cfg.tls_cert_file = Some(cert_path);
        cfg.tls_key_file = Some(key_path);
        return Ok(None);
    }
    let info = generate_self_signed(
        "telecrate",
        &[
            "telecrate".to_string(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ],
        825,
        &cert_path,
        &key_path,
    )?;
    cfg.tls_cert_file = Some(cert_path);
    cfg.tls_key_file = Some(key_path);
    Ok(Some(info))
}

/// Sinh self-signed ECDSA (P-256) + ghi file. Trả CertInfo (có fingerprint cho PBS).
/// `sans` nhận DNS (`telecrate.local`) và/hoặc IP (`192.168.1.10`).
/// Key ghi quyền 0600 trên unix; cert 0644.
pub fn generate_self_signed(
    cn: &str,
    sans: &[String],
    days: u64,
    cert_path: &str,
    key_path: &str,
) -> Result<CertInfo, String> {
    use rcgen::{date_time_ymd, CertificateParams, DistinguishedName, DnType, KeyPair};
    let cn = cn.trim();
    if cn.is_empty() {
        return Err("CN must not be empty".to_string());
    }
    if !(1..=825).contains(&days) {
        return Err("days must be 1..=825".to_string());
    }
    // CertificateParams::new tự phân biệt IP/DNS cho từng SAN.
    let mut san_strings: Vec<String> = sans
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if san_strings.is_empty() {
        san_strings.push(cn.to_string());
    }
    let mut params = CertificateParams::new(san_strings).map_err(|e| format!("bad SAN: {e}"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    // now-5m → now+days (ngày civil tính từ epoch, không cần crate time).
    let now_days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        / 86400;
    let (y1, m1, d1) = civil_from_days(now_days);
    let (y2, m2, d2) = civil_from_days(now_days + days as i64);
    params.not_before = date_time_ymd(y1, m1, d1);
    params.not_after = date_time_ymd(y2, m2, d2);
    let key_pair = KeyPair::generate().map_err(|e| format!("generate key: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("self-sign: {e}"))?;
    if let Some(parent) = std::path::Path::new(cert_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create cert parent dir: {e}"))?;
        }
    }
    if let Some(parent) = std::path::Path::new(key_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create key parent dir: {e}"))?;
        }
    }
    std::fs::write(key_path, key_pair.serialize_pem())
        .map_err(|e| format!("write key {key_path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::write(cert_path, cert.pem()).map_err(|e| format!("write cert {cert_path}: {e}"))?;
    let der: &[u8] = cert.der().as_ref();
    cert_info_der(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_format_matches_pbs_style() {
        let fp = fingerprint_der(b"abc");
        // SHA-256 = 32 bytes → 32 cặp hex cách nhau 31 dấu ':'.
        assert_eq!(fp.len(), 32 * 2 + 31);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase() || c == ':'));
        assert_eq!(&fp[2..3], ":");
    }

    #[test]
    fn self_signed_roundtrip_gives_parseable_cert_with_sans() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("tls.crt");
        let key = dir.path().join("tls.key");
        let info = generate_self_signed(
            "telecrate.local",
            &["telecrate.local".to_string(), "192.168.1.10".to_string()],
            90,
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        )
        .unwrap();
        assert!(info.subject.contains("telecrate.local"), "{}", info.subject);
        assert!(info.sans.iter().any(|s| s == "telecrate.local"));
        assert!(info.sans.iter().any(|s| s == "192.168.1.10"));
        assert!(info.days_left >= 89 && info.days_left <= 90);
        // Đọc lại từ file PEM → cùng fingerprint.
        let info2 = cert_info_pem_file(cert.to_str().unwrap()).unwrap();
        assert_eq!(info2.fingerprint, info.fingerprint);
        // Key tồn tại và là PEM.
        let key_pem = std::fs::read_to_string(key.to_str().unwrap()).unwrap();
        assert!(key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn ensure_auto_tls_generates_once_then_reuses() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap().to_string();
        // Tắt → không chạm FS.
        let mut c = crate::config::Config {
            tls_enabled: false,
            ..crate::config::Config::default()
        };
        assert!(ensure_auto_tls_in(&mut c, &d).unwrap().is_none());
        assert!(!dir.path().join("tls.crt").exists());
        // Bật, chưa có file → sinh mới + gán paths.
        let mut c = crate::config::Config::default();
        assert!(c.tls_enabled); // default-on
        let info = ensure_auto_tls_in(&mut c, &d).unwrap().expect("generated");
        assert!(info.fingerprint.len() == 32 * 2 + 31);
        assert!(dir.path().join("tls.crt").is_file());
        assert!(dir.path().join("tls.key").is_file());
        assert!(crate::config::validate(&c).is_ok());
        // Lần 2 → tái sử dụng, cùng fingerprint.
        let info2 = ensure_auto_tls_in(&mut c, &d).unwrap();
        assert!(info2.is_none());
        let again = cert_info_pem_file(dir.path().join("tls.crt").to_str().unwrap()).unwrap();
        assert_eq!(again.fingerprint, info.fingerprint);
    }

    #[test]
    fn self_signed_rejects_bad_input() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("c.crt");
        let key = dir.path().join("c.key");
        assert!(generate_self_signed("", &[], 90, "c", "k").is_err());
        assert!(
            generate_self_signed("cn", &[], 0, cert.to_str().unwrap(), key.to_str().unwrap())
                .is_err()
        );
        assert!(cert_info_pem_file("/khong/ton/tai.crt").is_err());
    }
}

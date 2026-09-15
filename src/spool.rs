//! Spool — filesystem riêng cho chunk pending. Tên file theo hash, không dùng object key làm path.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Map (version_id, chunk_idx) → tên file spool an toàn (chặn path traversal).
pub fn chunk_path(spool_dir: &str, version_id: &str, chunk_idx: u64) -> PathBuf {
    let mut h = Sha256::new();
    h.update(version_id.as_bytes());
    h.update([0u8]);
    h.update(chunk_idx.to_le_bytes());
    let name = hex::encode(h.finalize());
    Path::new(spool_dir).join(format!("{name}.chunk"))
}

/// Ghi durable: tmp + flush/fsync + atomic rename + fsync directory.
pub fn write_durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    // fsync directory để rename bền vững (Linux/production).
    // Windows không cho mở directory để fsync → bỏ qua, file data vẫn fsync ở trên.
    #[cfg(unix)]
    {
        let dir = path.parent().unwrap_or(Path::new("."));
        let dfd = std::fs::File::open(dir)?;
        dfd.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_name_does_not_contain_key() {
        let p = chunk_path("/spool", "../../etc/passwd", 0);
        let name = p.file_name().unwrap().to_str().unwrap();
        assert!(!name.contains("..") && !name.contains('/'));
        assert!(name.ends_with(".chunk"));
    }

    #[test]
    fn write_durable_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.chunk");
        write_durable(&p, b"hello").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
    }
}

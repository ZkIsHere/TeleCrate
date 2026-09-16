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

/// Dọn dẹp spool khi khởi động daemon:
/// - Xóa tất cả file `.tmp` mồ côi (dở dang giữa chừng).
/// - Xóa tất cả file `.chunk` mồ côi không nằm trong `active_paths` của DB (crash trước khi DB commit).
///
/// Trả về `(số_tmp_đã_xóa, số_chunk_mồ_côi_đã_xóa)`.
pub fn reconcile_spool(
    spool_dir: &Path,
    active_paths: &std::collections::HashSet<PathBuf>,
) -> std::io::Result<(usize, usize)> {
    if !spool_dir.exists() {
        return Ok((0, 0));
    }
    let mut tmp_count = 0;
    let mut chunk_count = 0;
    for entry in std::fs::read_dir(spool_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "tmp" {
                    if std::fs::remove_file(&path).is_ok() {
                        tmp_count += 1;
                    }
                } else if ext == "chunk" {
                    let normalized = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
                    let is_active = active_paths.contains(&path)
                        || active_paths.contains(&normalized)
                        || active_paths.iter().any(|p| {
                            p == &path
                                || p == &normalized
                                || std::fs::canonicalize(p)
                                    .map(|c| c == normalized)
                                    .unwrap_or(false)
                        });
                    if !is_active && std::fs::remove_file(&path).is_ok() {
                        chunk_count += 1;
                    }
                }
            }
        }
    }
    Ok((tmp_count, chunk_count))
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

    #[test]
    fn reconcile_spool_cleans_tmp_and_orphan_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path();
        let tmp_file = spool.join("incomplete.tmp");
        let orphan_chunk = spool.join("orphan.chunk");
        let active_chunk = spool.join("active.chunk");

        std::fs::write(&tmp_file, b"tmp data").unwrap();
        write_durable(&orphan_chunk, b"orphan chunk data").unwrap();
        write_durable(&active_chunk, b"active chunk data").unwrap();

        let mut active = std::collections::HashSet::new();
        active.insert(active_chunk.clone());
        if let Ok(canon) = std::fs::canonicalize(&active_chunk) {
            active.insert(canon);
        }

        let (tmps, chunks) = reconcile_spool(spool, &active).unwrap();
        assert_eq!(tmps, 1);
        assert_eq!(chunks, 1);

        assert!(!tmp_file.exists());
        assert!(!orphan_chunk.exists());
        assert!(active_chunk.exists());
    }
}

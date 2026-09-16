//! Mã hóa nội dung OPTIONAL (M2.4): ChaCha20-Poly1305, envelope đơn giản.
//!
//! - Tắt (`encryption = off`): plaintext qua spool/Telegram, vẫn checksum toàn vẹn.
//! - Bật: mỗi chunk = `nonce(12) || ciphertext`, nonce ngẫu nhiên, AAD = `version_id/idx`
//!   (chống reorder/truncate qua chunk), key 32 bytes từ file riêng (0600).
//! - Khóa KHÔNG BAO GIỜ lên Telegram/log; chunk chỉ lưu `key_id` để tra.
//! - Sai key / tamper / reorder đều fail đóng (AEAD verify trước khi trả plaintext).

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use std::collections::HashMap;

pub const NONCE_LEN: usize = 12;
pub const MODE_NONE: &str = "none";
pub const MODE_AEAD_V1: &str = "aead-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    UnknownKey,
    BadKeyFile(String),
    Encrypt(String),
    Decrypt,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Không chứa key material — chỉ mã lỗi.
        match self {
            CryptoError::UnknownKey => write!(f, "unknown content key id"),
            CryptoError::BadKeyFile(s) => write!(f, "bad key file: {s}"),
            CryptoError::Encrypt(s) => write!(f, "encrypt: {s}"),
            CryptoError::Decrypt => write!(f, "decrypt failed (wrong key or tampered data)"),
        }
    }
}

/// Kho khóa trong RAM: id → 32 bytes. Không Debug/Serialize key material.
#[derive(Clone, Default)]
pub struct KeyStore {
    keys: HashMap<String, [u8; 32]>,
}

impl KeyStore {
    pub fn get(&self, id: &str) -> Option<&[u8; 32]> {
        self.keys.get(id)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Nạp từ danh sách (id, đường dẫn file 32 bytes thô).
    pub fn load(pairs: &[(String, String)]) -> Result<Self, CryptoError> {
        let mut keys = HashMap::new();
        for (id, path) in pairs {
            let raw =
                std::fs::read(path).map_err(|e| CryptoError::BadKeyFile(format!("{path}: {e}")))?;
            if raw.len() != 32 {
                return Err(CryptoError::BadKeyFile(format!(
                    "{path}: cần đúng 32 bytes, thấy {}",
                    raw.len()
                )));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&raw);
            if keys.insert(id.clone(), k).is_some() {
                return Err(CryptoError::BadKeyFile(format!("trùng key id: {id}")));
            }
        }
        Ok(Self { keys })
    }
}

/// AAD gắn định danh + vị trí chunk: đổi version/idx → verify fail.
fn aad(version_id: &str, idx: u64) -> Vec<u8> {
    format!("{version_id}/{idx}").into_bytes()
}

/// Mã hóa 1 chunk → `nonce || ciphertext`.
pub fn encrypt_chunk(
    store: &KeyStore,
    key_id: &str,
    version_id: &str,
    idx: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = store.get(key_id).ok_or(CryptoError::UnknownKey)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| CryptoError::Encrypt(format!("nonce rng: {e}")))?;
    let mut buf = plaintext.to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(&nonce), &aad(version_id, idx), &mut buf)
        .map_err(|e| CryptoError::Encrypt(format!("{e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Giải mã + xác thực 1 chunk đã lưu. Sai key/tamper/reorder → `Decrypt`.
pub fn decrypt_chunk(
    store: &KeyStore,
    key_id: &str,
    version_id: &str,
    idx: u64,
    stored: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = store.get(key_id).ok_or(CryptoError::UnknownKey)?;
    if stored.len() < NONCE_LEN {
        return Err(CryptoError::Decrypt);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut buf = stored[NONCE_LEN..].to_vec();
    cipher
        .decrypt_in_place(
            Nonce::from_slice(&stored[..NONCE_LEN]),
            &aad(version_id, idx),
            &mut buf,
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(buf)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SseConfig {
    None,
    SseS3 {
        algorithm: String,
    },
    SseC {
        algorithm: String,
        key_b64: String,
        key_md5_b64: String,
        key_bytes: [u8; 32],
    },
}

pub fn parse_and_validate_sse_headers(
    headers: &axum::http::HeaderMap,
) -> Result<SseConfig, (axum::http::StatusCode, &'static str, &'static str)> {
    use axum::http::StatusCode;

    let sse_s3 = headers
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.to_str().ok());
    let sse_c_algo = headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok());
    let sse_c_key = headers
        .get("x-amz-server-side-encryption-customer-key")
        .and_then(|v| v.to_str().ok());
    let sse_c_key_md5 = headers
        .get("x-amz-server-side-encryption-customer-key-md5")
        .and_then(|v| v.to_str().ok());

    if sse_s3.is_some() && sse_c_algo.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "The request cannot contain both SSE and SSE-C headers.",
        ));
    }

    if let Some(algo) = sse_s3 {
        if algo != "AES256" && algo != "aws:kms" {
            return Err((
                StatusCode::BAD_REQUEST,
                "InvalidEncryptionAlgorithmError",
                "The encryption algorithm supplied is not supported. Only AES256 is supported.",
            ));
        }
        return Ok(SseConfig::SseS3 {
            algorithm: algo.to_string(),
        });
    }

    if let Some(algo) = sse_c_algo {
        if algo != "AES256" {
            return Err((
                StatusCode::BAD_REQUEST,
                "InvalidEncryptionAlgorithmError",
                "The customer-provided encryption algorithm of the request is not supported.",
            ));
        }
        let key_b64 = sse_c_key.ok_or((
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "The secret key was not provided.",
        ))?;
        let key_md5_b64 = sse_c_key_md5.ok_or((
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "The secret key MD5 was not provided.",
        ))?;

        let decoded = crate::s3::base64_decode(key_b64).ok_or((
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "The secret key is invalid base64.",
        ))?;
        if decoded.len() != 32 {
            return Err((
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "The secret key is invalid. Key must be 256 bits (32 bytes).",
            ));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&decoded);

        let computed_md5 = md5::compute(key_bytes);
        let computed_md5_b64 = crate::s3::base64_encode(computed_md5.as_ref());

        if computed_md5_b64.trim() != key_md5_b64.trim() {
            return Err((
                StatusCode::BAD_REQUEST,
                "InvalidDigest",
                "The calculated MD5 hash of the key does not match the provided MD5 hash.",
            ));
        }

        return Ok(SseConfig::SseC {
            algorithm: algo.to_string(),
            key_b64: key_b64.to_string(),
            key_md5_b64: key_md5_b64.to_string(),
            key_bytes,
        });
    }

    Ok(SseConfig::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> KeyStore {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k1.key");
        std::fs::write(&p, [7u8; 32]).unwrap();
        // KeyStore sở hữu bản copy 32 bytes nên dir drop an toàn.
        KeyStore::load(&[("k1".to_string(), p.to_str().unwrap().to_string())]).unwrap()
    }

    #[test]
    fn roundtrip_and_nonce_unique() {
        let ks = store();
        let a = encrypt_chunk(&ks, "k1", "v", 0, b"hello").unwrap();
        let b = encrypt_chunk(&ks, "k1", "v", 0, b"hello").unwrap();
        assert_ne!(a, b, "nonce phải duy nhất mỗi lần mã hóa");
        assert_eq!(decrypt_chunk(&ks, "k1", "v", 0, &a).unwrap(), b"hello");
    }

    #[test]
    fn tamper_reorder_truncate_fail_closed() {
        let ks = store();
        let mut s = encrypt_chunk(&ks, "k1", "v", 3, b"data-chunk-three").unwrap();
        // Đảo 1 byte ciphertext.
        let n = s.len();
        s[n - 1] ^= 1;
        assert_eq!(
            decrypt_chunk(&ks, "k1", "v", 3, &s).unwrap_err(),
            CryptoError::Decrypt
        );
        // Đảo nonce.
        let mut s2 = encrypt_chunk(&ks, "k1", "v", 3, b"data-chunk-three").unwrap();
        s2[0] ^= 1;
        assert_eq!(
            decrypt_chunk(&ks, "k1", "v", 3, &s2).unwrap_err(),
            CryptoError::Decrypt
        );
        // Reorder: giải với idx khác.
        let s3 = encrypt_chunk(&ks, "k1", "v", 3, b"data-chunk-three").unwrap();
        assert_eq!(
            decrypt_chunk(&ks, "k1", "v", 4, &s3).unwrap_err(),
            CryptoError::Decrypt
        );
        // Truncate.
        assert_eq!(
            decrypt_chunk(&ks, "k1", "v", 3, &s3[..10]).unwrap_err(),
            CryptoError::Decrypt
        );
        assert_eq!(
            decrypt_chunk(&ks, "k1", "v", 3, b"short").unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn wrong_key_and_unknown_key_fail() {
        let ks = store();
        let s = encrypt_chunk(&ks, "k1", "v", 0, b"x").unwrap();
        // Key khác cùng id? Không — store khác không có k1.
        let other = KeyStore::default();
        assert_eq!(
            decrypt_chunk(&other, "k1", "v", 0, &s).unwrap_err(),
            CryptoError::UnknownKey
        );
        // Key sai nội dung nhưng cùng id.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k1.key");
        std::fs::write(&p, [9u8; 32]).unwrap();
        let wrong = KeyStore::load(&[("k1".to_string(), p.to_str().unwrap().to_string())]).unwrap();
        assert_eq!(
            decrypt_chunk(&wrong, "k1", "v", 0, &s).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn key_file_must_be_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.key");
        std::fs::write(&p, b"too short").unwrap();
        assert!(matches!(
            KeyStore::load(&[("k".into(), p.to_str().unwrap().into())]),
            Err(CryptoError::BadKeyFile(_))
        ));
    }

    #[test]
    fn error_display_never_leaks_key() {
        let ks = store();
        let e = encrypt_chunk(&ks, "nope", "v", 0, b"x").unwrap_err();
        let msg = format!("{e}");
        assert_eq!(msg, "unknown content key id");
        // Key material là [7u8; 32] — không xuất hiện ở bất kỳ message nào.
        // (KeyStore cố ý không impl Debug.)
        for m in [
            format!("{}", CryptoError::Decrypt),
            format!("{}", CryptoError::Encrypt("x".into())),
            format!("{}", CryptoError::BadKeyFile("p".into())),
            msg,
        ] {
            assert!(!m.contains("0707"), "leak? {m}");
        }
    }
}

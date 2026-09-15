//! Telegram transport — interface trừu tượng + Bot API HTTP skeleton (M1).
//!
//! Nguyên tắc: ưu tiên bot identity, không dùng user session làm mặc định.
//! Không tái sử dụng file_id giữa các bot khác nhau khi chưa kiểm chứng.
//! URL download / file_reference coi là ephemeral, refresh khi cần.

use serde::{Deserialize, Serialize};

/// Loại transport đã kiểm chứng capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportType {
    /// HTTP Bot API (`https://api.telegram.org/bot<token>/...`). Triển khai trước.
    BotApiHttp,
    /// Local Bot API server (tự host). Thêm sau capability test.
    LocalBotApi,
    /// MTProto bot (api_id/api_hash + bot token). Thêm sau capability test.
    MtprotoBot,
}

/// Remote locator bền vững lưu trong DB cho mỗi blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteLocator {
    pub transport: TransportType,
    /// Định danh bot (không chứa token).
    pub bot_name: String,
    pub chat_id: i64,
    pub message_id: i64,
    pub file_id: String,
    pub file_unique_id: String,
    pub size: u64,
}

/// Phân loại lỗi để scheduler quyết định retry / dừng vĩnh viễn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Lỗi tạm thời: mất mạng, 429/Retry-After, FLOOD_WAIT, 5xx → retry + backoff.
    Transient {
        reason: String,
        retry_after_secs: Option<u64>,
    },
    /// Lỗi vĩnh viễn: token sai, bot bị kick, channel xóa → dừng + báo dashboard.
    Permanent { reason: String },
}

impl TransportError {
    pub fn is_transient(&self) -> bool {
        matches!(self, TransportError::Transient { .. })
    }
}

/// Kết quả kiểm tra capability trên channel thử nghiệm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub transport: TransportType,
    pub upload_ok: bool,
    pub download_byte_identical: bool,
    pub delete_ok: bool,
    pub history_lookup_ok: bool,
    pub note: String,
}

/// Interface transport — mọi implementation phải qua capability test trước khi dùng.
pub trait Transport {
    fn transport_type(&self) -> TransportType;
    fn upload(&self, chat_id: i64, bytes: &[u8]) -> Result<RemoteLocator, TransportError>;
    fn download(&self, locator: &RemoteLocator) -> Result<Vec<u8>, TransportError>;
    fn delete(&self, locator: &RemoteLocator) -> Result<bool, TransportError>;
}

/// Cấu hình Bot API HTTP. Token chỉ nằm trong config/runtime, không log.
#[derive(Debug, Clone)]
pub struct BotApiHttpConfig {
    /// Base URL, mặc định `https://api.telegram.org`. Local Bot API dùng URL tự host.
    pub base_url: String,
    /// Quyền admin tối thiểu trên channel thử nghiệm đã được cấp hay chưa.
    pub has_admin_rights: bool,
}

impl Default for BotApiHttpConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.telegram.org".to_string(),
            has_admin_rights: false,
        }
    }
}

/// Giới hạn Bot API HTTP theo tài liệu chính thức (kiểm tra 2026-09-15).
/// Số liệu cụ thể phải được xác minh bằng capability test (M1 live) trước khi chốt.
pub mod documented_limits {
    /// Bot API có giới hạn kích thước file riêng, khác Local Bot API / MTProto.
    /// Không hardcode số MB vào logic — chunk size là config đo hiệu năng (xem prompt §5).
    pub const NOTE: &str =
        "bot-api-file-size-limits-apply; verify-against-live-test-before-chunk-sizing";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Mock transport cho unit test — không chạm mạng.
    struct MockTransport {
        store: Arc<Mutex<HashMap<i64, Vec<u8>>>>,
        next_message: Mutex<i64>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                store: Arc::new(Mutex::new(HashMap::new())),
                next_message: Mutex::new(1),
            }
        }
    }

    impl Transport for MockTransport {
        fn transport_type(&self) -> TransportType {
            TransportType::BotApiHttp
        }

        fn upload(&self, chat_id: i64, bytes: &[u8]) -> Result<RemoteLocator, TransportError> {
            let mut n = self.next_message.lock().unwrap();
            let mid = *n;
            *n += 1;
            self.store.lock().unwrap().insert(mid, bytes.to_vec());
            Ok(RemoteLocator {
                transport: TransportType::BotApiHttp,
                bot_name: "mock-bot".to_string(),
                chat_id,
                message_id: mid,
                file_id: format!("mock-file-{mid}"),
                file_unique_id: format!("mock-unique-{mid}"),
                size: bytes.len() as u64,
            })
        }

        fn download(&self, locator: &RemoteLocator) -> Result<Vec<u8>, TransportError> {
            self.store
                .lock()
                .unwrap()
                .get(&locator.message_id)
                .cloned()
                .ok_or_else(|| TransportError::Permanent {
                    reason: "message not found".to_string(),
                })
        }

        fn delete(&self, locator: &RemoteLocator) -> Result<bool, TransportError> {
            Ok(self
                .store
                .lock()
                .unwrap()
                .remove(&locator.message_id)
                .is_some())
        }
    }

    #[test]
    fn mock_upload_download_byte_identical() {
        let t = MockTransport::new();
        let data = b"telecrate-m1-capability-probe".to_vec();
        let loc = t.upload(-1001234, &data).unwrap();
        assert_eq!(loc.transport, TransportType::BotApiHttp);
        let back = t.download(&loc).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn mock_delete_makes_download_fail() {
        let t = MockTransport::new();
        let loc = t.upload(-1001234, b"x").unwrap();
        assert!(t.delete(&loc).unwrap());
        assert!(!t.delete(&loc).unwrap());
        assert!(t.download(&loc).is_err());
    }

    #[test]
    fn error_taxonomy_transient_vs_permanent() {
        let a = TransportError::Transient {
            reason: "flood".to_string(),
            retry_after_secs: Some(30),
        };
        let b = TransportError::Permanent {
            reason: "bot kicked".to_string(),
        };
        assert!(a.is_transient());
        assert!(!b.is_transient());
    }

    /// Live test có kiểm soát — CHỈ chạy khi có secrets, tách khỏi PR checks.
    /// Ví dụ: `TELECRATE_BOT_TOKEN=... TELECRATE_TEST_CHAT_ID=... cargo test -- --ignored`
    #[test]
    #[ignore]
    fn live_bot_api_capability_probe() {
        let token = std::env::var("TELECRATE_BOT_TOKEN")
            .expect("thiếu TELECRATE_BOT_TOKEN — báo unverified, không giả live pass");
        let _ = token;
        let _chat: i64 = std::env::var("TELECRATE_TEST_CHAT_ID")
            .expect("thiếu TELECRATE_TEST_CHAT_ID")
            .parse()
            .unwrap();
        // Triển khai upload/download/xóa thử nhỏ ở changeset M1 tiếp theo.
    }
}

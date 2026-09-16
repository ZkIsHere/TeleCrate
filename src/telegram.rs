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

/// Client Bot API HTTP thật: upload document binary, download, delete.
/// Token KHÔNG BAO GIỜ xuất hiện trong log/error/Debug — mọi chuỗi lỗi đều redact.
/// Clone rẻ (reqwest Client share bên trong) để dùng chung qua AppState.
#[derive(Clone)]
pub struct BotApiHttpTransport {
    base_url: String,
    token: String,
    bot_name: String,
    client: reqwest::blocking::Client,
}

impl std::fmt::Debug for BotApiHttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BotApiHttpTransport")
            .field("base_url", &self.base_url)
            .field("bot_name", &self.bot_name)
            .field("token", &"***")
            .finish()
    }
}

impl BotApiHttpTransport {
    pub fn new(base_url: &str, token: &str, bot_name: &str) -> Result<Self, TransportError> {
        if token.is_empty() {
            return Err(TransportError::Permanent {
                reason: "empty bot token".to_string(),
            });
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| TransportError::Permanent {
                reason: format!("build http client: {e}"),
            })?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            bot_name: bot_name.to_string(),
            client,
        })
    }

    /// Base URL mặc định của hosted Bot API.
    pub fn hosted(token: &str, bot_name: &str) -> Result<Self, TransportError> {
        Self::new("https://api.telegram.org", token, bot_name)
    }

    fn redact(&self, s: &str) -> String {
        s.replace(&self.token, "***")
    }

    fn api_url(&self, method: &str) -> String {
        format!("{}/bot{}/{method}", self.base_url, self.token)
    }

    /// POST multipart, parse envelope `{"ok":true,"result":...}`.
    fn post_multipart(
        &self,
        method: &str,
        form: reqwest::blocking::multipart::Form,
    ) -> Result<serde_json::Value, TransportError> {
        let resp = self
            .client
            .post(self.api_url(method))
            .multipart(form)
            .send()
            .map_err(|e| TransportError::Transient {
                reason: format!("network: {}", self.redact(&e.to_string())),
                retry_after_secs: None,
            })?;
        self.read_envelope(resp)
    }

    /// GET query params, parse envelope.
    fn get(
        &self,
        method: &str,
        params: &[(&str, String)],
    ) -> Result<serde_json::Value, TransportError> {
        let resp = self
            .client
            .get(self.api_url(method))
            .query(params)
            .send()
            .map_err(|e| TransportError::Transient {
                reason: format!("network: {}", self.redact(&e.to_string())),
                retry_after_secs: None,
            })?;
        self.read_envelope(resp)
    }

    fn read_envelope(
        &self,
        resp: reqwest::blocking::Response,
    ) -> Result<serde_json::Value, TransportError> {
        let status = resp.status().as_u16();
        let body = resp.text().map_err(|e| TransportError::Transient {
            reason: format!("read body (http {status}): {}", self.redact(&e.to_string())),
            retry_after_secs: None,
        })?;
        let v: serde_json::Value = match serde_json::from_str(&body) {
            Ok(val) => val,
            Err(e) => {
                if status >= 500 || status == 429 {
                    return Err(TransportError::Transient {
                        reason: format!("HTTP {status} server error: {}", self.redact(&body)),
                        retry_after_secs: None,
                    });
                }
                return Err(TransportError::Transient {
                    reason: format!("bad api json (http {status}): {e}"),
                    retry_after_secs: None,
                });
            }
        };
        if v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
            return Ok(v);
        }
        Err(map_api_error(&self.token, status, &v))
    }
}

/// Map lỗi Bot API → Transient/Permanent. Token được redact khỏi mọi reason.
fn map_api_error(token: &str, status: u16, v: &serde_json::Value) -> TransportError {
    let redact = |s: &str| s.replace(token, "***");
    let desc = v
        .get("description")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown api error");
    let retry_after = v
        .pointer("/parameters/retry_after")
        .and_then(|x| x.as_u64());
    if status == 429 {
        return TransportError::Transient {
            reason: redact(&format!("rate limited: {desc}")),
            retry_after_secs: retry_after,
        };
    }
    if status >= 500 {
        return TransportError::Transient {
            reason: redact(&format!("telegram 5xx error {status}: {desc}")),
            retry_after_secs: Some(10),
        };
    }
    if status == 401 {
        return TransportError::Permanent {
            reason: "unauthorized: bot token sai hoặc đã revoke".to_string(),
        };
    }
    TransportError::Permanent {
        reason: redact(&format!("api error {status}: {desc}")),
    }
}

impl Transport for BotApiHttpTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::BotApiHttp
    }

    fn upload(&self, chat_id: i64, bytes: &[u8]) -> Result<RemoteLocator, TransportError> {
        // Tên file = hash nội dung — không lộ object key (prompt §5).
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        let fname = format!("chunk-{}.bin", hex::encode(h.finalize()));
        // TODO(M2): stream chunk lớn thay vì copy toàn bộ vào multipart (RAM bounded).
        let part = reqwest::blocking::multipart::Part::bytes(bytes.to_vec())
            .file_name(fname)
            .mime_str("application/octet-stream")
            .map_err(|e| TransportError::Permanent {
                reason: format!("mime: {e}"),
            })?;
        let form = reqwest::blocking::multipart::Form::new()
            .text("chat_id", chat_id.to_string())
            .text("disable_notification", "true")
            .part("document", part);
        let v = self.post_multipart("sendDocument", form)?;
        let mid = v
            .pointer("/result/message_id")
            .and_then(|x| x.as_i64())
            .ok_or_else(|| TransportError::Permanent {
                reason: "sendDocument: thiếu message_id".to_string(),
            })?;
        let doc = v
            .pointer("/result/document")
            .ok_or_else(|| TransportError::Permanent {
                reason: "sendDocument: thiếu document (nội dung có thể đã bị biến đổi)".to_string(),
            })?;
        let get_str = |k: &str| {
            doc.get(k)
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string()
        };
        let size = doc
            .get("file_size")
            .and_then(|x| x.as_u64())
            .unwrap_or(bytes.len() as u64);
        Ok(RemoteLocator {
            transport: TransportType::BotApiHttp,
            bot_name: self.bot_name.clone(),
            chat_id,
            message_id: mid,
            file_id: get_str("file_id"),
            file_unique_id: get_str("file_unique_id"),
            size,
        })
    }

    fn download(&self, locator: &RemoteLocator) -> Result<Vec<u8>, TransportError> {
        // getFile không tái sử dụng file_id giữa bot khác khi chưa kiểm chứng (prompt §5).
        let v = self.get("getFile", &[("file_id", locator.file_id.clone())])?;
        let path = v
            .pointer("/result/file_path")
            .and_then(|x| x.as_str())
            .ok_or_else(|| TransportError::Permanent {
                reason: "getFile: thiếu file_path (locator hết hạn?)".to_string(),
            })?
            .to_string();
        // URL download là ephemeral — dùng ngay, không lưu làm locator (prompt §5).
        let url = format!("{}/file/bot{}/{path}", self.base_url, self.token);
        let resp = self
            .client
            .get(url)
            .send()
            .map_err(|e| TransportError::Transient {
                reason: format!("download network: {}", self.redact(&e.to_string())),
                retry_after_secs: None,
            })?;
        if !resp.status().is_success() {
            return Err(TransportError::Transient {
                reason: format!("download http {}", resp.status().as_u16()),
                retry_after_secs: None,
            });
        }
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| TransportError::Transient {
                reason: format!("read download body: {}", self.redact(&e.to_string())),
                retry_after_secs: None,
            })
    }

    fn delete(&self, locator: &RemoteLocator) -> Result<bool, TransportError> {
        let v = self.get(
            "deleteMessage",
            &[
                ("chat_id", locator.chat_id.to_string()),
                ("message_id", locator.message_id.to_string()),
            ],
        )?;
        Ok(v.get("result").and_then(|x| x.as_bool()).unwrap_or(false))
    }
}

/// Mock transport cho test — không chạm mạng.
#[derive(Default, Clone)]
pub struct MockTransport {
    pub store: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<i64, Vec<u8>>>>,
    pub next_message: std::sync::Arc<std::sync::Mutex<i64>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            store: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            next_message: std::sync::Arc::new(std::sync::Mutex::new(1)),
        }
    }
}

impl Transport for MockTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::BotApiHttp
    }

    fn upload(&self, chat_id: i64, bytes: &[u8]) -> Result<RemoteLocator, TransportError> {
        let mut msg_guard = self.next_message.lock().unwrap();
        let msg_id = *msg_guard;
        *msg_guard += 1;
        self.store.lock().unwrap().insert(msg_id, bytes.to_vec());
        Ok(RemoteLocator {
            transport: TransportType::BotApiHttp,
            bot_name: "mock-bot".to_string(),
            chat_id,
            message_id: msg_id,
            file_id: format!("mock_file_{msg_id}"),
            file_unique_id: format!("uniq_{msg_id}"),
            size: bytes.len() as u64,
        })
    }

    fn download(&self, loc: &RemoteLocator) -> Result<Vec<u8>, TransportError> {
        self.store
            .lock()
            .unwrap()
            .get(&loc.message_id)
            .cloned()
            .ok_or_else(|| TransportError::Permanent {
                reason: format!("mock file {} not found", loc.message_id),
            })
    }

    fn delete(&self, loc: &RemoteLocator) -> Result<bool, TransportError> {
        let mut map = self.store.lock().unwrap();
        Ok(map.remove(&loc.message_id).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn api_error_mapping_429_401_and_redaction() {
        let token = "SECRET-TOKEN-123";
        let v429 = serde_json::json!({
            "ok": false, "error_code": 429,
            "description": "Too Many Requests: retry after 30",
            "parameters": {"retry_after": 30}
        });
        match map_api_error(token, 429, &v429) {
            TransportError::Transient {
                retry_after_secs: Some(30),
                ..
            } => {}
            other => panic!("expected transient 429, got {other:?}"),
        }
        match map_api_error(token, 401, &serde_json::json!({"ok":false})) {
            TransportError::Permanent { .. } => {}
            other => panic!("expected permanent 401, got {other:?}"),
        }
        // Token trong description phải bị redact.
        let v = serde_json::json!({"ok": false, "description": format!("bad {token}")});
        match map_api_error(token, 400, &v) {
            TransportError::Permanent { reason } => {
                assert!(!reason.contains(token), "token leaked: {reason}");
                assert!(reason.contains("***"));
            }
            other => panic!("expected permanent 400, got {other:?}"),
        }
    }

    #[test]
    fn transport_debug_redacts_token() {
        let t =
            BotApiHttpTransport::new("https://api.telegram.org", "SECRET-TOKEN-123", "b").unwrap();
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("SECRET-TOKEN-123"), "token leaked in Debug");
    }

    /// Live test có kiểm soát — CHỈ chạy khi có secrets, tách khỏi PR checks.
    /// `TELECRATE_BOT_TOKEN=... TELECRATE_TEST_CHAT_ID=... cargo test -- --ignored live_`
    /// Không in token/chat id ra output.
    #[test]
    #[ignore]
    fn live_bot_api_capability_probe() {
        let token = std::env::var("TELECRATE_BOT_TOKEN")
            .expect("thiếu TELECRATE_BOT_TOKEN — báo unverified, không giả live pass");
        let chat: i64 = std::env::var("TELECRATE_TEST_CHAT_ID")
            .expect("thiếu TELECRATE_TEST_CHAT_ID")
            .parse()
            .expect("TELECRATE_TEST_CHAT_ID không phải số");
        let t = BotApiHttpTransport::hosted(&token, "telecrate-probe").expect("build transport");
        // Payload xác định 8 KiB (không cần rand).
        let payload: Vec<u8> = (0u32..8192)
            .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
            .collect();
        let loc = t.upload(chat, &payload).expect("live upload");
        assert_eq!(loc.transport, TransportType::BotApiHttp);
        let back = t.download(&loc).expect("live download");
        assert_eq!(back, payload, "download không byte-identical");
        let delete_ok = t.delete(&loc).expect("live delete");
        // Chỉ in trạng thái boolean + size, không in locator/token.
        println!(
            "live probe: upload_ok=true download_identical=true delete_ok={delete_ok} bytes={}",
            payload.len()
        );
    }
}

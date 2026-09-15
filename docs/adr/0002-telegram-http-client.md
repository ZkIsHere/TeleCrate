# ADR 0002 — HTTP client cho Telegram Bot API: reqwest + rustls (không OpenSSL hệ thống)

Ngày: 2026-09-15. Trạng thái: chấp nhận (đã verify live).

## Bối cảnh

`BotApiHttpTransport` cần gọi `api.telegram.org` (HTTPS-only) từ daemon/CLI/test trên nhiều môi trường:
dev Windows, runner self-hosted Linux tối thiểu (vừa thiếu `cc`, không đảm bảo có `libssl-dev`).

## Lựa chọn

- **reqwest 0.12 `blocking`** + `json` + `multipart`, TLS = `rustls-tls-webpki-roots` (thuần Rust, roots bundle sẵn).
- Không dùng `default-tls` (openssl-sys cần header/lib hệ thống → gãy trên runner tối thiểu).
- Upload `sendDocument` multipart (`application/octet-stream`, tên file = hash nội dung);
  download `getFile` → GET file URL ngay (ephemeral, không lưu); delete `deleteMessage`.
- Lỗi: 429 → `Transient` (+ `retry_after`), 401 → `Permanent` (token sai/revoke), còn lại `Permanent`
  kèm description đã redact. Token không xuất hiện trong error/Debug/log (custom `Debug`, helper `redact`, unit test).

## Hệ quả

- Build không cần OpenSSL hệ thống — đã pass trên runner `ci-cd` sau khi chỉ cài `build-essential`.
- Giữ `blocking` client trong M1 để probe/test đơn giản; M2 (worker async trong daemon tokio) đánh giá lại:
  chuyển sang reqwest async hoặc bọc `spawn_blocking` để không nghẽn runtime.

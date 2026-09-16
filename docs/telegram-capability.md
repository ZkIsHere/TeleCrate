# Telegram capability spike — M1 (đang thực hiện)

> Ngày kiểm tra tài liệu: 2026-09-15. Mọi giới hạn phải được xác minh bằng test hành vi thật trên channel thử nghiệm, không suy đoán từ tên API.

## Tài liệu chính thức đã đối chiếu

- S3 overview & consistency: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html
- S3 API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html
- Telegram Bot API: https://core.telegram.org/bots/api
- Telegram Bot FAQ: https://core.telegram.org/bots/faq
- MTProto bot authorization: https://core.telegram.org/api/bots
- TDLib: https://core.telegram.org/tdlib
- MTProto channel deletion: https://core.telegram.org/method/channels.deleteMessages
- PBS storage/S3 backend: https://pbs.proxmox.com/docs/storage.html

## Phân biệt transport (không thay thế nhau khi chưa kiểm chứng)

| Đường | Identity | Khi nào dùng |
|---|---|---|
| HTTP Bot API | bot token | Mặc định M1 — đơn giản nhất, test trước |
| Local Bot API | bot token, server tự host | Nếu giới hạn file/khả dụng của hosted API không đủ — test riêng |
| MTProto bot (api_id/api_hash + bot token, vd. TDLib) | bot, KHÔNG phải user session | Chỉ khi HTTP/Local không đáp ứng manifest/GC/history — không dùng để né flood control |

Không chuyển sang user session khi gặp lỗi. Không quay vòng tài khoản/bot để né rate limit.

## Checklist capability (channel thử nghiệm + quyền admin tối thiểu)

- [ ] upload document binary (không gửi theo đường biến đổi nội dung), tên/caption không lộ object key/khóa
- [ ] download byte-identical
- [ ] refresh file reference / locator hết hạn
- [ ] message lookup / history access trong phạm vi bot cho phép
- [ ] xóa message cũ (`deleteMessage` Bot API vs `channels.deleteMessages` MTProto — ghi quyền + lỗi thực tế)
- [ ] flood control: 429/Retry-After/FLOOD_WAIT, backoff + jitter, circuit breaker
- [ ] chunk size cấu hình được theo transport + đo hiệu năng (không gom file khổng lồ mặc định)

## Trạng thái

- `implemented-and-tested` (local): `Transport` trait + `BotApiHttp` types + error taxonomy + mock upload/download/delete tests.
- `implemented-and-tested` (live, 2026-09-15): `BotApiHttpTransport` qua hosted Bot API —
  probe 8 KiB lên chat thử nghiệm do chủ dự án cấp: `upload_ok=true`,
  `download_identical=true` (byte-for-byte), `delete_ok=true`. Gửi document binary
  (`application/octet-stream`, tên file = hash nội dung, không lộ key).
- `implemented-and-tested` (live group, 2026-09-15): probe 8 KiB lặp lại trên basic group
  thử nghiệm: `upload_ok=true`, `download_identical=true`, `delete_ok=true`. Tin nhắn probe
  tự xóa sau vài giây (`disable_notification=true`). Quyền bot xác minh qua
  `getChatAdministrators`: `administrator` với `can_post_messages=true`,
  `can_delete_messages=true` — đủ cho upload/delete của TeleCrate (bot `@Elisofa_Bot`).
  Job `live-telegram` trên CI chạy probe vào chính group này (chat id trong Actions Secrets).
- `implemented-and-tested` (live S3 e2e, 2026-09-16): `tests/live_e2e.rs` chạy trong CI job
  `live-telegram` — PUT object qua S3 → worker upload lên group → spool GC → GET đọc từ Telegram
  byte-identical → DELETE dọn DB/spool/remote. Vòng đời durable đầy đủ đầu-cuối trên Telegram thật.
- Ràng buộc nền tảng (xác nhận với chủ dự án 2026-09-15): nâng group lên supergroup/`-100...`
  gần như bất khả thi trong môi trường này. Vì vậy các kiểm tra đặc thù channel/supergroup
  (quyền admin tối thiểu, `channels.deleteMessages` MTProto) ghi `blocked` với lý do rõ ràng,
  không chặn M2. Thiết kế recovery (M5) giả định trường hợp xấu nhất: bot không duyệt lịch sử
  (Bot API không có API search) → checkpoint phải có con trỏ ngoài.
- Chưa kiểm chứng live: refresh locator hết hạn, 429/FLOOD_WAIT thực tế (error mapping mới unit-test).
- Secrets (bot token, test chat id) chỉ nằm trong GitHub Actions Secrets + biến môi
  trường local, không bao giờ vào code/log. Job `live-telegram` tách khỏi PR checks,
  skip khi thiếu secrets (= `unverified`). An toàn khi repo chuyển public.

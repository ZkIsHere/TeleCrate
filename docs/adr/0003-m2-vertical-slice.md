# ADR 0003 — Thiết kế M2: vertical slice durable PUT/GET (single-part)

Ngày: 2026-09-15. Trạng thái: đề xuất — triển khai theo breakdown bên dưới, điều chỉnh khi gặp bằng chứng ngược.

## Phạm vi (single-part; multipart → M3, presigned/STS/policy → M4)

- Bucket: `CreateBucket` / `HeadBucket` / `DeleteBucket` (từ chối bucket không rỗng) / `ListBuckets`.
- Object: `PutObject` / `GetObject` (+ `Range` đơn giản) / `HeadObject` / `DeleteObject` / `DeleteObjects` (số lượng nhỏ) / `ListObjectsV2` (prefix, delimiter, pagination).
- Addressing path-style; virtual-hosted-style → M4. Streaming không `Content-Length` → từ chối rõ ở M2 (ghi nhận, không âm thầm buffer vô hạn).

## Auth (tối giản có chủ đích)

- SigV4 header (`Authorization: AWS4-HMAC-SHA256...`) cho mọi op M2; kiểm tra canonical request, scope ngày/region/service `s3`, clock skew ±15 phút, `x-amz-content-sha256` (gồm `UNSIGNED-PAYLOAD` theo đúng API client gửi).
- Keys lấy từ **config file** (quyền 0600), chưa có bảng `access_keys`/policy — dời sang M4 cùng bucket policy/deny. Nhiều key/instance ở M2 chỉ là danh sách tĩnh trong config, chưa phân quyền prefix.

## Chunking & giới hạn Telegram

- Bot API có giới hạn kích thước file riêng cho upload/download (hosted API khác Local Bot API/MTProto).
  Mới đo live 8 KiB — giới hạn thật chưa đo. Quyết định an toàn: `chunk_size_bytes` cấu hình được,
  **mặc định 8 MiB** (dưới ngưỡng download 20 MB của Bot API có biên độ), mỗi chunk = 1 document message.
- Mọi object đều đi qua chunk map ngay từ M2 (kể cả object nhỏ) để worker/GC/recovery được kiểm thử thật.

## ETag & checksum (tách bạch)

- `ETag` = MD5 hex của **plaintext** cho single-part (đúng semantics S3), độc lập chế độ mã hóa TeleCrate.
- Lưu riêng `plaintext_sha256` (toàn vẹn đầu-cuối) và `ciphertext_sha256` (toàn vẹn blob remote). Thêm crate `md5`.

## Mã hóa nội dung (OPTIONAL, toggle `encryption = off|on`)

- Off: lưu plaintext + checksum, không yêu cầu content key.
- On: ChaCha20-Poly1305 (thuần Rust, `chacha20poly1305` crate), nonce 96-bit ngẫu nhiên mỗi chunk,
  AAD = `version_id || chunk_idx` (chống reorder), envelope: `key_id` lưu theo chunk.
  Khóa instance nằm trong **file riêng** (`content_key_file`, 0600), tham chiếu bằng `key_id`;
  đổi toggle chỉ ảnh hưởng ghi mới; không re-encrypt toàn kho (job migration riêng ở M5+).
- Sai key / tamper / reorder / truncate phải fail đóng (authenticated) và có test.

## Worker & publication (M2)

- `PUT` → spool durable từng chunk → **một** DB txn (object `accepted-local` + chunks `pending` + job) → trả S3.
  Không giữ txn mở qua network.
- Worker trong `serve` (tokio task): poll `upload_jobs` sẵn sàng, claim bằng lease
  (`lease_owner` = instance id, window 60 s), gọi `BotApiHttpTransport` qua `spawn_blocking`
  (client blocking — xem ADR 0002), concurrency 2, backoff theo `TransportError` + Retry-After.
- Commit remote: `remote_locator_json` + chunk `remote` trong txn ngắn. GC spool file khi mọi chunk của
  version đã `remote`. Đơn giản hóa M2: chưa có recovery checkpoint ngoài (→ M5); ghi nhận rủi ro.
- Đọc: spool → Telegram trực tiếp (cache đọc tắt). Range phục vụ theo chunk, chunk mã hóa phải verify
  toàn đơn vị AEAD trước khi trả plaintext.

## Kiểm thử M2 (Definition of Done)

- Unit + crash injection (`kill -9` tại các điểm: giữa spool/DB/response/worker/GC) + restart không mất acknowledged object.
- AWS CLI local (`put/get/list/delete`, Unicode key, object rỗng, Range, ETag MD5) — rclone/SDK để M7.
- Cả hai chế độ mã hóa, đổi toggle không phá dữ liệu cũ, wrong-key/tamper tests, grep log 0 secret.

## Breakdown changesets

- **2.1**: config keys + SigV4 verify + bucket CRUD + error XML chuẩn + tests.
- **2.2**: PUT/GET/HEAD/DELETE/LIST durable single-chunk (chưa mã hóa) + ETag MD5 + worker tối giản (poll + upload + commit + GC).
- **2.3**: multi-chunk (`chunk_size_bytes`, mặc định 8 MiB) + worker lease/backoff/concurrency đầy đủ.
- **2.4**: mã hóa on (AEAD) + toggle + tamper/wrong-key tests.
- **2.5**: crash injection + AWS CLI conformance + đóng M2 (matrix + docs).

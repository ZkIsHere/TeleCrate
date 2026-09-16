# Kiến trúc TeleCrate

> Ngôn ngữ: tiếng Việt. Thuật ngữ kỹ thuật (S3, spool, WAL, AEAD...) giữ tiếng Anh.
> Ngày kiểm chứng tài liệu tham chiếu: 2026-09-15. Phiên bản S3/Telegram/PBS ghi trong compatibility matrix.

## 1. Tổng quan

TeleCrate là object storage tương thích S3, single-instance, self-hosted trên Linux, dùng Telegram làm blob backend.

Luồng ghi bền vững local-first:

```
S3 client → (SigV4 auth) → HTTP daemon → spool file (tmp+fsync+rename+fsync dir)
→ SQLite WAL txn (object version + chunk map + job) → S3 response (accepted-local)
→ worker nền: lease job → upload Telegram (Bot API, sau này Local Bot API/MTProto) → commit remote locator + recovery checkpoint → GC spool chunk khi an toàn
```

Hai trạng thái cam kết phân biệt rõ (xem prompt §4; triển khai ở M2 theo ADR 0003):

- **HTTP dispatch M2.1**: `GET /` có `Authorization` → S3 `ListBuckets`, không auth → index skeleton;
  `GET /{bucket}` không `?location` → 501 `NotImplemented` (ListObjects ở 2.2). Mọi S3 response mang
  `x-amz-request-id`; lỗi theo mã XML chuẩn (`NoSuchBucket`, `BucketNotEmpty`, `SignatureDoesNotMatch`...).

- `accepted-local`: object đầy đủ đã commit bền vững local (data + metadata), đọc lại được sau crash nếu disk còn. PUT/CompleteMultipartUpload trả thành công tại đây.
- `telegram-committed`: mọi chunk đã có remote locator bền vững trong DB + recovery metadata đạt checkpoint an toàn. Chỉ lúc này mới được giải phóng spool.

GET/HEAD/LIST sau ghi thành công phải thấy ngay version vừa ghi, kể cả khi worker chưa chạy. DELETE thành công ẩn version theo S3 semantics ngay, blob Telegram dọn sau qua GC.

## 2. Thành phần (trạng thái triển khai kè từng mục — chi tiết ở `milestones.md`)

- **binary duy nhất `telecrate`** (Rust): subcommands `init/serve/status/doctor/migrations` dùng chung lib.
  `implemented-and-tested` ở M0-M1 cho config/DB/spool/transport; HTTP S3 API, admin API,
  scheduler/worker, dashboard tĩnh là `planned` (M2/M6). Hiện tại `/health` + `/` chỉ là endpoint skeleton —
  không mock S3 200.
- **CLI vs daemon**: mục tiêu CLI gọi admin API khi daemon chạy. HIỆN TẠI `init/doctor/migrations`
  mở DB trực tiếp và chưa có pid lock — `partial`, khóa single-daemon + pid lock làm ở M2 cùng worker.
- **SQLite (WAL)**: index bucket/object/version/chunk/jobs/multipart/policies/retention/migrations/checkpoints. Xem `data-model.md`.
  Migration `0001_init` đã có (M0); các bảng còn lại thêm dần theo milestone. Backup nhất quán
  (`VACUUM INTO` / copy sau checkpoint) là `planned` (M5) — hiện `migrations apply` chỉ copy file DB làm backup.
- **spool filesystem**: thư mục data riêng, file chunk đặt tên theo content-hash/job-id, KHÔNG dùng object key trực tiếp làm path (chặn path traversal). Quota + high/low watermark + reserved free space. Không LRU cho pending data.
- **read cache (OPTIONAL, mặc định tắt/quota 0)**: chỉ chứa bản tái tải được, eviction riêng, không chiếm quota spool.
- **Telegram transport trait** (`src/telegram.rs`, `implemented-and-tested` M1): `BotApiHttpTransport`
  thật (upload document binary / download qua `getFile` / delete, verify live 2026-09-15) +
  `MockTransport` cho unit test; `LocalBotApi` / `MtprotoBot` thêm sau qua capability test.
  DB lưu transport type + chat/channel/message/file_id + locator metadata. `file_unique_id` không thay
  `file_id`. URL/file_reference coi là ephemeral, refresh khi cần. Lỗi phân loại Transient/Permanent
  cho scheduler; token luôn redact trong error/Debug (có test). Chi tiết: `telegram-capability.md`.
- **Scheduler** (`planned`, M2): global/per-bot/per-chat bounded concurrency, backoff + jitter, tôn trọng Retry-After/FLOOD_WAIT, circuit breaker, phân biệt lỗi tạm thời vs vĩnh viễn (token sai, mất quyền, channel xóa).
- **Frontend tĩnh**: build một lần (Vite), daemon serve, không cần Node.js runtime khi vận hành.

## 3. Durability & crash recovery

Publication = tmp file + flush/fsync + atomic rename + fsync directory + DB transaction. DB và FS không phải một transaction duy nhất nên phải chứng minh phục hồi tại từng điểm crash:

| Điểm crash | Trạng thái | Phục hồi khi khởi động |
|---|---|---|
| Giữa ghi tmp, trước rename | tmp mồ côi | startup reconciliation: xóa tmp không referenced sau grace period |
| Sau rename, trước DB commit | file mồ côi trên FS | reconciliation: file không có DB reference → xóa / đưa vào quarantine |
| Sau DB commit, trước S3 response | client retry | idempotency theo version-id/upload-id; không tạo version trùng |
| Sau S3 response, trước Telegram upload | accepted-local, job pending | worker tiếp tục lease job |
| Telegram đã nhận nhưng response mất | remote dư | dedup theo chunk hash + generation guard; không ghi đè location version mới bằng worker cũ |
| Sau remote commit, trước spool delete | chunk còn local + remote | GC idempotent: chỉ xóa khi refcount=0 và checkpoint an toàn |

Không giữ transaction DB mở suốt network upload. Job có `lease_owner, lease_expires, retry_count, next_attempt, generation`.

## 4. Đọc (GET/Range)

Thứ tự: pending spool → read cache (nếu bật) → Telegram. Coalesce concurrent miss cùng chunk. Range chỉ tải phần cần, nhưng với chunk mã hóa phải xác thực toàn bộ đơn vị AEAD trước khi trả plaintext. Khi cache tắt: stream hoặc dùng vùng tạm bounded rồi dọn sau request, không giữ lâu, không xâm lấn quota spool. Metadata cache phải invalidate đúng write/delete (strong consistency).

## 5. Xóa & GC

Logical delete (tombstone/delete-marker) tách khỏi physical cleanup. GC tôn trọng versions, references, retention, multipart, inflight reads. Lỗi xóa Telegram vào retry queue + dashboard, không báo "đã dọn" khi mới tombstone.

## 6. Triển khai

Native Linux systemd: `/etc/telecrate/`, `/var/lib/telecrate`, user riêng `telecrate`, hardening, readiness/liveness, graceful shutdown (ngừng nhận ghi mới, giữ durable jobs, không chờ hết hàng đợi Telegram). Xem `packaging/`.

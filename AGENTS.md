# AGENTS.md — Quy tắc làm việc cho TeleCrate

> Tài liệu hướng dẫn bằng tiếng Việt. Tên API, mã nguồn, thuật ngữ chuẩn giữ tiếng Anh.

## 1. Nguyên tắc chung

- Sản phẩm chạy thật, tự triển khai được trên Linux native qua systemd. Không mock endpoint trả 200 cho tính năng chưa làm.
- Một instance đơn, self-hosted, không máy chủ trung tâm / multi-tenant. Mỗi người tự nối bot/channel của mình.
- Backend nhận upload → commit bền vững local (spool + DB) → trả phản hồi S3 → worker upload Telegram ở nền.
- Phân biệt trạng thái triển khai trong mọi báo cáo: `implemented-and-tested`, `implemented-unverified`, `partial`, `blocked`, `unsupported`.
- Không hardcode thông số homelab (2 vCPU / 2 GB RAM / 100 GB / 62 GB / 25.000 objects) vào sản phẩm; chỉ dùng làm fixture kiểm thử hiệu năng.
- Không đọc/ghi/xóa trực tiếp cache PBS. Không chạm datastore PBS thật khi chưa được phép.

## 2. Coding rules

- Stack chính: Rust stable (edition 2021+), SQLite (WAL) cho index/jobs, spool là filesystem riêng, frontend build tĩnh phục vụ bởi daemon. Xem `docs/adr/0001-stack.md`.
- RAM bounded: stream chunk, không load toàn bộ object vào RAM. Multipart temp, spool, read-cache, DB/logs có quota riêng.
- Publication bền vững: file tạm + flush/fsync + atomic rename + fsync directory + DB transaction. DB và FS không phải một transaction — phải chứng minh phục hồi tại từng điểm crash (xem `docs/architecture.md`).
- Không giữ transaction DB mở suốt network upload. Worker dùng job bền vững: lease/claim, retry count, next-attempt, generation guard.
- S3 semantics lấy từ tài liệu chính thức, không suy đoán từ tên API. ETag không luôn là MD5. Folder chỉ là prefix.
- Mã hóa nội dung OPTIONAL (bật/tắt rõ ràng). Primitive AEAD chuẩn, envelope encryption, nonce duy nhất, AAD gắn chunk identity. Tách plaintext checksum / ciphertext checksum / ETag S3.
- Bảo mật: service user riêng, quyền thư mục chặt, không log bot token / S3 secret / presigned query / key. S3 secret lưu để kiểm HMAC dưới bảo vệ thích hợp; admin password dùng hash chuẩn. Chặn path traversal qua object key; không dùng key trực tiếp làm đường dẫn spool. Hạn chế SSRF cho webhook.
- CLI và web dùng chung service/business logic; CLI không sửa DB trực tiếp khi daemon đang chạy (đi qua API/socket).
- Mọi endpoint/metric/log phải có trạng thái thật: loading/empty/error/offline/permission. Cấm chart mock, metric hardcode trong production.

## 3. Quy trình migrations

- Migrations SQL có version, forward-only, lưu tại `migrations/NNNN_ten.sql`.
- Mỗi migration phải có: backup DB trước khi apply (tự động trong `telecrate migrations apply`), downgrade constraint ghi rõ (rollback chỉ khi được thiết kế, mặc định không auto-rollback dữ liệu).
- CI kiểm tra migrations: apply từ 0 lên head trên DB trống + apply tuần tự từng version đều pass (`cargo test migrations`).
- Không sửa migration đã release; chỉ thêm migration mới. Khóa ngăn hai daemon dùng cùng state (pid lock + `schema_version` check).

## 4. Bảo mật & secrets

- Không commit secrets, DB/spool/cache runtime, recovery bundle chứa secrets. Xem `.gitignore`.
- Backup DB đầy đủ có secrets phải mã hóa riêng; hoặc loại secrets ra và yêu cầu cấu hình lại khi restore. Recovery index không chứa secrets khi mã hóa nội dung tắt.
- Dashboard: session protection, CSRF, rate-limit login, secret redaction, audit config changes. Export log có redaction + retention để không đầy ổ.

## 5. Kiểm thử & tiêu chí hoàn thành (Definition of Done)

- Mỗi changeset: thay đổi → kiểm tra local → commit → push nhánh → kiểm tra CI của đúng SHA → chỉ khi required checks xanh mới sang bước tiếp theo.
- Required checks trên push/PR: fmt (`cargo fmt --check`), clippy (`-D warnings`), build (backend/CLI/frontend), unit/integration + conformance chạy được local, kiểm tra migrations, package Linux (systemd unit + config mẫu validate).
- Live Telegram/PBS tests cần secrets tách khỏi PR checks; thiếu secrets báo `unverified`, không giả live pass.
- Khi CI fail: chỉ làm chẩn đoán + sửa để xanh lại; không phát triển tính năng khác, không bỏ test / `continue-on-error` / sửa workflow để che lỗi.
- Crash injection tại ranh giới file/DB/remote/metadata/spool-delete; restart không mất object đã acknowledged nếu disk còn nguyên.
- S3 conformance: AWS CLI, rclone, ≥1 SDK; auth sai, policy deny, Unicode keys, multipart, Range, concurrent overwrite/delete/versioning, ETags.
- Cache đọc mặc định tắt/quota 0 phải được kiểm tra: spool giảm sau upload an toàn, không giữ bản sao transport âm thầm, không xóa pending khi đầy ổ.
- Mọi tính năng advanced thiếu phải có trạng thái cụ thể trong compatibility matrix, không lặng lẽ bỏ khỏi phạm vi.

## 6. Quy tắc commit & Git

- Mọi thay đổi qua Git: source, tests, docs, CI, migrations, config mẫu, packaging. Không gom toàn bộ dự án vào một commit cuối.
- Giữ thay đổi của người dùng; không reset/rebase/force-push để làm sạch trạng thái.
- Commit message: `<scope>: <mô tả ngắn>` + body lý do. Ví dụ: `spool: dọn chunk sau telegram-commit an toàn`.
- Không commit secrets. Review `git status` + `git diff` trước mỗi commit. Không tự tạo remote công khai hay đổi quyền repo.

## 7. Tài liệu bắt buộc

- `docs/architecture.md`, `docs/data-model.md`, `docs/threat-model.md`, `docs/compatibility-matrix.md`, `docs/milestones.md` luôn cập nhật theo code.
- Quyết định quan trọng ghi ADR tại `docs/adr/NNNN-*.md`.
- Giao tiếp và tài liệu hướng dẫn bằng tiếng Việt.

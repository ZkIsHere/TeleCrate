# TeleCrate

[![Version](https://img.shields.io/badge/version-0.3.1-blue.svg)](https://github.com/ZkIsHere/TeleCrate/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable%202021-orange.svg)](https://www.rust-lang.org)
[![S3 Compatibility](https://img.shields.io/badge/S3-Compatible-blueviolet.svg)](docs/compatibility-matrix.md)
[![Platform](https://img.shields.io/badge/platform-Linux%20Native%20(systemd)-lightgrey.svg)](docs/install.md)
[![Offline](https://img.shields.io/badge/frontend-100%25%20Offline%20(Zero%20CDN)-success.svg)](src/dashboard/)

**TeleCrate** là giải pháp Cổng lưu trữ đối tượng (Object Storage Gateway) tương thích chuẩn **Amazon S3 API**, sử dụng tài nguyên kênh/nhóm của **Telegram Bot API** làm kho lưu trữ đám mây bền vững ở tầng backend.

Sản phẩm được thiết kế theo kiến trúc **đơn phiên bản (single instance), tự host (self-hosted)** trên máy chủ Linux native thông qua **systemd**, với cơ chế cam kết cục bộ trước (**Local-First Durable Spool + SQLite WAL Index**) và hàng đợi worker tải lên Telegram bất đồng bộ trong nền.

---

## ⚡ Cài đặt Nhanh 1-Line (Khuyên dùng cho Linux)

Chỉ cần một câu lệnh duy nhất trên máy chủ Linux (Ubuntu, Debian, CentOS/RHEL/Rocky Linux):

```bash
curl -fsSL https://raw.githubusercontent.com/ZkIsHere/TeleCrate/master/install.sh | bash
```

Kịch bản cài đặt tự động [`install.sh`](install.sh) sẽ:
1. Nhận diện kiến trúc hệ thống (`amd64` / `arm64`) và tải bản binary release `v0.3.1` mới nhất.
2. Khởi tạo system user `telecrate` và thiết lập các thư mục dữ liệu với quyền hạn bảo mật nghiêm ngặt (`700/750`).
3. Mở **Wizard tương tác thông minh**: hỏi mật khẩu Admin Dashboard, Telegram Bot Token, Chat ID, cổng dịch vụ và tự động sinh cặp S3 Access Key ban đầu.
4. Tự động sinh file cấu hình `/etc/telecrate/telecrate.toml` (quyền `600`).
5. Đăng ký, kích hoạt và khởi chạy dịch vụ **Systemd native** (`telecrate.service`).
6. In bảng tổng kết thông tin URL Dashboard, mật khẩu quản trị và thông số S3 Client để sử dụng ngay lập tức!

---

## 🖥️ Giao diện Quản trị Web Dashboard (v2)

TeleCrate tích hợp sẵn Web Dashboard trực tiếp trong binary daemon (`http://localhost:7070`), chạy **hoàn toàn offline** (không dùng CDN, không font chữ bên ngoài), tuân thủ phong cách **Restrained Ops** (tương tự GitHub/AWS/Grafana):

* **Fluid Full-Width Layout**: Trải rộng tràn viền trên mọi kích thước màn hình (1080p, 2K, 4K, Ultrawide) kèm chế độ Dark / Light Mode.
* **Biểu đồ đường (Line Charts) thời gian thực**: Sử dụng HTML5 Canvas 2D thuần, hiển thị 4 biểu đồ lưới 2×2:
  * **Objects**: Biến động số lượng đối tượng lưu trữ theo thời gian.
  * **Spool Usage**: Dung lượng spool chiếm dụng trên ổ cứng local.
  * **Storage Growth**: Tăng trưởng dung lượng cơ sở dữ liệu.
  * **Job Pipeline**: Trạng thái thông lượng worker upload nền.
* **Trình duyệt Tệp tin Phân cấp Chuẩn AWS S3 (Hierarchical File Browser)**:
  * Duyệt theo cây thư mục với `prefix` và `delimiter=/`.
  * Điều hướng nhanh qua thanh Breadcrumb.
  * Bảng trượt **Slide-out Side Panel** xem chi tiết siêu dữ liệu (Full Key, Bucket, kích thước, ETag, Version ID, Content-Type, trạng thái).
  * Hộp kiểm chọn nhiều tệp tin (**Multi-select**) và thanh công cụ xóa hàng loạt (**Batch Delete**).
* **Quản lý Access Keys v2**:
  * Phân quyền truy cập theo từng bucket cụ thể.
  * Nút chuyển đổi nhanh trạng thái `Active` / `Inactive` (key inactive bị SigV4 chặn ngay lập tức).
  * Theo dõi mốc thời gian sử dụng lần cuối (`last_used_at`).
  * Secret key chỉ hiển thị **duy nhất 1 lần** lúc tạo bằng CSPRNG, vĩnh viễn không lưu hay render ra DOM bảng.
* **Giám sát Jobs & Pipeline Bar**:
  * Thanh 4 trạng thái trực quan: `pending`, `uploading`, `completed`, `failed` (click để lọc bảng).
  * Tự động làm mới dữ liệu mỗi 5 giây.
* **Bảo trì & Hủy Multipart Uploads dở dang**:
  * Bảng giám sát các phiên multipart upload đang thực hiện.
  * Nút **"Hủy upload"** (Abort) giúp giải phóng ngay lập tức các chunk tạm thời trong spool.
  * Chạy Garbage Collection (GC), Doctor kiểm tra sức khỏe DB/spool, và Sao lưu DB index một chạm.
* **Nhật ký Kiểm toán (Audit Logs)**: Lọc mức độ theo segment (`ALL`, `INFO`, `WARN`, `ERROR`), tìm kiếm, phân trang và xuất tệp JSON an toàn đã qua redact bí mật.

---

## 🔌 Tương thích S3 & Kết nối Client

TeleCrate tương thích cao với chuẩn AWS S3 API (được kiểm chứng qua AWS CLI v2, rclone, MinIO `mc` và các S3 SDKs):

* **Xác thực & Chữ ký**: AWS Signature Version 4 (SigV4) dạng Authorization Header và Presigned URL query string; POST Form Policy upload.
* **Quản lý Bucket & Đối tượng**: Bucket CRUD, Location Constraint, Object PUT/GET/HEAD/DELETE, CopyObject (zero-copy spool reference), Batch Delete (`DeleteObjects`).
* **Truy vấn Dải & Điều kiện**: HTTP Range requests (206 Partial Content), `If-Match`, `If-None-Match` (304/412), `If-Modified-Since`, `If-Range`.
* **Upload Nhiều phần (Multipart Uploads)**: `CreateMultipartUpload`, `UploadPart`, `ListParts`, `CompleteMultipartUpload`, `AbortMultipartUpload`.
* **Phiên bản Đối tượng (Versioning)**: Bucket Versioning (Enabled/Suspended), Delete Markers, versioned GET/HEAD/DELETE (`?versionId=...`).
* **Bảo mật & Quản trị Nâng cao**:
  * Mã hóa nội dung tùy chọn: **ChaCha20-Poly1305 AEAD** (tách biệt ETag plaintext và ciphertext checksum).
  * SSE-S3 & SSE-C Cryptographic validation.
  * CORS Engine (OPTIONS preflight matching, XML configuration).
  * Bucket Policy Engine (Deny precedence, principal matching, action wildcards).
  * Block Public Access (BPA) bảo vệ chống lộ dữ liệu.
  * Object Lock WORM Gateway (GOVERNANCE, COMPLIANCE mode, Legal Hold).

### Ví dụ Cấu hình AWS CLI

```ini
# ~/.aws/credentials
[default]
aws_access_key_id = AKIAEXAMPLE12345
aws_secret_access_key = your-secret-key-here

# ~/.aws/config
[default]
region = us-east-1
endpoint_url = http://localhost:7070
s3 =
    addressing_style = path
```

```bash
# Tạo bucket
aws s3 mb s3://my-bucket

# Tải file lên
aws s3 cp document.pdf s3://my-bucket/

# Duyệt danh sách
aws s3 ls s3://my-bucket/

# Tải file về
aws s3 cp s3://my-bucket/document.pdf ./downloaded.pdf
```

### Ví dụ Cấu hình rclone

```ini
# ~/.config/rclone/rclone.conf
[telecrate]
type = s3
provider = Other
env_auth = false
access_key_id = AKIAEXAMPLE12345
secret_access_key = your-secret-key-here
endpoint = http://localhost:7070
```

---

## ⚙️ Cấu hình Daemon (`/etc/telecrate/telecrate.toml`)

```toml
# Đường dẫn lưu trữ cơ sở dữ liệu chỉ mục SQLite (chế độ WAL tự động)
db_path = "/var/lib/telecrate/telecrate.db"

# Thư mục lưu trữ tạm spool cho các chunk dữ liệu local-first
spool_dir = "/var/lib/telecrate/spool"

# Cổng lắng nghe HTTP phục vụ S3 Gateway, Admin REST API và Web Dashboard
listen_port = 7070

# Mã hóa dữ liệu nội dung: "off" | "on" (ChaCha20-Poly1305 AEAD)
encryption = "off"

# Mật khẩu quản trị Web Dashboard & Admin API
admin_password = "mat-khau-quan-tri-secure"

# Cấu hình kết nối Telegram Bot API làm backend lưu trữ bền vững
telegram_bot_token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
telegram_chat_id = -1001234567890

# Kích thước chunk upload Telegram (mặc định 8 MiB)
chunk_size_bytes = 8388608

# Số lượng worker đồng thời tải dữ liệu lên Telegram nền (1..8)
worker_concurrency = 2

# Access keys tĩnh mặc định khởi tạo
[[access_keys]]
access_key_id = "AKIAEXAMPLE12345"
secret_key = "secret1234567890secret1234567890"

# Nhật ký hệ thống
log_level = "info"
log_to_file = true
log_dir = "/var/log/telecrate"
log_retention_days = 14
```

---

## 🛡️ Quản lý Dịch vụ Systemd (Linux Native)

TeleCrate được đóng gói sẵn file unit `telecrate.service` với các lớp bảo vệ bảo mật hệ thống nghiêm ngặt:

```bash
# Kiểm tra trạng thái hoạt động
sudo systemctl status telecrate

# Xem nhật ký hệ thống thời gian thực
sudo journalctl -u telecrate -f

# Khởi động / Dừng / Khởi động lại
sudo systemctl restart telecrate
sudo systemctl stop telecrate
sudo systemctl start telecrate
```

---

## 💻 Phát triển & Kiểm thử Cục bộ (Dev)

Yêu cầu môi trường: **Rust stable 1.88+**.

```bash
# Kiểm tra định dạng mã nguồn chuẩn
cargo fmt --check

# Kiểm tra cảnh báo clippy nghiêm ngặt (-D warnings)
cargo clippy -- -D warnings

# Chạy toàn bộ test suite (54+ unit tests + integration tests)
cargo test

# Kiểm tra quá trình áp dụng DB migrations
cargo test migrations

# Chạy test kiểm thử trực tiếp Telegram (yêu cầu biến môi trường secrets)
TELECRATE_BOT_TOKEN=... TELECRATE_TEST_CHAT_ID=... cargo test -- --ignored live_
```

---

## 📚 Tài liệu Dự án

* [AGENTS.md](AGENTS.md) — Nguyên tắc cốt lõi, quy tắc lập trình, bảo mật và tiêu chuẩn nghiệm thu (Definition of Done).
* [RELEASE_NOTES.md](RELEASE_NOTES.md) — Chi tiết các thay đổi trong phiên bản mới nhất v0.3.1.
* [docs/install.md](docs/install.md) — Hướng dẫn cài đặt chi tiết trên Linux native và biên dịch từ mã nguồn.
* [docs/architecture.md](docs/architecture.md) — Kiến trúc hệ thống, quy trình ghi bền vững (Durable Commit) và cơ chế phục hồi sau sự cố.
* [docs/compatibility-matrix.md](docs/compatibility-matrix.md) — Ma trận tương thích chi tiết các API S3.
* [docs/disaster-recovery.md](docs/disaster-recovery.md) — Hướng dẫn sao lưu, phục hồi và xử lý sự cố thảm họa.
* [docs/milestones.md](docs/milestones.md) — Lịch sử hoàn thành các cột mốc tính năng từ M0 đến M7.

---

## 📄 Bản quyền (License)

Dự án được phát hành theo giấy phép [MIT License](LICENSE).

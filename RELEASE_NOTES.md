# TeleCrate v0.3.1 — Release Notes

Phiên bản **TeleCrate v0.3.1** là bản vá phát hành TLS native + DAL async dual-backend
SQLite/Postgres, đồng thời sửa 3 lỗi thật làm đỏ CI sau v0.3.0: worker lồng runtime
(panic `Cannot drop a runtime...` → live-e2e timeout), daemon mặc định HTTPS trong khi
script test gọi HTTP, và CLI hardcode HTTP.

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.1

### 1. DAL async dual-backend SQLite/Postgres + TLS native (phát hành chính thức)
* Toàn bộ DAL chuyển sang `telecrate::db::Db` async trên sqlx, hỗ trợ song song SQLite
  và Postgres (bind `?` một lần, tự rebind `$N`); DDL Postgres tương đương SQLite
  0001→0004 tại `migrations/postgres/`.
* Serve HTTPS mặc định (rustls/ring thuần Rust): chưa có cert/key thì tự sinh self-signed
  lúc khởi động, fingerprint SHA-256 cho client S3 bắt HTTPS; dashboard có fieldset
  TLS/HTTPS + tab **Kết nối** (preset PBS/AWS CLI/rclone).

### 2. Sửa worker lồng runtime gây timeout live-e2e
* `process_one_job` async gọi `transport.upload()` blocking bên trong `block_on`
  `current_thread` → panic và kẹt job ở `pending`. Tách `process_one_job_sync`:
  DB `block_on` từng bước ngắn, upload gọi **ngoài** mọi async context.
* Live Telegram e2e xanh trở lại (PUT → GET spool → worker remote → GET Telegram → DELETE).

### 3. Sửa HTTPS-vs-HTTP làm đỏ CI website/conformance
* `tests/website.sh` và job `awscli-conformance` trong CI tạo config thiếu `tls_enabled`
  nên rơi vào default `true` (HTTPS) trong khi curl/AWS CLI gọi `http://`.
* Đặt `tls_enabled = false` tường minh cho smoke test HTTP; CLI (`status/gc/config`)
  hỗ trợ cả hai scheme theo `tls_enabled`, chấp nhận self-signed local.

---

## 🔄 Hướng dẫn Nâng cấp từ v0.3.0 lên v0.3.1

Không có migration SQLite mới (schema giữ nguyên) — nâng cấp nhị phân, giữ DB/spool:

```bash
# 1. Dừng service
sudo systemctl stop telecrate

# 2. Tải binary v0.3.1 mới nhất và ghi đè
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.1/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/

# 3. Khởi động lại service
sudo systemctl start telecrate

# 4. Kiểm tra trạng thái hoạt động
sudo systemctl status telecrate
```

Lưu ý: daemon mặc định serve **HTTPS** (tự sinh self-signed nếu chưa có cert). Dashboard
mở qua `https://<host>:<port>/` (trình duyệt cảnh báo self-signed lần đầu); smoke test
nội bộ dùng `tls_enabled = false` để giữ HTTP.

---

# TeleCrate v0.3.0 — Release Notes

Phiên bản **TeleCrate v0.3.0** bổ sung cấu hình vị trí spool (dashboard + installer),
hỗ trợ chọn backend metadata DB SQLite/Postgres (partial), Admin API batch nguyên tử,
và sửa lỗi parse tag release trong `install.sh`.

---

## 🌟 Điểm nổi bật trong phiên bản v0.3.0

### 1. Cấu hình vị trí Spool
* Dashboard tab Cấu hình → fieldset **Lưu trữ**: ô `Thư mục spool` (đánh dấu ⟳ restart),
  validate absolute + cấm `..` (`src/config.rs`).
* `install.sh` wizard thêm mục **6. Thư mục spool local** (mặc định `/var/lib/telecrate/spool`,
  tự động hóa bằng `TELECRATE_SPOOL_DIR=/mnt/data/spool`), tự tạo thư mục + phân quyền `700`.

### 2. Backend metadata DB: SQLite / Postgres (partial — ADR 0005)
* `db_backend = "sqlite"` (mặc định, runnable duy nhất) | `"postgres"` + `database_url`
  (redact mọi nơi như bot token). Chọn qua TOML / `telecrate config set` / dashboard.
* Schema DDL Postgres đầy đủ tương đương SQLite 0001→0004 tại
  `migrations/postgres/0001_0004_schema.sql`; xem trước bằng `telecrate db pg-schema`.
* Runtime Postgres còn `blocked`: daemon từ chối khởi động rõ ràng thay vì fallback lén.

### 3. Admin API batch nguyên tử (`POST /admin/api/config` + `updates`)
* Lưu toàn bộ tab Cấu hình trong 1 request: đổi `db_backend` cần backend+URL cùng lúc,
  gửi từng key riêng lẻ trước đây kẹt ở trạng thái trung gian. Dashboard đã chuyển sang batch.

### 4. Sửa lỗi `install.sh` parse tag release
* GitHub API trả JSON 1 dòng làm parser cũ (`grep + cut -f4`) trích nhầm field `url`
  thành tag → URL download lồng nhau. Parser mới (ưu tiên `jq` → `python3` → `grep -o`),
  validate tag `vX.Y.Z`, retry curl + hiện lỗi chi tiết, pin version `TELECRATE_VERSION`.

---

## 🔄 Hướng dẫn Nâng cấp từ v0.2.0 lên v0.3.0

Không có migration SQLite mới (schema giữ nguyên) — nâng cấp nhị phân, giữ DB/spool:

```bash
# 1. Dừng service
sudo systemctl stop telecrate

# 2. Tải binary v0.3.0 mới nhất và ghi đè
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.3.0/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/

# 3. Khởi động lại service
sudo systemctl start telecrate

# 4. Kiểm tra trạng thái hoạt động
sudo systemctl status telecrate
```

---

# TeleCrate v0.2.0 — Release Notes

Phiên bản **TeleCrate v0.2.0** mang đến bản nâng cấp toàn diện về giao diện vận hành (Web Dashboard & Admin Console), trải nghiệm duyệt tệp tin chuẩn AWS S3, quản lý khóa truy cập nâng cao, và script cài đặt tự động 1-line (`install.sh`) cho môi trường Linux native.

---

## 🌟 Điểm nổi bật trong phiên bản v0.2.0

### 1. Kịch bản Cài đặt Tự động 1-Line (`install.sh`)
* Cài đặt toàn diện TeleCrate chỉ với một câu lệnh:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/ZkIsHere/TeleCrate/master/install.sh | bash
  ```
* Tự động phát hiện kiến trúc máy chủ (`amd64` / `arm64`), tải binary release mới nhất từ GitHub Releases.
* Tự động khởi tạo user hệ thống `telecrate`, phân quyền chặt chẽ các thư mục `/var/lib/telecrate` và `/var/lib/telecrate/spool`.
* **Wizard cấu hình thông minh** qua `/dev/tty`: Hướng dẫn nhập bot token Telegram, chat ID, mật khẩu admin (hoặc sinh ngẫu nhiên), cổng lắng nghe, mã hóa nội dung và tự sinh cặp Access Key S3 ban đầu.
* Tự động tạo và kích hoạt dịch vụ **Systemd native** (`telecrate.service`), kiểm tra trạng thái hoạt động và in bảng tóm tắt thông tin kết nối ngay trên terminal.

---

### 2. Giao diện Quản trị Web Dashboard v2 (Restrained Ops Console)
* **Thiết kế chuẩn vận hành (GitHub/AWS/Grafana)**: Typography hệ thống rõ nét, chế độ Sáng/Tối (Dark/Light mode), độ tương phản cao, layout tràn viền toàn màn hình (`fluid full-width`) không góc chết trên màn hình rộng 1080p/2K/4K.
* **100% Offline & Tự lưu trữ**: Không phụ thuộc bất kỳ CDN hoặc font chữ bên ngoài, an toàn và hoạt động hoàn hảo trong mạng nội bộ / homelab.
* **Hệ thống Biểu đồ đường (Line Charts) thời gian thực**:
  * Tự phát triển engine đồ họa trên **HTML5 Canvas 2D thuần**, hỗ trợ khử răng cưa DPI cao.
  * 4 biểu đồ đường trực quan bố trí dạng lưới 2×2 cân đối:
    1. **Objects**: Biến động số lượng đối tượng lưu trữ theo thời gian.
    2. **Spool Usage**: Dung lượng spool cục bộ chiếm dụng trên ổ cứng.
    3. **Storage Growth**: Tăng trưởng dung lượng lưu trữ cơ sở dữ liệu.
    4. **Job Pipeline**: Lưu lượng jobs chờ tải lên và đang tải lên nền.
  * Tự động co giãn mượt mà khi thay đổi kích thước cửa sổ trình duyệt (debounced resize listener).

---

### 3. Trình duyệt Tệp tin Phân cấp Chuẩn AWS S3 (Hierarchical File Browser)
* **Duyệt theo cây thư mục**: Hỗ trợ đầy đủ tiền tố (`prefix`) và dấu phân cách (`delimiter = '/'`), phân biệt rõ ràng giữa thư mục con (common prefixes) và tệp tin.
* **Thanh điều hướng Breadcrumbs**: Dễ dàng click chuyển đổi nhanh giữa các cấp thư mục hoặc quay về danh sách bucket.
* **Slide-out Side Panel**: Bảng trượt bên phải hiển thị toàn diện thông tin metadata của object (Full Key, Bucket, kích thước chính xác đến từng byte, ETag, Version ID, Content-Type, trạng thái spool/remote, thời điểm tạo/sửa đổi và nút xóa).
* **Multi-select & Batch Delete**: Chọn nhiều tệp tin cùng lúc qua hộp kiểm và xóa hàng loạt qua thanh công cụ nổi (sticky batch bar).

---

### 4. Nâng cấp Hệ thống Quản lý Access Keys (v2)
* **Migration `0004_dashboard_enhancements.sql`**: Bổ sung trường `last_used_at` và `allowed_buckets` cho bảng `access_keys`.
* **Phân quyền theo Bucket**: Giới hạn phạm vi truy cập của từng Access Key theo danh sách bucket cụ thể (hoặc `*` cho toàn quyền).
* **Bật/Tắt trạng thái tức thì**: Nút chuyển đổi nhanh `Active` ↔ `Inactive` qua API `PATCH /admin/api/access-keys/:id` mà không cần thu hồi key; client dùng key inactive sẽ bị SigV4 từ chối ngay lập tức.
* **Bảo mật Secret Key**: Secret key được sinh ngẫu nhiên bằng CSPRNG và **chỉ hiển thị duy nhất 1 lần** trong hộp thoại cảnh báo lúc tạo; không bao giờ lưu trữ hoặc render ra DOM bảng danh sách.

---

### 5. Tab Jobs & Giám sát Worker Pipeline
* **Thanh trạng thái Pipeline Bar**: Hiển thị số lượng jobs theo 4 trạng thái (`pending`, `uploading`, `completed`, `failed`), click vào từng ô để lọc nhanh bảng jobs.
* **Bảng theo dõi chi tiết**: Cung cấp Job ID, Bucket/Key, State badge, số lần thử lại (Retries), thời điểm chạy kế tiếp, Worker ID đang giữ lease, và chi tiết lỗi nếu gặp sự cố mạng.
* **Tự động làm mới**: Tự động reload số liệu mỗi 5 giây khi đang mở tab.

---

### 6. Tab Bảo trì & Quản lý Multipart Uploads
* **Giám sát Multipart dở dang**: Bảng liệt kê các phiên upload nhiều phần đang thực hiện (Upload ID, Bucket, Key, Content-Type, Initiated at).
* **Hủy upload một chạm (Abort Multipart)**: Nút hủy gọi trực tiếp `POST /admin/api/multipart/:id/abort` giúp dọn dẹp triệt để các chunk tạm thời trong spool, giải phóng dung lượng đĩa.
* **Công cụ bảo trì một chạm**: Tích hợp sẵn nút chạy Garbage Collection (`/admin/api/gc`), Doctor kiểm tra toàn vẹn DB/spool (`/admin/api/doctor`), và Sao lưu cơ sở dữ liệu (`/admin/api/backup`).

---

### 7. Cải tiến Hạ tầng CI/CD & Runner
* **Tự động cài đặt GitHub CLI (`gh`)**: Script `cd.yml` tự động tải bản static standalone của `gh` nếu máy self-hosted runner chưa cài đặt, khắc phục lỗi `gh: command not found`.
* **Chống nghẽn Runner (Deadlock Prevention)**: Job `gate-ci` trong CD ưu tiên kiểm tra CI run đã pass trước đó cho commit SHA, tránh tình trạng treo hoặc fail khi chạy trên môi trường 1 runner duy nhất.

---

## 📦 Danh sách Gói phát hành (Release Assets)

| Tên tệp tin | Mô tả |
|---|---|
| `telecrate-linux-amd64.tar.gz` | Binary release tối ưu hóa cho Linux x86_64 / amd64 |
| `telecrate-dev-linux-amd64.tar.gz` | Binary build có debuginfo |
| `telecrate_0.2.0_amd64.deb` | Gói cài đặt Debian/Ubuntu native |
| `telecrate-0.2.0-1.x86_64.rpm` | Gói cài đặt RedHat/CentOS/Rocky Linux native |

---

## 🔄 Hướng dẫn Nâng cấp từ v0.1.0 lên v0.2.0

Nếu bạn đang chạy TeleCrate v0.1.0, việc nâng cấp hoàn toàn tự động và an toàn (forward-only migrations):

```bash
# 1. Dừng service
sudo systemctl stop telecrate

# 2. Tải binary v0.2.0 mới nhất và ghi đè
curl -fsSL https://github.com/ZkIsHere/TeleCrate/releases/download/v0.2.0/telecrate-linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin/

# 3. Khởi động lại service (hệ thống sẽ tự động apply migration 0004)
sudo systemctl start telecrate

# 4. Kiểm tra trạng thái hoạt động
sudo systemctl status telecrate
```

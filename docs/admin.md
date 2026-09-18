# Hướng dẫn Quản trị & Vận hành TeleCrate

> Hướng dẫn sử dụng CLI, Web Dashboard, quản lý Access Keys, theo dõi chỉ số hệ thống và bảo trì định kỳ.

---

## 1. Web Dashboard Quản trị Tích hợp

TeleCrate tích hợp sẵn Web Dashboard ngay bên trong daemon single-binary (không cần build riêng,
chạy offline hoàn toàn — không font/CDN ngoài).

Giao diện vận hành tiết chế: font hệ thống, sáng/tối, bảng mật độ hợp lý, mọi màn hình có trạng thái
đang nạp/trống/lỗi/mất kết nối. Các tab: Tổng quan (số liệu thật từ daemon), Buckets (+xem objects),
Access keys (secret chỉ hiện đúng 1 lần lúc tạo, không render ra bảng), Cấu hình (validate trước apply,
đánh dấu trường cần restart), Bảo trì (GC/Doctor/Backup), Nhật ký (lọc mức + tìm kiếm + phân trang + xuất JSON).

### Logging daemon

- `log_level`: trace|debug|info|warn|error (mặc định `info`), áp dụng cả stdout (journald) và file.
- `log_to_file = true` + `log_dir` (mặc định `/var/lib/telecrate/logs`): file `telecrate.log.YYYY-MM-DD`
  rotation theo ngày; startup tự xóa file quá `log_retention_days` (mặc định 14).
- Không ghi secret/token/key material ra log (quy tắc AGENTS.md §4).

### Tab Cấu hình (dashboard)

- Fieldset **Lưu trữ**: `spool_dir` (absolute, cấm `..`, ⟳ restart),
  `db_backend = "sqlite" | "postgres"` (⟳ restart) + `database_url` (password input,
  chỉ gửi khi nhập mới; về `sqlite` tự xóa URL cũ).
- Nút Lưu gửi **batch nguyên tử** 1 request `POST /admin/api/config` (`{"updates": {...}}`):
  đổi backend cần backend+URL cùng lúc. API đơn key (`{"key","value"}`) vẫn tương thích.
- `database_url` redact ở GET config, audit log và CLI stdout như secret.

### TLS / HTTPS native (cho PBS S3)

- TeleCrate serve **HTTPS mặc định** trên cùng `listen_port` (PBS S3 bắt buộc HTTPS).
  Chưa cấu hình cert/key → daemon **tự sinh self-signed** lúc khởi động
  (`/var/lib/telecrate/tls.crt|tls.key`, key 0600) và in fingerprint ra log.
  Muốn về HTTP thuần: `tls_enabled = false` + restart (không khuyến nghị).
- Dashboard tab Cấu hình → fieldset **TLS / HTTPS** hiển thị trạng thái bất cứ lúc nào:
  bật/tắt, đường dẫn cert/key, Subject, SANs, hạn dùng, số ngày còn lại và
  **SHA-256 fingerprint** (`AA:BB:...`) để dán vào endpoint PBS (self-signed).
- Nút **Tự sinh self-signed** (ECDSA P-256, `POST /admin/api/tls/generate`): nhập CN
  (vd IP/hostname máy TeleCrate) + SANs cách nhau dấu phẩy + số ngày (1..825).
  Key ghi quyền 600. Sinh xong tick **Bật HTTPS** → Lưu → restart daemon.
- Tab **Kết nối**: helper nhập host/port, xem endpoint URL, chọn/tạo Access Key
  (secret chỉ hiện 1 lần), preset PBS (endpoint/port/path-style/fingerprint/bucket),
  snippet AWS CLI + nút chép, lệnh `s3 check`/`datastore create`.
- Trạng thái chi tiết qua API: `GET /admin/api/tls/status` (cần login, không trả key material).
- Dùng cert CA thật (Let's Encrypt) thì chép fullchain + key vào máy, nhập đường dẫn,
  bật HTTPS — PBS không cần fingerprint nữa.

### Audit log

- Ring-buffer in-memory 5000 bản ghi có cấu trúc `{ts, level, actor, action, detail}` (mới nhất trước).
- API `GET /admin/api/audit-logs?level=&q=&limit=&offset=` trả `{entries, total}`; detail đã redact ở server.
- Ghi nhận: tạo/xóa bucket, tạo/thu hồi key, GC, doctor, backup, đổi config (giá trị secret → `[REDACTED]`),
  login thành công/thất bại, logout. Login sai quá 10 lần/phút → 429.

---

## 2. Quản trị bằng Lệnh CLI (`telecrate`)

CLI của TeleCrate được thiết kế thông minh: **khi daemon đang chạy, CLI sẽ tương tác qua Admin REST API để không vi phạm khóa mở SQLite**.

### 2.1 Kiểm tra trạng thái hệ thống
```bash
telecrate --config /etc/telecrate/telecrate.toml status
```

### 2.2 Kích hoạt Garbage Collection (GC)
```bash
telecrate --config /etc/telecrate/telecrate.toml gc
```

### 2.3 Kiểm tra sức khỏe DB & Spool (Doctor / Verify)
```bash
# Doctor scan DB SQLite
telecrate --config /etc/telecrate/telecrate.toml doctor

# Verify SHA256 các file spool local
telecrate --config /etc/telecrate/telecrate.toml verify

# Scrubbing đối chiếu remote Telegram locators
telecrate --config /etc/telecrate/telecrate.toml scrub
```

---

## 3. Quản lý An toàn & Bảo mật

- **Secret Redaction**: Tất cả log xuất ra từ daemon hoặc Web Dashboard đều được tự động lọc bỏ Bot Token (`[REDACTED_BOT_TOKEN]`) và S3 Secret Key.
- **Session Protection**: Web Dashboard sử dụng cookie `telecrate_session` (HttpOnly + SameSite=Lax) kết hợp Header validation `x-csrf-token` bắt buộc cho mọi thao tác ghi/xóa.

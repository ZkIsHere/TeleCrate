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

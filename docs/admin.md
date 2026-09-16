# Hướng dẫn Quản trị & Vận hành TeleCrate

> Hướng dẫn sử dụng CLI, Web Dashboard, quản lý Access Keys, theo dõi chỉ số hệ thống và bảo trì định kỳ.

---

## 1. Web Dashboard Quản trị Tích hợp

TeleCrate tích hợp sẵn Web Dashboard giao diện hiện đại ngay bên trong daemon single-binary.

### Các tính năng chính trên Web Dashboard:
1. **Tổng quan (Overview)**: Theo dõi Uptime, dung lượng ổ đĩa spool local, dung lượng DB SQLite, tiến độ worker upload Telegram, tổng số Buckets, Objects và Chunks.
2. **Quản lý Buckets**: Tạo bucket mới, kiểm tra cấu hình Region & Versioning, xóa bucket rỗng.
3. **Quản lý Access Keys**: Khởi tạo Access Key S3 mới (Secret Key hiển thị duy nhất 1 lần khi tạo), thu hồi Access Key cũ.
4. **Bảo trì & GC (Maintenance)**: Thực thi thủ công Physical Garbage Collection (GC), Integrity Doctor scan, và sao lưu SQLite Online Backup.
5. **Audit Logs Viewer**: Xem nhật ký hoạt động hệ thống với cơ chế che giấu tự động (Secret Redaction) các Bot Token, S3 Secret Keys và Signatures.

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

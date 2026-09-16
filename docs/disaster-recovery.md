# Hướng dẫn Khôi phục Thảm họa (Disaster Recovery)

> Quy trình sao lưu, xuất bọc phục hồi (Recovery Bundle) độc lập và khôi phục hệ thống TeleCrate khi gặp sự cố phần cứng hoặc hỏng cơ sở dữ liệu.

---

## 1. Kịch bản 1: Sao lưu & Khôi phục Cơ sở dữ liệu SQLite

### 1.1 Tạo Online Backup (khi daemon đang chạy)
```bash
# Tạo backup không mã hóa
telecrate --config /etc/telecrate/telecrate.toml db backup --output /var/backups/telecrate_db.bak

# Tạo backup mã hóa AEAD bằng mật khẩu
telecrate --config /etc/telecrate/telecrate.toml db backup --output /var/backups/telecrate_db.enc --passphrase "my-secret-pass"
```

### 1.2 Phục hồi Database (khi daemon đã dừng)
```bash
# Phục hồi từ backup (tự động kiểm tra PRAGMA integrity_check và tạo safety_backup trước khi đè)
telecrate --config /etc/telecrate/telecrate.toml db restore --input /var/backups/telecrate_db.enc --passphrase "my-secret-pass"
```

---

## 2. Kịch bản 2: Standalone Recovery Bundle (Không cần DB SQLite)

Recovery Bundle lưu trữ toàn bộ chỉ mục buckets, objects, version_ids, chunk maps và Telegram locators dưới dạng file JSON độc lập.

### 2.1 Xuất Recovery Bundle
```bash
telecrate --config /etc/telecrate/telecrate.toml recovery export --output /var/backups/recovery_bundle.json --passphrase "dr-key-pass"
```

### 2.2 Nhập Recovery Bundle trên Server Mới
Khi máy chủ bị hỏng hoàn toàn và bạn thiết lập một server TeleCrate mới từ đầu:
```bash
# Nhập lại toàn bộ siêu dữ liệu index từ Recovery Bundle
telecrate --config /etc/telecrate/telecrate.toml recovery import --input /var/backups/recovery_bundle.json --passphrase "dr-key-pass"
```

---

## 3. Kịch bản 3: Sửa chữa & Đồng bộ Spool Local (Doctor Scan)

Nếu máy chủ bị khôi phục sau sự cố mất điện đột ngột:
```bash
# 1. Chạy Doctor để kiểm tra DB
telecrate --config /etc/telecrate/telecrate.toml doctor

# 2. Chạy Verify để quét checksum spool local
telecrate --config /etc/telecrate/telecrate.toml verify

# 3. Kích hoạt GC để giải phóng spool đã committed an toàn
telecrate --config /etc/telecrate/telecrate.toml gc
```

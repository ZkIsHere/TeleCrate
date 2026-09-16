# Hướng dẫn Cài đặt & Triển khai TeleCrate (Linux Native Systemd)

> Tài liệu hướng dẫn vận hành production cho TeleCrate trên Linux native.

---

## 1. Yêu cầu Hệ thống

- **Hệ điều hành**: Linux (Debian 11/12, Ubuntu 22.04/24.04 LTS, RHEL/Rocky Linux 9).
- **Phần cứng khuyến nghị**: 1-2 vCPU, ≥ 1 GB RAM, Ổ cứng SSD (cho SQLite WAL + Spool).
- **Quyền hạn**: Root hoặc `sudo` để tạo service systemd và user hệ thống `telecrate`.

---

## 2. Cài đặt từ Gói Đóng gói sẵn (`.deb` / Tarball)

> **Lưu ý**: Đường dẫn `wget` bên dưới là URL chuẩn khi tag release (ví dụ `v0.1.0`) đã được publish trên GitHub Releases. Nếu bạn đang chạy trực tiếp từ mã nguồn local, bạn có thể tự đóng gói bằng script `packaging/build-deb.sh` hoặc tự biên dịch bằng Cargo (xem Phần 2.3).

### Cách 1: Cài đặt gói `.deb` (Debian / Ubuntu)

```bash
# Tải gói cài đặt .deb (khi đã publish release trên GitHub)
wget https://github.com/ZkIsHere/TeleCrate/releases/download/v0.1.0/telecrate_0.1.0_amd64.deb

# Hoặc tự tạo gói .deb tại local từ repo mã nguồn:
./packaging/build-deb.sh

# Cài đặt gói .deb vừa tạo hoặc tải về
sudo dpkg -i telecrate_0.1.0_amd64.deb

# Đóng gói tự động khởi tạo user hệ thống telecrate, thư mục /var/lib/telecrate và service systemd.
```

### Cách 2: Cài đặt từ Mã nguồn Archive / Zip / Tarball

```bash
# Nếu tải file .zip (Source code zip từ GitHub Releases):
sudo apt install -y unzip # (Nếu chưa có unzip)
unzip TeleCrate-0.1.0.zip
cd TeleCrate-0.1.0

# Nếu tải file .tar.gz:
tar -xzvf TeleCrate-0.1.0.tar.gz
cd TeleCrate-0.1.0

# Copy binary vào /usr/bin
sudo cp bin/telecrate /usr/bin/
sudo chmod +x /usr/bin/telecrate

# Tạo user hệ thống telecrate
sudo useradd --system --user-group --no-create-home --shell /bin/false telecrate || true

# Tạo thư mục dữ liệu & cấu hình
sudo mkdir -p /etc/telecrate /var/lib/telecrate/spool /var/log/telecrate
sudo cp etc/telecrate/telecrate.toml /etc/telecrate/telecrate.toml
sudo cp systemd/telecrate.service /etc/systemd/system/

# Giao quyền sở hữu cho user telecrate
sudo chown -R telecrate:telecrate /var/lib/telecrate /var/log/telecrate /etc/telecrate
sudo chmod 750 /var/lib/telecrate /var/log/telecrate
sudo chmod 600 /etc/telecrate/telecrate.toml
```

---

## 3. Cấu hình Daemon `/etc/telecrate/telecrate.toml`

Mở file `/etc/telecrate/telecrate.toml` và cập nhật các thông số cần thiết:

```toml
db_path = "/var/lib/telecrate/index.db"
spool_dir = "/var/lib/telecrate/spool"
listen_port = 7070
encryption = "off"
region = "us-east-1"
admin_password = "mat-khau-quan-tri-secure"

# Telegram Bot API Credentials
telegram_bot_token = "123456789:YOUR_TELEGRAM_BOT_TOKEN"
telegram_chat_id = -1001234567890
worker_concurrency = 2
```

---

## 4. Quản lý Service với Systemd

```bash
# Reload daemon cấu hình systemd
sudo systemctl daemon-reload

# Kích hoạt tự khởi động cùng hệ thống và start service
sudo systemctl enable --now telecrate

# Kiểm tra trạng thái service
sudo systemctl status telecrate

# Xem log thời gian thực
sudo journalctl -u telecrate -f
```

---

## 5. Kiểm tra Hoạt động (Health Check & Dashboard)

- Truy cập Web Dashboard qua trình duyệt: `http://<IP_SEVER>:7070`
- Đăng nhập bằng mật khẩu đã cấu hình trong `admin_password`.
- Đăng nhập S3 API từ AWS CLI hoặc Rclone với Access Key mặc định hoặc tạo key mới qua Dashboard/CLI.

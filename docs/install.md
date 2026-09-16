# Hướng dẫn Cài đặt & Triển khai TeleCrate (Linux Native Systemd)

> Tài liệu hướng dẫn vận hành production cho TeleCrate trên Linux native.

---

## 1. Yêu cầu Hệ thống

- **Hệ điều hành**: Linux (Debian 11/12, Ubuntu 22.04/24.04 LTS, RHEL/Rocky Linux 9).
- **Môi trường Rust**: `rustc ≥ 1.88` (Cập nhật lên bản stable mới nhất bằng `rustup update stable` hoặc `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`).
- **Phần cứng khuyến nghị**: 1-2 vCPU, ≥ 1 GB RAM, Ổ cứng SSD (cho SQLite WAL + Spool).
- **Quyền hạn**: Root hoặc `sudo` để tạo service systemd và user hệ thống `telecrate`.

---

## 2. Cài đặt từ Mã nguồn (Source Code ZIP / GitHub Repo)

Khi bạn tải mã nguồn `TeleCrate-0.1.0.zip` hoặc `Source code (tar.gz)` từ GitHub Releases, chọn 1 trong 2 phương án bên dưới để triển khai trên Linux:

---

### Phương án A: Biên dịch & Cài đặt bằng Cargo (Khuyên dùng cho mọi Distro Linux)

#### Bước 1: Chuẩn bị Môi trường & Giải nén Mã nguồn
```bash
# 1. Cập nhật Rustc lên bản stable mới nhất (yêu cầu rustc >= 1.88+)
rustup update stable

# 2. Cài đặt unzip & công cụ build hệ thống (trên Debian/Ubuntu)
sudo apt update && sudo apt install -y unzip build-essential pkg-config libssl-dev

# 3. Giải nén mã nguồn
unzip TeleCrate-0.1.0.zip
cd TeleCrate-0.1.0
```

#### Bước 2: Biên dịch Binary Release
```bash
# Biên dịch phiên bản release tối ưu hóa
cargo build --release

# Copy binary vừa biên dịch vào /usr/bin/
sudo cp target/release/telecrate /usr/bin/
sudo chmod +x /usr/bin/telecrate
```

#### Bước 3: Tạo User Hệ thống & Cấu hình Systemd
```bash
# Tạo user hệ thống telecrate
sudo useradd --system --user-group --no-create-home --shell /bin/false telecrate || true

# Tạo thư mục cấu hình, spool và log
sudo mkdir -p /etc/telecrate /var/lib/telecrate/spool /var/log/telecrate

# Copy file cấu hình mẫu và service systemd từ folder packaging/
sudo cp packaging/telecrate.sample.toml /etc/telecrate/telecrate.toml
sudo cp packaging/telecrate.service /etc/systemd/system/

# Phân quyền cho user telecrate
sudo chown -R telecrate:telecrate /var/lib/telecrate /var/log/telecrate /etc/telecrate
sudo chmod 750 /var/lib/telecrate /var/log/telecrate
sudo chmod 600 /etc/telecrate/telecrate.toml
```

---

### Phương án B: Tự Đóng gói `.deb` & Cài đặt (Khuyên dùng cho Debian / Ubuntu)

```bash
# Giải nén mã nguồn
unzip TeleCrate-0.1.0.zip
cd TeleCrate-0.1.0

# Chạy script đóng gói .deb tự động
chmod +x packaging/build-deb.sh
./packaging/build-deb.sh

# Cài đặt gói .deb vừa được tạo ra tại target/debian/
sudo dpkg -i target/debian/telecrate_0.1.0_amd64.deb

# Gói .deb sẽ tự động thiết lập user `telecrate`, thư mục dữ liệu và service systemd.
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

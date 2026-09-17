#!/usr/bin/env bash
# ==============================================================================
# TeleCrate — Automated Linux One-Line Installer & Setup Wizard
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ZkIsHere/TeleCrate/master/install.sh | bash
#
# Hoặc chạy cục bộ:
#   chmod +x install.sh && ./install.sh
# ==============================================================================

set -euo pipefail

GITHUB_REPO="ZkIsHere/TeleCrate"
DEFAULT_VERSION="v0.2.0"
INSTALL_BIN="/usr/local/bin/telecrate"
ALT_BIN="/usr/bin/telecrate"
CONFIG_DIR="/etc/telecrate"
CONFIG_FILE="${CONFIG_DIR}/telecrate.toml"
DATA_DIR="/var/lib/telecrate"
SPOOL_DIR="${DATA_DIR}/spool"
LOG_DIR="/var/log/telecrate"
SERVICE_FILE="/etc/systemd/system/telecrate.service"
TELECRATE_USER="telecrate"
TELECRATE_GROUP="telecrate"

# Màu sắc hiển thị terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()  { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }

# Xác định TTY cho interactive input khi chạy qua `curl | bash`
if [ -t 0 ]; then
    INPUT_TTY="/dev/stdin"
elif [ -e /dev/tty ]; then
    INPUT_TTY="/dev/tty"
else
    INPUT_TTY="/dev/null"
fi

ask() {
    local var_name="$1"
    local prompt_text="$2"
    local default_val="${3:-}"
    local is_secret="${4:-false}"
    local val=""

    if [ "$INPUT_TTY" = "/dev/null" ]; then
        # Không có TTY, sử dụng default hoặc biến môi trường
        eval "$var_name=\"\${$var_name:-\$default_val}\""
        return
    fi

    if [ -n "$default_val" ]; then
        printf "${BOLD}%s${NC} [${CYAN}%s${NC}]: " "$prompt_text" "$default_val"
    else
        printf "${BOLD}%s${NC}: " "$prompt_text"
    fi

    if [ "$is_secret" = "true" ]; then
        stty -echo < "$INPUT_TTY" 2>/dev/null || true
        read -r val < "$INPUT_TTY"
        stty echo < "$INPUT_TTY" 2>/dev/null || true
        printf "\n"
    else
        read -r val < "$INPUT_TTY"
    fi

    val="$(echo "$val" | tr -d '\r\n')"
    if [ -z "$val" ]; then
        val="$default_val"
    fi
    eval "$var_name=\"\$val\""
}

rand_str() {
    local len="${1:-16}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$((len / 2))" 2>/dev/null || true
    else
        tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$len"
    fi
}

echo -e "${CYAN}"
cat << 'EOF'
  _______   _       _____           _       
 |__   __| | |     / ____|         | |      
    | | ___| | ___| |     _ __ __ _| |_ ___ 
    | |/ _ \ |/ _ \ |    | '__/ _` | __/ _ \
    | |  __/ |  __/ |____| | | (_| | ||  __/
    |_|\___|_|\___|\_____|_|  \__,_|\__\___|
EOF
echo -e "${BOLD}TeleCrate v0.2.0 — S3 Storage Gateway backed by Telegram${NC}"
echo -e "Self-hosted · Single Instance · Systemd Native\n"

# 1. Kiểm tra hệ điều hành & kiến trúc
info "Kiểm tra môi trường hệ thống..."
OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
    error "TeleCrate chỉ hỗ trợ môi trường Linux native (phát hiện: $OS)."
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        TARGET_ARCH="amd64"
        ;;
    aarch64|arm64)
        TARGET_ARCH="arm64"
        ;;
    *)
        error "Kiến trúc CPU '$ARCH' chưa được hỗ trợ gói dựng sẵn. Vui lòng build từ nguồn."
        ;;
esac
ok "Hệ điều hành: Linux ($TARGET_ARCH)"

# 2. Kiểm tra quyền root/sudo
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        warn "Script đang chạy dưới user thường, sẽ sử dụng 'sudo' để thực hiện cấu hình hệ thống."
    else
        error "Vui lòng chạy script với quyền root hoặc cài đặt 'sudo'."
    fi
fi

# 3. Tải binary release mới nhất
TMP_DIR="$(mktemp -d /tmp/telecrate-installer.XXXXXX)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

info "Đang kiểm tra phiên bản mới nhất từ GitHub..."
LATEST_TAG=""
if command -v curl >/dev/null 2>&1; then
    LATEST_TAG="$(curl -fsSL -H "User-Agent: TeleCrate-Installer" "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | head -n1 | cut -d'"' -f4 || true)"
fi
if [ -z "$LATEST_TAG" ]; then
    LATEST_TAG="$DEFAULT_VERSION"
    warn "Không lấy được tag từ GitHub API, sử dụng phiên bản mặc định: $LATEST_TAG"
else
    ok "Phiên bản release mới nhất: $LATEST_TAG"
fi

DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_TAG}/telecrate-linux-${TARGET_ARCH}.tar.gz"
ARCHIVE_PATH="${TMP_DIR}/telecrate.tar.gz"

info "Đang tải gói TeleCrate (${DOWNLOAD_URL})..."
DOWNLOADED=false
if curl -fsSL -o "$ARCHIVE_PATH" "$DOWNLOAD_URL" 2>/dev/null; then
    DOWNLOADED=true
elif [ -f "./target/release/telecrate" ]; then
    # Chạy trực tiếp từ repo mã nguồn
    info "Phát hiện binary có sẵn tại ./target/release/telecrate"
    cp ./target/release/telecrate "${TMP_DIR}/telecrate"
    DOWNLOADED=true
fi

if [ "$DOWNLOADED" != "true" ]; then
    # Thử tìm gói .deb hoặc compile fallback nếu có cargo
    DEB_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_TAG}/telecrate_${LATEST_TAG#v}_${TARGET_ARCH}.deb"
    if curl -fsSL -o "${TMP_DIR}/telecrate.deb" "$DEB_URL" 2>/dev/null; then
        info "Đang giải nén từ gói Debian..."
        ar x "${TMP_DIR}/telecrate.deb" --output="${TMP_DIR}" 2>/dev/null || dpkg-deb -x "${TMP_DIR}/telecrate.deb" "${TMP_DIR}/deb_out"
        if [ -f "${TMP_DIR}/deb_out/usr/bin/telecrate" ]; then
            cp "${TMP_DIR}/deb_out/usr/bin/telecrate" "${TMP_DIR}/telecrate"
        fi
    fi
fi

if [ -f "$ARCHIVE_PATH" ]; then
    tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"
fi

BINARY_SRC=""
if [ -f "${TMP_DIR}/telecrate" ]; then
    BINARY_SRC="${TMP_DIR}/telecrate"
elif [ -f "${TMP_DIR}/target/release/telecrate" ]; then
    BINARY_SRC="${TMP_DIR}/target/release/telecrate"
else
    error "Không thể tải hoặc giải nén binary TeleCrate. Vui lòng kiểm tra kết nối mạng hoặc tag release."
fi

# 4. Cài đặt binary vào /usr/bin hoặc /usr/local/bin
TARGET_BIN="$INSTALL_BIN"
if [ ! -d "/usr/local/bin" ]; then
    TARGET_BIN="$ALT_BIN"
fi
info "Đang cài đặt binary vào ${TARGET_BIN}..."
$SUDO cp "$BINARY_SRC" "$TARGET_BIN"
$SUDO chmod 755 "$TARGET_BIN"
ok "Đã cài đặt: $($TARGET_BIN --version 2>/dev/null || echo 'TeleCrate v0.2.0')"

# 5. Tạo user & group hệ thống
if ! id "$TELECRATE_USER" >/dev/null 2>&1; then
    info "Tạo system user '${TELECRATE_USER}'..."
    $SUDO useradd --system --user-group --no-create-home --shell /bin/false "$TELECRATE_USER" 2>/dev/null || \
    $SUDO adduser --system --group --no-create-home --shell /bin/false "$TELECRATE_USER" 2>/dev/null || true
    ok "Đã tạo user '${TELECRATE_USER}'"
else
    ok "User '${TELECRATE_USER}' đã tồn tại"
fi

# 6. Thiết lập các thư mục vận hành
info "Khởi tạo các thư mục lưu trữ và phân quyền..."
$SUDO mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$SPOOL_DIR" "$LOG_DIR"
$SUDO chown root:"$TELECRATE_GROUP" "$CONFIG_DIR"
$SUDO chmod 750 "$CONFIG_DIR"
$SUDO chown -R "$TELECRATE_USER":"$TELECRATE_GROUP" "$DATA_DIR" "$LOG_DIR"
$SUDO chmod 700 "$DATA_DIR" "$SPOOL_DIR"
$SUDO chmod 750 "$LOG_DIR"
ok "Các thư mục dữ liệu đã sẵn sàng"

# 7. Wizard cấu hình tương tác
echo ""
echo -e "${BOLD}${CYAN}====================================================${NC}"
echo -e "${BOLD}${CYAN}      THIẾT LẬP THÔNG SỐ VẬN HÀNH CHO TELECRATE     ${NC}"
echo -e "${BOLD}${CYAN}====================================================${NC}"
echo -e "Nhấn [Enter] để sử dụng giá trị mặc định trong dấu ngoặc vuông.\n"

# A. Admin Password
DEFAULT_ADMIN_PASS="$(rand_str 14)"
CFG_ADMIN_PASS=""
ask CFG_ADMIN_PASS "1. Mật khẩu quản trị Web Dashboard & API" "$DEFAULT_ADMIN_PASS"

# B. Telegram Bot Token
CFG_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
echo -e "${YELLOW}* Để tạo Bot, hãy chat với @BotFather trên Telegram -> gõ /newbot -> lấy API Token${NC}"
while [ -z "$CFG_BOT_TOKEN" ]; do
    ask CFG_BOT_TOKEN "2. Telegram Bot Token (ví dụ: 123456789:ABCdef...)" ""
    if [ -z "$CFG_BOT_TOKEN" ]; then
        warn "Bot Token là bắt buộc để TeleCrate lưu trữ dữ liệu lên Telegram. Vui lòng nhập."
    fi
done

# C. Telegram Chat ID
CFG_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
echo -e "${YELLOW}* ID nhóm hoặc Channel làm kho lưu trữ (ví dụ: -1001234567890)${NC}"
echo -e "${YELLOW}  (Hãy thêm Bot vào Channel/Group đó với quyền Admin / Post Messages)${NC}"
while [ -z "$CFG_CHAT_ID" ]; do
    ask CFG_CHAT_ID "3. Telegram Chat / Channel ID" ""
    if [ -z "$CFG_CHAT_ID" ]; then
        warn "Chat ID là bắt buộc. Vui lòng nhập ID channel/group của bạn."
    fi
done

# D. Port
CFG_PORT=""
ask CFG_PORT "4. Cổng dịch vụ HTTP (S3 Gateway & Dashboard)" "7070"

# E. Mã hóa nội dung
CFG_ENCRYPTION=""
ask CFG_ENCRYPTION "5. Bật mã hóa ChaCha20-Poly1305 phía máy chủ (off/on)" "off"

# F. Access Key & Secret Key ban đầu
CFG_ACCESS_KEY="AKIA$(rand_str 12 | tr '[:lower:]' '[:upper:]')"
CFG_SECRET_KEY="$(rand_str 32)"

# 8. Ghi file cấu hình /etc/telecrate/telecrate.toml
info "Đang tạo file cấu hình ${CONFIG_FILE}..."
$SUDO tee "$CONFIG_FILE" > /dev/null << TOML
# ==============================================================================
# Cấu hình TeleCrate Daemon (v0.2.0)
# Tạo tự động bởi install.sh lúc $(date '+%Y-%m-%d %H:%M:%S')
# ==============================================================================

# Database SQLite lưu index và jobs
db_path = "${DATA_DIR}/telecrate.db"

# Thư mục lưu spool tạm trước khi tải lên Telegram
spool_dir = "${SPOOL_DIR}"

# Cổng lắng nghe HTTP
listen_port = ${CFG_PORT}

# Mã hóa nội dung
encryption = "${CFG_ENCRYPTION}"

# Mật khẩu quản trị Dashboard
admin_password = "${CFG_ADMIN_PASS}"

# Kết nối Telegram Bot API
telegram_bot_token = "${CFG_BOT_TOKEN}"
telegram_chat_id = ${CFG_CHAT_ID}

# Kích thước chunk upload Telegram (8 MiB)
chunk_size_bytes = 8388608

# Số worker chạy ngầm
worker_concurrency = 2

# Access keys tĩnh khởi tạo ban đầu
[[access_keys]]
access_key_id = "${CFG_ACCESS_KEY}"
secret_key = "${CFG_SECRET_KEY}"

# Ghi nhật ký
log_level = "info"
log_to_file = true
log_dir = "${LOG_DIR}"
log_retention_days = 14
TOML

$SUDO chown "$TELECRATE_USER":"$TELECRATE_GROUP" "$CONFIG_FILE"
$SUDO chmod 600 "$CONFIG_FILE"
ok "Đã lưu cấu hình tại ${CONFIG_FILE} (quyền 600)"

# 9. Cài đặt Systemd Service
info "Cài đặt systemd service..."
$SUDO tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=TeleCrate S3-Compatible Object Storage Gateway
Documentation=https://github.com/${GITHUB_REPO}
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${TELECRATE_USER}
Group=${TELECRATE_GROUP}
WorkingDirectory=${DATA_DIR}
ExecStart=${TARGET_BIN} --config ${CONFIG_FILE} serve
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

# Systemd Sandboxing & Security Hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR} /run

[Install]
WantedBy=multi-user.target
EOF

$SUDO systemctl daemon-reload
$SUDO systemctl enable telecrate
info "Khởi động dịch vụ TeleCrate..."
$SUDO systemctl restart telecrate

# 10. Kiểm tra trạng thái dịch vụ
sleep 2
if $SUDO systemctl is-active --quiet telecrate; then
    ok "Dịch vụ TeleCrate đang hoạt động ổn định (active)!"
else
    warn "Dịch vụ chưa ở trạng thái active. Vui lòng kiểm tra: 'journalctl -u telecrate -n 30'"
fi

# Lấy địa chỉ IP chính của máy
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1')"
if [ -z "$SERVER_IP" ]; then SERVER_IP="127.0.0.1"; fi

# 11. In bảng thông tin hoàn tất
echo ""
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "${GREEN}${BOLD}       🎉 CÀI ĐẶT THÀNH CÔNG TELECRATE v0.2.0 TRÊN LINUX!        ${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo ""
echo -e "${BOLD}1. Giao diện Quản trị (Web Dashboard):${NC}"
echo -e "   URL:             ${CYAN}http://${SERVER_IP}:${CFG_PORT}/${NC}  (hoặc http://localhost:${CFG_PORT}/)"
echo -e "   Mật khẩu Admin:  ${YELLOW}${CFG_ADMIN_PASS}${NC}"
echo ""
echo -e "${BOLD}2. Thông số S3 Client (AWS CLI, rclone, Cyberduck, SDKs):${NC}"
echo -e "   S3 Endpoint:     ${CYAN}http://${SERVER_IP}:${CFG_PORT}${NC}"
echo -e "   Region:          ${CYAN}us-east-1${NC} (hoặc bất kỳ)"
echo -e "   Access Key ID:   ${YELLOW}${CFG_ACCESS_KEY}${NC}"
echo -e "   Secret Key:      ${YELLOW}${CFG_SECRET_KEY}${NC}"
echo ""
echo -e "${BOLD}3. Lệnh Quản lý Dịch vụ Systemd:${NC}"
echo -e "   Kiểm tra trạng thái:  ${BOLD}sudo systemctl status telecrate${NC}"
echo -e "   Xem log thời gian thực: ${BOLD}sudo journalctl -u telecrate -f${NC}"
echo -e "   Khởi động lại daemon: ${BOLD}sudo systemctl restart telecrate${NC}"
echo -e "   Tập tin cấu hình:     ${BOLD}${CONFIG_FILE}${NC}"
echo ""
echo -e "${GREEN}${BOLD}Chúc mừng bạn đã thiết lập thành công TeleCrate Object Storage!${NC}\n"

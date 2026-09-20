#!/usr/bin/env bash
set -euo pipefail

# Script tạo gói cài đặt Debian/Ubuntu .deb cho TeleCrate

VERSION="0.3.3-beta.1"
BUILD_TMP_DIR="/tmp/telecrate_deb_build/telecrate_${VERSION}_amd64"
OUT_DIR="target/debian"

echo "==> Building release binary..."
cargo build --release

echo "==> Preparing Debian package directory structure..."
rm -rf "${BUILD_TMP_DIR}"
mkdir -p "${BUILD_TMP_DIR}/DEBIAN"
mkdir -p "${BUILD_TMP_DIR}/usr/bin"
mkdir -p "${BUILD_TMP_DIR}/etc/telecrate"
mkdir -p "${BUILD_TMP_DIR}/lib/systemd/system"
mkdir -p "${BUILD_TMP_DIR}/var/lib/telecrate/spool"
mkdir -p "${BUILD_TMP_DIR}/var/log/telecrate"
mkdir -p "${OUT_DIR}"

echo "==> Copying binaries and configuration files..."
cp target/release/telecrate "${BUILD_TMP_DIR}/usr/bin/"
cp packaging/telecrate.sample.toml "${BUILD_TMP_DIR}/etc/telecrate/telecrate.toml"
cp packaging/telecrate.service "${BUILD_TMP_DIR}/lib/systemd/system/"

cat << EOF > "${BUILD_TMP_DIR}/DEBIAN/control"
Package: telecrate
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: TeleCrate Maintainers <admin@telecrate.local>
Description: TeleCrate S3-compatible object storage gateway backed by Telegram
 Single-instance, self-hosted, durable local-first S3 object storage server.
EOF

cat << 'EOF' > "${BUILD_TMP_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
if ! id -u telecrate >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /bin/false telecrate || true
fi
chown -R telecrate:telecrate /var/lib/telecrate /var/log/telecrate /etc/telecrate
chmod 750 /var/lib/telecrate /var/log/telecrate
chmod 600 /etc/telecrate/telecrate.toml || true
systemctl daemon-reload || true
EOF
chmod 755 "${BUILD_TMP_DIR}/DEBIAN/postinst"
chmod 755 "${BUILD_TMP_DIR}/DEBIAN"
chmod 755 "${BUILD_TMP_DIR}"

echo "==> Building .deb package..."
dpkg-deb --build "${BUILD_TMP_DIR}"
mv "/tmp/telecrate_deb_build/telecrate_${VERSION}_amd64.deb" "${OUT_DIR}/"
rm -rf "/tmp/telecrate_deb_build"

echo "==> Success: Created ${OUT_DIR}/telecrate_${VERSION}_amd64.deb"


#!/usr/bin/env bash
set -euo pipefail

# Script tạo gói cài đặt Debian/Ubuntu .deb cho TeleCrate

VERSION="0.1.0"
PKG_DIR="target/debian/telecrate_${VERSION}_amd64"

echo "==> Building release binary..."
cargo build --release

echo "==> Preparing Debian package directory structure..."
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/etc/telecrate"
mkdir -p "${PKG_DIR}/lib/systemd/system"
mkdir -p "${PKG_DIR}/var/lib/telecrate/spool"
mkdir -p "${PKG_DIR}/var/log/telecrate"

echo "==> Copying binaries and configuration files..."
cp target/release/telecrate "${PKG_DIR}/usr/bin/"
cp packaging/telecrate.sample.toml "${PKG_DIR}/etc/telecrate/telecrate.toml"
cp packaging/telecrate.service "${PKG_DIR}/lib/systemd/system/"

cat << EOF > "${PKG_DIR}/DEBIAN/control"
Package: telecrate
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: TeleCrate Maintainers <admin@telecrate.local>
Description: TeleCrate S3-compatible object storage gateway backed by Telegram
 Single-instance, self-hosted, durable local-first S3 object storage server.
EOF

cat << 'EOF' > "${PKG_DIR}/DEBIAN/postinst"
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
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

echo "==> Building .deb package..."
dpkg-deb --build "${PKG_DIR}"
echo "==> Success: Created target/debian/telecrate_${VERSION}_amd64.deb"

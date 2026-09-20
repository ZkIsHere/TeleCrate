#!/usr/bin/env bash
set -euo pipefail

# Script tạo gói cài đặt Linux Tarball & RPM cho TeleCrate

VERSION="0.3.3-beta.1"
DIST_DIR="target/dist/telecrate-v${VERSION}-linux-amd64"

echo "==> Building release binary..."
cargo build --release

echo "==> Creating distribution directory layout..."
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}/bin"
mkdir -p "${DIST_DIR}/etc/telecrate"
mkdir -p "${DIST_DIR}/systemd"
mkdir -p "${DIST_DIR}/docs"

cp target/release/telecrate "${DIST_DIR}/bin/"
cp packaging/telecrate.sample.toml "${DIST_DIR}/etc/telecrate/telecrate.toml"
cp packaging/telecrate.service "${DIST_DIR}/systemd/"
cp README.md "${DIST_DIR}/docs/" || true
cp docs/*.md "${DIST_DIR}/docs/" || true

echo "==> Packing tar.gz distribution archive..."
tar -czvf "target/dist/telecrate-v${VERSION}-linux-amd64.tar.gz" -C target/dist "telecrate-v${VERSION}-linux-amd64"

echo "==> Success: Created target/dist/telecrate-v${VERSION}-linux-amd64.tar.gz"

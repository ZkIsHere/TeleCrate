#!/usr/bin/env bash
set -euo pipefail

# Script tạo gói cài đặt Linux Tarball & RPM cho TeleCrate

# Version lấy từ Cargo.toml (single source of truth) — không hardcode để khỏi
# gắn nhãn sai cho release sau (vd. build beta.6 nhưng deb ghi beta.5).
VERSION="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)"
if [ -z "${VERSION}" ]; then
  echo "ERROR: khong doc duoc version tu Cargo.toml" >&2
  exit 1
fi
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

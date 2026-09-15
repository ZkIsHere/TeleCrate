# TeleCrate

Object storage tương thích S3, dùng Telegram để lưu dữ liệu. Single instance, self-hosted trên Linux (systemd). Mã hóa nội dung OPTIONAL do người dùng quyết định.

> Trạng thái M0 (bootstrap): khung repo + daemon/CLI skeleton + SQLite migrations v1 + config mẫu + systemd unit + CI. S3 API ở trạng thái `unsupported` có chủ đích — không mock 200. Xem `docs/compatibility-matrix.md` và `docs/milestones.md`.

## Chạy local (dev)

Yêu cầu: Rust stable.

```sh
cargo fmt --check
cargo clippy -- -D warnings
cargo build
cargo test
```

## Cài đặt native (Linux, tổng quan — chi tiết đầy đủ ở M6)

```sh
sudo useradd -r -s /usr/sbin/nologin telecrate
sudo install -m 0755 target/release/telecrate /usr/local/bin/telecrate
sudo mkdir -p /etc/telecrate /var/lib/telecrate/spool
sudo cp configs/telecrate.example.toml /etc/telecrate/telecrate.toml
sudo cp packaging/systemd/telecrate.service /etc/systemd/system/telecrate.service
sudo systemctl enable --now telecrate
systemctl status telecrate
journalctl -u telecrate -f
```

## Tài liệu

- `AGENTS.md` — quy tắc làm việc
- `docs/architecture.md`, `docs/data-model.md`, `docs/threat-model.md`
- `docs/compatibility-matrix.md`, `docs/milestones.md`
- `docs/adr/0001-stack.md`

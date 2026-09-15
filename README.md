# TeleCrate

Object storage tương thích S3, dùng Telegram để lưu dữ liệu. Single instance, self-hosted trên Linux (systemd). Mã hóa nội dung OPTIONAL do người dùng quyết định.

> Trạng thái (2026-09-15, sau M1 changeset 2): khung repo + daemon/CLI skeleton + SQLite migrations v1 +
> `BotApiHttpTransport` thật (upload/download/delete đã verify live). S3 API vẫn `unsupported` có chủ đích —
> không mock 200. Xem `docs/compatibility-matrix.md` và `docs/milestones.md`.

## Chạy local (dev)

Yêu cầu: Rust stable.

```sh
cargo fmt --check
cargo clippy -- -D warnings
cargo build
cargo test
# Live probe Telegram (cần secrets, tách khỏi test thường):
TELECRATE_BOT_TOKEN=... TELECRATE_TEST_CHAT_ID=... cargo test -- --ignored live_
```

## Secrets (bot token, test chat id)

Không bao giờ commit vào repo. Local dùng biến môi trường tạm thời; CI dùng GitHub Actions Secrets
(`TELECRATE_BOT_TOKEN`, `TELECRATE_TEST_CHAT_ID`) cho job `live-telegram` riêng. An toàn khi repo chuyển public.

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
- `docs/compatibility-matrix.md`, `docs/milestones.md`, `docs/telegram-capability.md`
- `docs/adr/0001-stack.md`, `docs/adr/0002-telegram-http-client.md`, `docs/adr/0003-m2-vertical-slice.md`

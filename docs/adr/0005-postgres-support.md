# ADR 0005 — Hỗ trợ Postgres cho metadata DB (pluggable backend)

> Ngày: 2026-09-18. Trạng thái: `partial` (chấp nhận).
> Liên quan: ADR 0001 (stack SQLite), `docs/data-model.md`, `docs/compatibility-matrix.md`.

## 1. Bối cảnh

TeleCrate dùng SQLite (WAL) cho toàn bộ index/jobs (`src/db.rs`, `rusqlite` bundled).
Vận hành có nhu cầu chọn 1 trong 2 backend: `sqlite` hoặc `postgres`.

## 2. Quyết định

- Thêm `db_backend = "sqlite" | "postgres"` (mặc định `"sqlite"`) + `database_url`
  (chỉ dùng khi `postgres`, chứa password → redact mọi nơi như bot token).
- SQLite giữ nguyên 100% hành vi, là backend runnable duy nhất.
- Postgres ở mức `partial` trong turn này:
  - **Xong**: chọn backend qua TOML/CLI/dashboard + validate fail-closed,
    DDL schema Postgres đầy đủ tương đương migrations SQLite 0001→0004
    (file `migrations/postgres/0001_0004_schema.sql`, nạp qua `include_str!`
    thành `DbBackend::POSTGRES_SCHEMA`, in ra bằng `telecrate db pg-schema`),
    guard khởi động từ chối chạy khi `db_backend='postgres'` với thông báo rõ ràng.
  - **Chưa xong (`blocked`, cấm fake)**: port query DAL (`rusqlite::Connection`
    dùng trực tiếp khắp `app`/`admin`/`worker`/`gc`), lease atomic Postgres
    (`SELECT ... FOR UPDATE SKIP LOCKED`), pool + retry, migrate dữ liệu
    SQLite→Postgres, conformance + crash-injection lại trên Postgres.
- Không bao giờ lặng lẽ fallback Postgres→SQLite: sai backend là lỗi khởi động.

## 3. Quy tắc an toàn áp dụng

- `database_url` redact trong: `Config: Debug`, `GET /admin/api/config`,
  audit `config.update`, CLI `config set` stdout, dashboard (password input,
  chỉ hiện 1 lần như secret).
- Validate: `sqlite` cấm `database_url` (tránh cấu hình mồ côi);
  `postgres` bắt buộc scheme `postgres://`/`postgresql://`.
- Đổi backend cần restart + migrate dữ liệu thủ công (không tự migrate).

## 4. Bước tiếp theo (khi làm runtime Postgres)

1. Trait repository trừu tượng trên `db.rs` (mỗi query có 2 implementation).
2. Lease Postgres bằng `FOR UPDATE SKIP LOCKED` + kiểm chứng no-double-upload
   tương đương `worker_reclaims_expired_uploading_lease`.
3. Tool `telecrate db migrate --to postgres` (dump SQLite → COPY vào Postgres,
   verify count + checksum mẫu).
4. Chạy lại full suite (unit/integration/conformance/crash-injection) với Postgres,
   rồi mới chuyển matrix sang `implemented-and-tested`.

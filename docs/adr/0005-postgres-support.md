# ADR 0005 — Hỗ trợ Postgres cho metadata DB (pluggable backend)

> Ngày: 2026-09-18. Trạng thái: `implemented-and-tested` (chấp nhận và đã hoàn thành).
> Liên quan: ADR 0001 (stack SQLite), `docs/data-model.md`, `docs/compatibility-matrix.md`.

## 1. Bối cảnh

TeleCrate ban đầu dùng SQLite (WAL) đồng bộ qua `rusqlite` cho toàn bộ index/jobs.
Để đáp ứng các kịch bản triển khai phân tán hoặc tận dụng hạ tầng CSDL PostgreSQL có sẵn,
hệ thống cần hỗ trợ dual-backend: `sqlite` hoặc `postgres` mà không làm phân mảnh logic nghiệp vụ S3.

## 2. Quyết định

- Cung cấp trừu tượng async DAL `telecrate::db::Db` dựa trên `sqlx` (hỗ trợ cả `sqlx::SqlitePool` và `sqlx::PgPool`).
- Không còn phụ thuộc `rusqlite` đồng bộ trong runtime chính; toàn bộ S3 HTTP handlers, worker background,
  GC engine, doctor/verify/scrub, admin API, recovery export/import và migrations đều chạy non-blocking async.
- Thêm `db_backend = "sqlite" | "postgres"` (mặc định `"sqlite"`) + `database_url`
  (chỉ dùng khi `postgres`, chứa password → redact mọi nơi như bot token).
- Cả hai backend dùng chung:
  - Schema parity 15 bảng (SQLite migrations 0001→0004 & Postgres DDL).
  - Transaction wrapper `Tx<'a>` tương thích cả SQLite và Postgres (`Box<Transaction<Postgres>>`).
  - Phân trang ListObjects / ListObjectVersions động theo prefix & delimiter.
  - Lease job atomic cho worker và GC WORM retention guard.
- Quy tắc kiểm thử: Toàn bộ test suite (unit tests, 20 integration tests, 10 crash points, 25k simulation)
  đều chạy thông qua async DAL `Db`.

## 3. Quy tắc an toàn áp dụng

- `database_url` redact trong: `Config: Debug`, `GET /admin/api/config`,
  audit `config.update`, CLI `config set` stdout, dashboard (password input,
  chỉ hiện 1 lần như secret).
- Validate: `sqlite` cấm `database_url` (tránh cấu hình mồ côi);
  `postgres` bắt buộc scheme `postgres://`/`postgresql://`.
- Đổi backend cần restart + migrate dữ liệu thủ công (không tự migrate).


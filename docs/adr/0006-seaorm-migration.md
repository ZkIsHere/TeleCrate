# ADR 0006 — Migrate DB layer sang SeaORM + SeaQuery (incremental)

> Ngày: 2026-09-22. Trạng thái: `implemented-and-tested` (hoàn thành Phase 1→4b,
> CI xanh toàn bộ: entities + parity, CRUD buckets/keys/policy, objects/jobs/
> multipart, worker lease, gc/doctor/recovery, gỡ shim Val/Row/Tx).
> Liên quan: ADR 0001 (stack SQLite), ADR 0005 (dual-backend sqlx), `docs/data-model.md`,
> `migrations/NNNN_*.sql`, `migrations/postgres/*.sql`.

## 1. Bối cảnh

DAL hiện tại (`src/db.rs`, ~3000 dòng) viết raw SQL với placeholder `?` + tự rebind
`$N` cho Postgres, cộng hai bộ DDL song song (SQLite + Postgres) phải giữ parity
bằng tay. Mỗi thay đổi schema có nguy cơ lệch một trong hai backend mà chỉ phát
hiện khi chạy test Postgres (hiếm khi chạy local).

## 2. Quyết định

- Dùng **SeaORM 1.x** (`sqlx-sqlite`, `sqlx-postgres`, `runtime-tokio-rustls`, tương
  thích sqlx 0.8 sẵn có) + **SeaQuery** làm single source of truth cho cấu trúc bảng
  qua entities viết tay tại `src/db/entities/` (15 bảng dữ liệu + `schema_version`).
- **Incremental, giữ API ổn định**: chữ ký public `telecrate::db::*` không đổi trong
  suốt quá trình migrate; từng module thay ruột sang entities, mỗi phase phải xanh
  toàn bộ test suite mới sang phase tiếp theo.
- **Giữ hệ migrations SQL hiện tại**: `migrations/NNNN_*.sql` forward-only và CI kiểm
  tra migrations không thay đổi (AGENTS.md). Entities chỉ *mirror* DDL, không thay
  thế migrator (không dùng SeaORM Migrator để tránh phân mảnh lịch sử migrate của
  DB đang chạy production).
- **Test parity schema** (`tests/entity_schema_parity.rs`): sinh `CREATE TABLE` từ
  entities bằng SeaQuery cho cả hai backend rồi đối chiếu tập cột + kiểu với DDL
  thật (SQLite: `sqlite_master` sau khi apply migrations; Postgres: file
  `migrations/postgres/*.sql`). Lệch schema = fail CI, thay vì fail lúc chạy.
- Entities viết tay (không dùng `sea-orm-cli` codegen) để build offline hoàn toàn.
- Kiểu ánh xạ tối giản, zero behavior change: mọi cột số nguyên → `i64`
  (kể cả flag 0/1, khớp `get_i64` hiện tại), mọi cột datetime TEXT → `String`
  (giữ format `YYYY-MM-DD HH:MM:SS` UTC, không thêm chrono).
- `rusqlite` được giữ lại **chỉ** cho tests mở trực tiếp file DB (setup FK OFF,
  bulk insert scale_sim) — đường dữ liệu runtime và backup (`VACUUM INTO` qua sea)
  không dùng tới.

## 3. Lộ trình

- **Phase 1** (không đổi hành vi): deps + `src/db/entities/` + test parity + ADR này.
- **Phase 2**: migrate CRUD ít rủi ro (buckets, access_keys, policy/cors/bpa/lock),
  `Db` bọc `DatabaseConnection`.
- **Phase 3**: đường nóng objects/chunks/jobs + multipart (kèm kiểm tra hiệu năng
  `scale_sim` 25k objects).
- **Phase 4**: doctor/gc/recovery call sites; gỡ shim `Val/Row/exec` khi không còn
  ai dùng; cập nhật `data-model.md` + `compatibility-matrix.md`.

## 4. Ràng buộc giữ nguyên

- Không giữ transaction mở suốt network upload (worker dùng job lease như cũ).
- `rowid` (SQLite) / `ctid` (Postgres) tiebreaker cho "bản ghi mới nhất" được giữ
  qua SeaQuery fragment tường minh, có test bao phủ.
- `database_url` vẫn redact mọi nơi (config Debug, admin API, audit, CLI).
- Mọi endpoint/metric/log vẫn trạng thái thật; cấm mock trong production.

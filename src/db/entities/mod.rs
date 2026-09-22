//! SeaORM entities — single source of truth cho cấu trúc bảng (ADR 0006).
//!
//! Quy tắc:
//! - Mỗi entity mirror đúng 1 bảng trong `migrations/NNNN_*.sql` (+ bản Postgres
//!   tương ứng). Migrations SQL vẫn là migrator duy nhất — entities KHÔNG tạo bảng
//!   lúc runtime, chỉ dùng để build query type-safe ở các phase sau.
//! - Ánh xạ tối giản, zero behavior change: số nguyên → `i64` (kể cả flag 0/1),
//!   datetime TEXT (`YYYY-MM-DD HH:MM:SS` UTC) → `String`.
//! - `tests/entity_schema_parity.rs` đối chiếu tập cột + nhóm kiểu của entities
//!   với DDL thật cả hai backend — lệch là fail CI.

pub mod access_keys;
pub mod bucket_bpa;
pub mod bucket_cors;
pub mod bucket_lock_configs;
pub mod bucket_policies;
pub mod buckets;
pub mod chunks;
pub mod multipart_parts;
pub mod multipart_uploads;
pub mod object_locks;
pub mod objects;
pub mod schema_version;
pub mod upload_jobs;

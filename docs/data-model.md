# Data model TeleCrate (SQLite WAL + Postgres)

> Forward-only migrations tại `migrations/NNNN_*.sql` (+ song sinh Postgres tại
> `migrations/postgres/`). Không sửa migration đã release.
> Entities SeaORM tại `src/db/entities/` mirror DDL; `tests/entity_schema_parity.rs`
> đối chiếu tự động (cập nhật 2026-09-22).

## Bảng chính (sau migration 0005 — cập nhật 2026-09-22)

- `schema_version(version PK, applied_at)`
- `buckets(name PK, region, versioning_status, created_at)`
- `objects(bucket, key, version_id PK, is_delete_marker, storage_state, size, etag, content_type, created_at, user_metadata_json NULL, system_metadata_json NULL)` + index `(bucket, key, created_at DESC)`
- `chunks(version_id FK, idx, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref NULL, spool_path NULL, remote_locator_json NULL, state)` — PK `(version_id, idx)`
- `upload_jobs(job_id PK, version_id FK, state, lease_owner NULL, lease_expires NULL, retry_count, next_attempt, last_error NULL)` + index `(state, next_attempt)` cho worker claim poll
- `multipart_uploads(upload_id PK, bucket, key, content_type, metadata_json NULL, created_at)` + index `(bucket, key, created_at DESC)`
- `multipart_parts(upload_id FK, part_number, size, etag, plaintext_sha256, ciphertext_sha256, spool_path NULL, created_at, PRIMARY KEY (upload_id, part_number))`
- `access_keys(access_key_id PK, secret_key, status, description NULL, created_at, last_used_at NULL, allowed_buckets NULL)` (M4 — secret lưu để kiểm HMAC dưới bảo vệ thích hợp, file quyền 0600, không log)
- `bucket_policies(bucket PK, policy_json, updated_at)` + `bucket_cors`, `bucket_bpa`, `bucket_lock_configs`, `object_locks(bucket, key, version_id PK, retain_until_date NULL, mode NULL, legal_hold, updated_at)` (M4)

Đã xóa ở migration 0005 (audit schema 2026-09-22 — bảng/cột chết, không code path nào dùng):
- Bảng `kv`, `recovery_checkpoints`; cột `chunks.nonce` (nonce nằm trong file spool),
  `chunks.offset` (đọc lắp theo `idx`), `buckets.encryption_override`,
  `upload_jobs.generation` (luôn 1), `multipart_parts.remote_locator_json`/`state`.
- Giữ `multipart_parts.created_at` (S3 ListParts `LastModified`).

Planned (thêm ở migration mới khi tới milestone):
- `remote_blobs` + `chunk_blobs` (nếu packing — quyết sau khi đo random read/GC, hiện chưa packing)

## Trạng thái chuẩn

- `chunks.state`: `pending` → `remote` (worker upload xong). GC dọn spool của chunk
  `remote` còn `spool_path` (crash giữa commit và cleanup).
- `upload_jobs.state`: `pending` → `uploading` (lease) → `done` / `failed`.
  Dashboard "Hoàn tất" đếm `done`.

## Quy tắc

- Binary lớn nằm ở spool FS, không lưu blob vào DB.
- Chunk đặt tên theo `sha256(version_id|idx)` + `.chunk` (code: `spool::chunk_path`), ghi qua `.tmp` → rename,
  không dùng object key làm path.
- Mọi checksum tách bạch: `plaintext_sha256`, `ciphertext_sha256`, `etag` (S3 ETag theo loại upload, không luôn MD5).
- Khi encryption tắt: `encryption_mode='none'`, `key_ref=NULL`; vẫn giữ checksum toàn vẹn. Khi bật: `encryption_mode='aead-v1'`, envelope encryption, nonce duy nhất, AAD = chunk identity.

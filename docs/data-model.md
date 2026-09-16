# Data model TeleCrate (SQLite WAL)

> Forward-only migrations tại `migrations/NNNN_*.sql`. Không sửa migration đã release.

## Bảng chính (đối chiếu `migrations/0001_init.sql` — cập nhật 2026-09-15)

Đã có ở migration 0001 (`implemented-and-tested` - M0):
- `schema_version(version INTEGER PRIMARY KEY, applied_at)`
- `buckets(name PK, region, versioning_status, encryption_override NULL, created_at)`
- `objects(bucket, key, version_id PK, is_delete_marker, storage_state, size, etag, content_type, created_at)` + index `(bucket, key, created_at DESC)`
- `chunks(version_id FK, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref NULL, nonce NULL, spool_path NULL, remote_locator_json NULL, state)`
- `upload_jobs(job_id PK, version_id FK, state, lease_owner NULL, lease_expires NULL, retry_count, next_attempt, generation, last_error NULL)`
- `recovery_checkpoints(seq PK, manifest_json, sha256, created_at)`
- `kv(key PK, value)`

Đã bổ sung ở migration 0002 (`implemented-and-tested` - M3):
- `multipart_uploads(upload_id PK, bucket, key, content_type, metadata_json NULL, created_at)`
- `multipart_parts(upload_id FK, part_number, size, etag, plaintext_sha256, ciphertext_sha256, spool_path NULL, remote_locator_json NULL, state, created_at, PRIMARY KEY (upload_id, part_number))`
- `objects` (cột `system_metadata_json NULL` và `user_metadata_json NULL`)

Planned (thêm ở migration mới khi tới milestone):
- `remote_blobs` + `chunk_blobs` (nếu packing — quyết sau khi đo random read/GC, hiện chưa packing)
- `access_keys` (M4 — secret lưu để kiểm HMAC dưới bảo vệ thích hợp, file quyền 0600, không log)
- `policies` + `retention` (M4)

## Quy tắc

- Binary lớn nằm ở spool FS, không lưu blob vào DB.
- Chunk đặt tên theo `sha256(version_id|idx)` + `.chunk` (code: `spool::chunk_path`), ghi qua `.tmp` → rename,
  không dùng object key làm path.
- Mọi checksum tách bạch: `plaintext_sha256`, `ciphertext_sha256`, `etag` (S3 ETag theo loại upload, không luôn MD5).
- Khi encryption tắt: `encryption_mode='none'`, `key_ref=NULL`; vẫn giữ checksum toàn vẹn. Khi bật: `encryption_mode='aead-v1'`, envelope encryption, nonce duy nhất, AAD = chunk identity.

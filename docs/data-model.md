# Data model TeleCrate (SQLite WAL)

> Forward-only migrations tại `migrations/NNNN_*.sql`. Không sửa migration đã release.

## Bảng chính (đối chiếu `migrations/0001_init.sql` — cập nhật 2026-09-15)

Đã có ở migration 001 (`implemented-and-tested`):
- `schema_version(version INTEGER PRIMARY KEY, applied_at)`
- `buckets(name PK, region, versioning_status, encryption_override NULL, created_at)`
- `objects(bucket, key, version_id PK, is_delete_marker, storage_state, size, etag, content_type, created_at)` + index `(bucket, key, created_at DESC)`
- `chunks(version_id FK, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref NULL, nonce NULL, spool_path NULL, remote_locator_json NULL, state)`
- `upload_jobs(job_id PK, version_id FK, state, lease_owner NULL, lease_expires NULL, retry_count, next_attempt, generation, last_error NULL)`
- `recovery_checkpoints(seq PK, manifest_json, sha256, created_at)`
- `kv(key PK, value)`

Planned (thêm ở migration mới khi tới milestone, KHÔNG sửa 001):
- `remote_blobs` + `chunk_blobs` (nếu packing — quyết sau khi đo random read/GC, hiện chưa packing)
- `multipart_uploads` + `multipart_parts` (M3)
- `tombstones` (M2), `access_keys` (M4 — secret lưu để kiểm HMAC dưới bảo vệ thích hợp, file quyền 0600, không log)
- `policies` + `retention` (M4)

## Quy tắc

- Binary lớn nằm ở spool FS, không lưu blob vào DB.
- Chunk đặt tên theo `sha256(version_id|idx)` + `.chunk` (code: `spool::chunk_path`), ghi qua `.tmp` → rename,
  không dùng object key làm path.
- Mọi checksum tách bạch: `plaintext_sha256`, `ciphertext_sha256`, `etag` (S3 ETag theo loại upload, không luôn MD5).
- Khi encryption tắt: `encryption_mode='none'`, `key_ref=NULL`; vẫn giữ checksum toàn vẹn. Khi bật: `encryption_mode='aead-v1'`, envelope encryption, nonce duy nhất, AAD = chunk identity.

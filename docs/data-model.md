# Data model TeleCrate (SQLite WAL)

> Forward-only migrations tại `migrations/NNNN_*.sql`. Không sửa migration đã release.

## Bảng chính

- `schema_version(version INTEGER PRIMARY KEY, applied_at)`
- `buckets(name PK, region, versioning_status, created_at, encryption_override NULL)`
- `objects(bucket, key, version_id PK, is_delete_marker, storage_state TEXT[accepted-local|telegram-committed], size, etag, content_type, created_at)` + index `(bucket, key, created_at DESC)`
- `chunks(version_id FK, idx, offset, length, plaintext_sha256, ciphertext_sha256, encryption_mode, key_ref NULL, nonce NULL, spool_path NULL, remote_locator_json NULL, state TEXT[pending|uploading|remote|gc-ready])`
- `remote_blobs(blob_id PK, transport TEXT, chat_id, message_id, file_id, file_unique_id, size, created_at)` — chunk → blob qua `chunk_blobs` nếu packing (M3+, hiện chưa packing).
- `upload_jobs(job_id PK, version_id FK, state, lease_owner NULL, lease_expires NULL, retry_count, next_attempt, generation, last_error NULL)`
- `multipart_uploads(upload_id PK, bucket, key, initiated_at, state)` + `multipart_parts(upload_id, part_number, size, etag, spool_path, state)`
- `tombstones(bucket, key, version_id, created_at)` + `delete_markers` gộp trong `objects.is_delete_marker`
- `access_keys(access_key_id PK, secret_hash, policy_json, created_at, disabled)` — secret lưu để kiểm HMAC dưới bảo vệ thích hợp (file quyền 0600, không log).
- `policies(bucket PK, policy_json)` + `retention(bucket, key, version_id, retain_until, legal_hold)`
- `recovery_checkpoints(seq PK, manifest_json, sha256, created_at)` — manifest có version, checksum, object/chunk mapping, encryption mode, locator đủ khôi phục.
- `kv(key PK, value)` cho con trỏ checkpoint mới nhất, generation guard.

## Quy tắc

- Binary lớn nằm ở spool FS, không lưu blob vào DB.
- Chunk đặt tên theo `sha256(job|version|idx)` + suffix `.tmp` → rename, không dùng object key làm path.
- Mọi checksum tách bạch: `plaintext_sha256`, `ciphertext_sha256`, `etag` (S3 ETag theo loại upload, không luôn MD5).
- Khi encryption tắt: `encryption_mode='none'`, `key_ref=NULL`; vẫn giữ checksum toàn vẹn. Khi bật: `encryption_mode='aead-v1'`, envelope encryption, nonce duy nhất, AAD = chunk identity.

-- 0005_gc_cleanup: Dọn schema thừa sau audit toàn diện (SeaORM Phase 4c).
-- Forward-only migration. Không sửa migration đã release.
--
-- Xóa:
-- - Bảng chết `kv`, `recovery_checkpoints` (không code path nào đọc/ghi).
-- - `chunks.nonce` (nonce AEAD nằm prepend trong file spool, không dùng cột).
-- - `chunks.offset` (GET lắp chunk theo `idx`, không đọc offset).
-- - `buckets.encryption_override` (không API nào set/đọc).
-- - `upload_jobs.generation` (luôn 1, không logic nào dùng).
-- - `multipart_parts.remote_locator_json` (không bao giờ ghi/đọc),
--   `multipart_parts.state` (ghi 'pending' nhưng không ai đọc).
-- Giữ `multipart_parts.created_at` (S3 ListParts LastModified) và mọi cột
-- audit `updated_at`/`applied_at`/`created_at` còn lại.
-- Thêm index cho worker claim poll (state, next_attempt).

DROP TABLE IF EXISTS kv;
DROP TABLE IF EXISTS recovery_checkpoints;

ALTER TABLE chunks DROP COLUMN nonce;
ALTER TABLE chunks DROP COLUMN "offset";
ALTER TABLE buckets DROP COLUMN encryption_override;
ALTER TABLE upload_jobs DROP COLUMN generation;
ALTER TABLE multipart_parts DROP COLUMN remote_locator_json;
ALTER TABLE multipart_parts DROP COLUMN state;

CREATE INDEX IF NOT EXISTS idx_upload_jobs_state_next ON upload_jobs(state, next_attempt);

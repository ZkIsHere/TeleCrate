-- pg 0005_gc_cleanup: tuong duong migrations/0005_gc_cleanup.sql. Forward-only.
DROP TABLE IF EXISTS kv;
DROP TABLE IF EXISTS recovery_checkpoints;

ALTER TABLE chunks DROP COLUMN IF EXISTS nonce;
ALTER TABLE chunks DROP COLUMN IF EXISTS "offset";
ALTER TABLE buckets DROP COLUMN IF EXISTS encryption_override;
ALTER TABLE upload_jobs DROP COLUMN IF EXISTS generation;
ALTER TABLE multipart_parts DROP COLUMN IF EXISTS remote_locator_json;
ALTER TABLE multipart_parts DROP COLUMN IF EXISTS state;

CREATE INDEX IF NOT EXISTS idx_upload_jobs_state_next ON upload_jobs(state, next_attempt);

-- pg 0002_m3_multipart_versioning: tuong duong migrations/0002_*.sql. Forward-only.
CREATE TABLE IF NOT EXISTS multipart_uploads(
  upload_id TEXT PRIMARY KEY,
  bucket TEXT NOT NULL REFERENCES buckets(name),
  key TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  metadata_json TEXT NULL,
  created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);
CREATE INDEX IF NOT EXISTS idx_multipart_uploads_bucket_key ON multipart_uploads(bucket, key, created_at DESC);
CREATE TABLE IF NOT EXISTS multipart_parts(
  upload_id TEXT NOT NULL REFERENCES multipart_uploads(upload_id) ON DELETE CASCADE,
  part_number BIGINT NOT NULL,
  size BIGINT NOT NULL,
  etag TEXT NOT NULL,
  plaintext_sha256 TEXT NOT NULL DEFAULT '',
  ciphertext_sha256 TEXT NOT NULL DEFAULT '',
  spool_path TEXT NULL,
  remote_locator_json TEXT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')),
  PRIMARY KEY(upload_id, part_number)
);
ALTER TABLE objects ADD COLUMN IF NOT EXISTS user_metadata_json TEXT NULL;
ALTER TABLE objects ADD COLUMN IF NOT EXISTS system_metadata_json TEXT NULL;

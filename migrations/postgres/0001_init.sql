-- pg 0001_init: schema goc TeleCrate, dialect Postgres (TEXT datetime UTC, BIGINT).
-- Tuong duong migrations/0001_init.sql. Forward-only.
CREATE TABLE IF NOT EXISTS schema_version(
  version BIGINT PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);
CREATE TABLE IF NOT EXISTS buckets(
  name TEXT PRIMARY KEY,
  region TEXT NOT NULL DEFAULT 'telecrate-1',
  versioning_status TEXT NOT NULL DEFAULT 'Disabled',
  encryption_override TEXT NULL,
  created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);
CREATE TABLE IF NOT EXISTS objects(
  bucket TEXT NOT NULL REFERENCES buckets(name),
  key TEXT NOT NULL,
  version_id TEXT PRIMARY KEY,
  is_delete_marker BIGINT NOT NULL DEFAULT 0,
  storage_state TEXT NOT NULL DEFAULT 'accepted-local',
  size BIGINT NOT NULL DEFAULT 0,
  etag TEXT NOT NULL DEFAULT '',
  content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);
CREATE INDEX IF NOT EXISTS idx_objects_bucket_key ON objects(bucket, key, created_at DESC);
CREATE TABLE IF NOT EXISTS chunks(
  version_id TEXT NOT NULL REFERENCES objects(version_id),
  idx BIGINT NOT NULL,
  "offset" BIGINT NOT NULL,
  length BIGINT NOT NULL,
  plaintext_sha256 TEXT NOT NULL DEFAULT '',
  ciphertext_sha256 TEXT NOT NULL DEFAULT '',
  encryption_mode TEXT NOT NULL DEFAULT 'none',
  key_ref TEXT NULL,
  nonce TEXT NULL,
  spool_path TEXT NULL,
  remote_locator_json TEXT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  PRIMARY KEY(version_id, idx)
);
CREATE TABLE IF NOT EXISTS upload_jobs(
  job_id TEXT PRIMARY KEY,
  version_id TEXT NOT NULL REFERENCES objects(version_id),
  state TEXT NOT NULL DEFAULT 'pending',
  lease_owner TEXT NULL,
  lease_expires TEXT NULL,
  retry_count BIGINT NOT NULL DEFAULT 0,
  next_attempt TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')),
  generation BIGINT NOT NULL DEFAULT 1,
  last_error TEXT NULL
);
CREATE TABLE IF NOT EXISTS recovery_checkpoints(
  seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  manifest_json TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);
CREATE TABLE IF NOT EXISTS kv(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

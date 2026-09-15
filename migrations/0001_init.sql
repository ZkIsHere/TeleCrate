-- 0001_init: schema gốc TeleCrate (M0). Forward-only, không sửa sau release.
-- Downgrade constraint: không auto-rollback dữ liệu; rollback chỉ bằng restore từ backup.

CREATE TABLE IF NOT EXISTS schema_version(
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS buckets(
  name TEXT PRIMARY KEY,
  region TEXT NOT NULL DEFAULT 'telecrate-1',
  versioning_status TEXT NOT NULL DEFAULT 'Disabled',
  encryption_override TEXT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS objects(
  bucket TEXT NOT NULL,
  key TEXT NOT NULL,
  version_id TEXT PRIMARY KEY,
  is_delete_marker INTEGER NOT NULL DEFAULT 0,
  storage_state TEXT NOT NULL DEFAULT 'accepted-local',
  size INTEGER NOT NULL DEFAULT 0,
  etag TEXT NOT NULL DEFAULT '',
  content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(bucket) REFERENCES buckets(name)
);
CREATE INDEX IF NOT EXISTS idx_objects_bucket_key ON objects(bucket, key, created_at DESC);

CREATE TABLE IF NOT EXISTS chunks(
  version_id TEXT NOT NULL REFERENCES objects(version_id),
  idx INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  length INTEGER NOT NULL,
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
  retry_count INTEGER NOT NULL DEFAULT 0,
  next_attempt TEXT NOT NULL DEFAULT (datetime('now')),
  generation INTEGER NOT NULL DEFAULT 1,
  last_error TEXT NULL
);

CREATE TABLE IF NOT EXISTS recovery_checkpoints(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  manifest_json TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS kv(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

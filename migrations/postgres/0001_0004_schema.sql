-- TeleCrate Postgres schema — equivalent to SQLite migrations 0001..0004.
-- Forward-only; generate with `telecrate db pg-schema` (loaded via include_str!
-- as DbBackend::POSTGRES_SCHEMA). Runtime DAL port: blocked (ADR 0005).
CREATE TABLE IF NOT EXISTS schema_version(
  version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS buckets(
  name TEXT PRIMARY KEY,
  region TEXT NOT NULL DEFAULT 'telecrate-1',
  versioning_status TEXT NOT NULL DEFAULT 'Disabled',
  encryption_override TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS objects(
  bucket TEXT NOT NULL REFERENCES buckets(name),
  key TEXT NOT NULL,
  version_id TEXT PRIMARY KEY,
  is_delete_marker INTEGER NOT NULL DEFAULT 0,
  storage_state TEXT NOT NULL DEFAULT 'accepted-local',
  size BIGINT NOT NULL DEFAULT 0,
  etag TEXT NOT NULL DEFAULT '',
  content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_metadata_json TEXT NULL,
  system_metadata_json TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_objects_bucket_key ON objects(bucket, key, created_at DESC);
CREATE TABLE IF NOT EXISTS chunks(
  version_id TEXT NOT NULL REFERENCES objects(version_id),
  idx INTEGER NOT NULL,
  offset BIGINT NOT NULL,
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
  lease_expires TIMESTAMPTZ NULL,
  retry_count INTEGER NOT NULL DEFAULT 0,
  next_attempt TIMESTAMPTZ NOT NULL DEFAULT now(),
  generation BIGINT NOT NULL DEFAULT 1,
  last_error TEXT NULL
);
CREATE TABLE IF NOT EXISTS recovery_checkpoints(
  seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  manifest_json TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS kv(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS multipart_uploads(
  upload_id TEXT PRIMARY KEY,
  bucket TEXT NOT NULL REFERENCES buckets(name),
  key TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  metadata_json TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_multipart_uploads_bucket_key ON multipart_uploads(bucket, key, created_at DESC);
CREATE TABLE IF NOT EXISTS multipart_parts(
  upload_id TEXT NOT NULL REFERENCES multipart_uploads(upload_id) ON DELETE CASCADE,
  part_number INTEGER NOT NULL,
  size BIGINT NOT NULL,
  etag TEXT NOT NULL,
  plaintext_sha256 TEXT NOT NULL DEFAULT '',
  ciphertext_sha256 TEXT NOT NULL DEFAULT '',
  spool_path TEXT NULL,
  remote_locator_json TEXT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(upload_id, part_number)
);
CREATE TABLE IF NOT EXISTS access_keys(
  access_key_id TEXT PRIMARY KEY,
  secret_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Active',
  description TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ NULL,
  allowed_buckets TEXT NULL
);
CREATE TABLE IF NOT EXISTS bucket_policies(
  bucket TEXT PRIMARY KEY REFERENCES buckets(name) ON DELETE CASCADE,
  policy_json TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bucket_cors(
  bucket TEXT PRIMARY KEY REFERENCES buckets(name) ON DELETE CASCADE,
  cors_json TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bucket_bpa(
  bucket TEXT PRIMARY KEY REFERENCES buckets(name) ON DELETE CASCADE,
  block_public_acls INTEGER NOT NULL DEFAULT 0,
  ignore_public_acls INTEGER NOT NULL DEFAULT 0,
  block_public_policy INTEGER NOT NULL DEFAULT 0,
  restrict_public_buckets INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bucket_lock_configs(
  bucket TEXT PRIMARY KEY REFERENCES buckets(name) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'Enabled',
  default_retention_mode TEXT NULL,
  default_retention_days INTEGER NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS object_locks(
  bucket TEXT NOT NULL,
  key TEXT NOT NULL,
  version_id TEXT NOT NULL REFERENCES objects(version_id) ON DELETE CASCADE,
  retain_until_date TIMESTAMPTZ NULL,
  mode TEXT NULL,
  legal_hold INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(bucket, key, version_id)
);

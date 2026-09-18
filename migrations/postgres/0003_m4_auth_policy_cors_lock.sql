-- pg 0003_m4_auth_policy_cors_lock: tuong duong migrations/0003_*.sql. Forward-only.
CREATE TABLE IF NOT EXISTS access_keys(
  access_key_id TEXT PRIMARY KEY,
  secret_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Active',
  description TEXT NULL,
  created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);
CREATE TABLE IF NOT EXISTS bucket_policies(
  bucket TEXT PRIMARY KEY REFERENCES buckets(name) ON DELETE CASCADE,
  policy_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);
CREATE TABLE IF NOT EXISTS bucket_cors(
  bucket TEXT PRIMARY KEY REFERENCES buckets(name) ON DELETE CASCADE,
  cors_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);
CREATE TABLE IF NOT EXISTS bucket_bpa(
  bucket TEXT PRIMARY KEY REFERENCES buckets(name) ON DELETE CASCADE,
  block_public_acls BIGINT NOT NULL DEFAULT 0,
  ignore_public_acls BIGINT NOT NULL DEFAULT 0,
  block_public_policy BIGINT NOT NULL DEFAULT 0,
  restrict_public_buckets BIGINT NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);
CREATE TABLE IF NOT EXISTS bucket_lock_configs(
  bucket TEXT PRIMARY KEY REFERENCES buckets(name) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'Enabled',
  default_retention_mode TEXT NULL,
  default_retention_days BIGINT NULL,
  updated_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))
);
CREATE TABLE IF NOT EXISTS object_locks(
  bucket TEXT NOT NULL,
  key TEXT NOT NULL,
  version_id TEXT NOT NULL REFERENCES objects(version_id) ON DELETE CASCADE,
  retain_until_date TEXT NULL,
  mode TEXT NULL,
  legal_hold BIGINT NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')),
  PRIMARY KEY(bucket, key, version_id)
);

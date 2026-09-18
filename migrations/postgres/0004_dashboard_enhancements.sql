-- pg 0004_dashboard_enhancements: tuong duong migrations/0004_*.sql. Forward-only.
ALTER TABLE access_keys ADD COLUMN IF NOT EXISTS last_used_at TEXT NULL;
ALTER TABLE access_keys ADD COLUMN IF NOT EXISTS allowed_buckets TEXT NULL;

-- 0004_dashboard_enhancements: Thêm trường cho Access Key management mở rộng.
-- Forward-only migration. Không sửa migration đã release.

-- last_used_at: timestamp lần cuối key được dùng auth thành công (NULL = chưa dùng).
ALTER TABLE access_keys ADD COLUMN last_used_at TEXT NULL;

-- allowed_buckets: JSON array tên bucket key được truy cập, NULL = unrestricted.
-- Ví dụ: '["backups","data"]' hoặc NULL.
ALTER TABLE access_keys ADD COLUMN allowed_buckets TEXT NULL;

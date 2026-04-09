DROP INDEX IF EXISTS idx_volume_permissions_grantee_status;
DROP INDEX IF EXISTS unique_active_volume_permission;

ALTER TABLE volume_permissions
DROP COLUMN IF EXISTS revoked_at;

ALTER TABLE volume_permissions
DROP COLUMN IF EXISTS status;
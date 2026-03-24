ALTER TABLE volume_permissions
ADD COLUMN IF NOT EXISTS status permission_status NOT NULL DEFAULT 'ACTIVE';

ALTER TABLE volume_permissions
ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS unique_active_volume_permission
ON volume_permissions(volume_id, grantee_id)
WHERE status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_volume_permissions_grantee_status
ON volume_permissions(grantee_id, status);
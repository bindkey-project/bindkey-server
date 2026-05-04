-- Restauration du schéma volume_permissions tel qu'il existait avant la suppression
-- (cumul des migrations 202512050007 + 202603080005 + 20260324232755).
CREATE TYPE permission_level  AS ENUM ('READ', 'READ_WRITE');
CREATE TYPE permission_status AS ENUM ('ACTIVE', 'REVOKED');

CREATE TABLE volume_permissions (
    id          UUID PRIMARY KEY,
    volume_id   UUID NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
    grantee_id  UUID NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    permission  permission_level  NOT NULL,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  UUID REFERENCES users(id),
    status      permission_status NOT NULL DEFAULT 'ACTIVE',
    revoked_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX unique_active_volume_permission
    ON volume_permissions(volume_id, grantee_id)
    WHERE status = 'ACTIVE';

CREATE INDEX idx_volume_permissions_grantee_status
    ON volume_permissions(grantee_id, status);

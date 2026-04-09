CREATE TABLE volume_keys (
    id UUID PRIMARY KEY,
    volume_id UUID NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
    encrypted_key TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX volume_keys_volume_id_key_version_unique
ON volume_keys(volume_id, key_version);

CREATE UNIQUE INDEX volume_keys_one_active_per_volume
ON volume_keys(volume_id)
WHERE is_active = TRUE;
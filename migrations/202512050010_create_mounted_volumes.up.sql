CREATE TABLE mounted_volumes (
    id UUID PRIMARY KEY,
    volume_id UUID NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    
    -- SUPPRIMÉ : device_id REFERENCES devices(id)
    device_id UUID,  -- plus de référence à devices

    mounted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    unmounted_at TIMESTAMPTZ,
    device_info JSONB
);

CREATE TABLE mounted_volumes (
    id UUID PRIMARY KEY,

    -- Volume monté
    volume_id UUID NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,

    -- L'utilisateur qui a monté le volume
    user_id UUID NOT NULL REFERENCES users(id),

    -- Session utilisée pour effectuer le montage
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,

    mounted_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    expires_at TIMESTAMPTZ,
    unmounted_at TIMESTAMPTZ,

    device_info TEXT
);

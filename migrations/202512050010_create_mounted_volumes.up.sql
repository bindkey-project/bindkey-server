CREATE TABLE mounted_volumes (
    id UUID PRIMARY KEY,
    volume_id UUID NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),

    mounted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    unmounted_at TIMESTAMPTZ
);

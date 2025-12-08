-- Enum pour le niveau de permission d'un volume
CREATE TYPE permission_level AS ENUM ('READ', 'READ_WRITE');

-- Table volume_permissions (partage des volumes entre utilisateurs)
CREATE TABLE volume_permissions (
    id UUID PRIMARY KEY,

    -- Le volume partagé
    volume_id UUID NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,

    -- L'utilisateur qui reçoit l'accès
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Permission (READ / READ_WRITE)
    permission permission_level NOT NULL DEFAULT 'READ',

    -- Date d'expiration du partage (optionnel)
    expires_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

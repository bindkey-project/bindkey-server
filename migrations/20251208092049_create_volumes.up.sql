-- Table volumes (volumes chiffrés BindKey)
CREATE TABLE volumes (
    id UUID PRIMARY KEY,

    -- Propriétaire du volume (User Story 2)
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Disque physique sur lequel le volume est stocké
    disk_id UUID NOT NULL REFERENCES disks(id) ON DELETE CASCADE,

    -- Nom du volume
    name TEXT NOT NULL,

    -- Taille du volume en octets
    size_bytes BIGINT NOT NULL,

    -- Clé symétrique chiffrée (Base64 ou similar)
    encrypted_key TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

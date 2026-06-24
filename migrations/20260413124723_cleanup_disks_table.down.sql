-- migration cleanup_disks_table (DOWN)
BEGIN;

-- 1. Recréer la table disks
CREATE TABLE IF NOT EXISTS disks (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Rajouter la colonne disk_id dans volumes
ALTER TABLE volumes ADD COLUMN IF NOT EXISTS disk_id UUID REFERENCES disks(id);

COMMIT;
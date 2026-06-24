-- 1. Création de la table avec sécurité
CREATE TABLE IF NOT EXISTS volume_keys (
    id UUID PRIMARY KEY,
    volume_id UUID NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
    encrypted_key TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Création des index (avec DO pour éviter l'erreur si déjà existants)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'volume_keys_volume_id_key_version_unique') THEN
        CREATE UNIQUE INDEX volume_keys_volume_id_key_version_unique ON volume_keys(volume_id, key_version);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'volume_keys_one_active_per_volume') THEN
        CREATE UNIQUE INDEX volume_keys_one_active_per_volume ON volume_keys(volume_id) WHERE is_active = TRUE;
    END IF;
END $$;
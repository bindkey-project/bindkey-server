-- ENUM nécessaire pour la table bindkeys
CREATE TYPE bindkey_status AS ENUM ('ACTIVE', 'RESET', 'LOST', 'BROKEN');

-- Table bindkeys (clés physiques BindKey)
CREATE TABLE bindkeys (
    id UUID PRIMARY KEY,

    -- utilisateur propriétaire (nullable pendant l’enrôlement)
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- identifiant matériel unique renvoyé par la BindKey
    bindkey_uid TEXT UNIQUE NOT NULL,

    -- empreinte du doigt (hash)
    fingerprint_hash TEXT NOT NULL,

    -- clé publique du Secure Element
    public_key TEXT NOT NULL,

    -- statut BindKey : ACTIVE, RESET, LOST, BROKEN
    status bindkey_status NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

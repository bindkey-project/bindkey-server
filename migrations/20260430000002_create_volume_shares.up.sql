-- Enum de statut de livraison d'un partage de volume.
-- PENDING   : partage stocké côté serveur, pas encore récupéré par l'app cible.
-- DELIVERED : la BK cible a confirmé la réception (ack côté app).
CREATE TYPE volume_share_status AS ENUM ('PENDING', 'DELIVERED');

-- Table volume_shares
-- Trace chaque partage de volume entre deux BindKeys.
-- Le serveur ne peut PAS déchiffrer wrapped_blob (chiffré ECDH par la BK source
-- pour la BK cible, clés privées dans les SE ATECC608).
CREATE TABLE volume_shares (
    id UUID PRIMARY KEY,

    -- SN ATECC608 (9 bytes) de la BK source / cible.
    -- Référencent bindkeys.bindkey_uid (UNIQUE) — qui sera renommée en `sn`
    -- par la migration 20260430000004, et la FK suit automatiquement (Postgres
    -- track les FK par OID de colonne, pas par nom).
    source_sn TEXT NOT NULL REFERENCES bindkeys(bindkey_uid) ON DELETE CASCADE,
    target_sn TEXT NOT NULL REFERENCES bindkeys(bindkey_uid) ON DELETE CASCADE,

    -- Volume partagé. UUID = 16 bytes binaires, ce qui correspond exactement
    -- au volume_id côté firmware (BkTable de la source).
    volume_id UUID NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,

    -- Slot ATECC608 sur la BK cible où la clé partagée sera stockée.
    -- Plage autorisée par le firmware : [10..14] (5 slots de partage par device).
    target_slot SMALLINT NOT NULL CHECK (target_slot BETWEEN 10 AND 14),

    -- Bundle chiffré opaque produit par la BK source (nonce || ciphertext || tag).
    -- Taille fixée par le firmware : 60 bytes exactement.
    wrapped_blob BYTEA NOT NULL CHECK (octet_length(wrapped_blob) = 60),

    status volume_share_status NOT NULL DEFAULT 'PENDING',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,

    -- Un slot reste occupé tant qu'aucune révocation n'est implémentée :
    -- on interdit donc deux partages actifs sur le même slot d'une même cible.
    UNIQUE (target_sn, target_slot)
);

-- Index pour les requêtes de polling de la cible.
CREATE INDEX idx_volume_shares_target_status
    ON volume_shares (target_sn, status);

-- Index pour les listings côté source.
CREATE INDEX idx_volume_shares_source
    ON volume_shares (source_sn);

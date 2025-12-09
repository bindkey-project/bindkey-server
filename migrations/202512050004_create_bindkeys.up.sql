CREATE TABLE bindkeys (                                        
    -- Table pour les "BindKeys" (identités sécurisées / clés biométriques)

    id UUID PRIMARY KEY,                                       
    -- Identifiant unique de la BindKey.

    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Chaque BindKey appartient à un user.
    -- Si le user est supprimé, on supprime aussi ses bindkeys.

    bindkey_uid TEXT UNIQUE NOT NULL,                          
    -- Identifiant fonctionnel de la BindKey (exposé au client).
    -- UNIQUE pour éviter les doublons.

    fingerprint_template TEXT NOT NULL,                        
    -- Gabarit biométrique (empreinte) en version encodée/serialisée.
    -- NOT NULL car une BindKey sans empreinte n’a pas de sens.

    public_key TEXT NOT NULL,                                  
    -- Clé publique associée à la BindKey (pour crypto, signatures, etc.).
    -- NOT NULL : élément central du système de sécurité.

    status bindkey_status NOT NULL DEFAULT 'ACTIVE',           
    -- Enum pour l’état de la BindKey (ex: ACTIVE, REVOKED...).
    -- NOT NULL avec valeur par défaut ACTIVE.

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()              
    -- Date de création de la BindKey.
);

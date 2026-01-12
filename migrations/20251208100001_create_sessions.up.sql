-- Table sessions (gère les sessions d'accès sécurisées entre un user et sa BindKey)
CREATE TABLE sessions (
    id UUID PRIMARY KEY,

    -- Utilisateur authentifié
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- BindKey utilisée pour cette session
    bindkey_id UUID NOT NULL REFERENCES bindkeys(id) ON DELETE CASCADE,

    -- Jeton côté serveur (utilisé dans les requêtes API)
    server_token TEXT NOT NULL,

    -- Jeton côté client/soft (pour renforcer la session localement)
    local_token TEXT NOT NULL,

    -- Date d'expiration de la session
    expires_at TIMESTAMPTZ NOT NULL,

    -- Date de création de la session
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

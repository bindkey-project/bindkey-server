CREATE TABLE sessions (                                        
    -- Sessions d’authentification actives entre client et serveur

    id UUID PRIMARY KEY,                                       
    -- Identifiant de la session.

    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- User connecté.

    bindkey_id UUID NOT NULL REFERENCES bindkeys(id) ON DELETE CASCADE,
    -- BindKey utilisée pour créer la session.
    -- Si la BindKey est supprimée, les sessions associées sont supprimées.

    server_token TEXT NOT NULL UNIQUE,                         
    -- Jeton côté serveur (stocké en DB) pour identifier la session.
    -- UNIQUE pour éviter les collisions.

    local_token TEXT NOT NULL UNIQUE,                          
    -- Jeton utilisé côté client/appareil (par ex. dans le storage local).
    -- UNIQUE aussi pour pouvoir invalider précisément une session.

    expires_at TIMESTAMPTZ NOT NULL,                           
    -- Date d’expiration de la session (obligatoire pour la sécurité).

    device_id UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()             
    -- Date de création de la session.
);

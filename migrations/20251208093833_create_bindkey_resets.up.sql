-- Table bindkey_resets (historique des réinitialisations BindKey)
CREATE TABLE bindkey_resets (
    id UUID PRIMARY KEY,

    -- BindKey qui a été réinitialisée
    bindkey_id UUID NOT NULL REFERENCES bindkeys(id) ON DELETE CASCADE,

    -- Type de réinitialisation : RESET, ADMIN_RESET, FACTORY_RESET, LOST_RESET, etc.
    reset_type TEXT NOT NULL,

    -- Utilisateur (souvent admin) qui a effectué le reset
    performed_by UUID NOT NULL REFERENCES users(id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

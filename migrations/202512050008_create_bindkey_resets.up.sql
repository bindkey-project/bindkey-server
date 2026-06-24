CREATE TABLE bindkey_resets (                                  
    -- Historique des resets / réinitialisations de BindKeys

    id UUID PRIMARY KEY,                                       
    -- Identifiant unique de l’événement de reset.

    bindkey_id UUID NOT NULL REFERENCES bindkeys(id) ON DELETE CASCADE,
    -- BindKey concernée par le reset.
    -- ON DELETE CASCADE : si la BindKey est supprimée, on n’a plus besoin de conserver ces resets.

    reset_type TEXT NOT NULL,                                  
    -- Type de reset (ex: "lost_device", "security_compromise").
    -- En TEXT pour rester flexible au début.

    performed_by UUID NOT NULL REFERENCES users(id),           
    -- User qui a effectué l’action (admin, owner…).
    -- NOT NULL pour savoir qui est responsable.

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()              
    -- Date de l’opération de reset.
);

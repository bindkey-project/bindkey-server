-- Table audit_logs (trace toutes les actions sensibles)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY,

    -- Utilisateur à l'origine de l'action (facultatif : certaines actions système n'ont pas de user)
    user_id UUID REFERENCES users(id),

    -- BindKey impliquée dans l'action (facultatif)
    bindkey_id UUID REFERENCES bindkeys(id),

    -- Description courte de l'action : "VOLUME_MOUNT", "BINDKEY_RESET", "LOGIN_FAILED", etc.
    action TEXT NOT NULL,

    -- Détails supplémentaires sous forme texte ou JSON si tu veux plus tard
    details TEXT,

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (                                      
    -- Journal d’audit des actions importantes dans le système

    id UUID PRIMARY KEY,                                       
    -- Identifiant unique du log.

    user_id UUID REFERENCES users(id),                         
    -- User à l’origine de l’action (si applicable).
    -- Optionnel : certaines actions peuvent venir d’un système interne.

    bindkey_id UUID REFERENCES bindkeys(id),                   
    -- BindKey concernée par l’action (si c’est le cas).
    -- Optionnel aussi.

    action TEXT NOT NULL,                                      
    -- Type d’action (ex: "LOGIN", "MOUNT_VOLUME", "RESET_BINDKEY").
    -- NOT NULL car un log sans action ne sert à rien.

    details TEXT,                                              
    -- Détails textuels (message, contexte…).
    -- Optionnel pour rester léger si on n’a pas toujours des détails.

    severity TEXT NOT NULL DEFAULT 'INFO',                     
    -- Niveau de gravité (INFO, WARNING, ERROR…).
    -- TEXT pour rester souple, DEFAULT 'INFO' pour les événements normaux.

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()              
    -- Date de l’événement loggé.
);

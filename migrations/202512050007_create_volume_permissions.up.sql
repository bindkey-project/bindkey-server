CREATE TABLE volume_permissions (                              
    -- Droits d’accès aux volumes (partage entre users)

    id UUID PRIMARY KEY,                                       
    -- Identifiant unique de la permission.

    volume_id UUID NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
    -- Volume concerné.
    -- ON DELETE CASCADE : si le volume disparaît, les permissions aussi.

    grantee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- User qui reçoit l’accès au volume (grantee = bénéficiaire).
    -- ON DELETE CASCADE : si ce user est supprimé, on retire son droit.

    permission permission_level NOT NULL,                       
    -- Enum pour le niveau d’accès (READ, WRITE, OWNER, etc.).
    -- NOT NULL : une permission doit toujours avoir un niveau clair.

    expires_at TIMESTAMPTZ,                                    
    -- Date d’expiration du droit (optionnel).
    -- NULL = permission sans expiration.

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),             
    -- Date de création de la permission.

    created_by UUID REFERENCES users(id)                       
    -- User qui a créé cette permission (admin ou owner).
    -- Optionnel, car certains systèmes auto peuvent créer des droits.
);

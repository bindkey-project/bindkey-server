CREATE TABLE devices (                                         
    -- Table pour représenter les appareils (PC, laptop…) utilisés par les users

    id UUID PRIMARY KEY,                                       
    -- Identifiant unique de l’appareil, en UUID pour éviter les collisions.

    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, 
    -- L’appareil appartient à un user précis.
    -- NOT NULL : un device doit toujours être lié à un user.
    -- FOREIGN KEY vers users(id).
    -- ON DELETE CASCADE : si le user est supprimé, tous ses devices sont supprimés aussi.

    device_name TEXT NOT NULL,                                 
    -- Nom lisible du device .
    -- NOT NULL car ça aide pour l’UI et le debug.

    os TEXT,                                                   
    -- Système d'exploitation (Windows, Linux, macOS…).
    -- Optionnel, car on peut ne pas toujours détecter l’OS.

    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),              
    -- Dernière fois où l’appareil a été vu/actif.
    -- NOT NULL + DEFAULT now() : on trace au moins la création.

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()              
    -- Date de création de l’enregistrement device.
    -- TIMESTAMPTZ pour gérer les fuseaux.
);

CREATE TABLE volumes (                                         
    -- Volumes logiques stockés sur un disque (partition / volume chiffré)

    id UUID PRIMARY KEY,                                       
    -- Identifiant unique du volume.

    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- User propriétaire du volume (celui qui en a le contrôle principal).
    -- Si ce user est supprimé, on supprime aussi ses volumes.

    disk_id UUID NOT NULL REFERENCES disks(id) ON DELETE CASCADE,
    -- Le volume est hébergé sur un disque précis.
    -- ON DELETE CASCADE : si le disque est retiré de la config, les volumes associés disparaissent aussi.

    name TEXT NOT NULL,                                        
    -- Nom du volume pour l’UI 

    size_bytes BIGINT NOT NULL,                                
    -- Taille allouée au volume en octets.

    encrypted_key TEXT NOT NULL,                               
    -- Clé chiffrée utilisée pour accéder au volume (jamais en clair).
    -- NOT NULL : un volume sans clé chiffrée n’est pas utilisable.

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),             
    -- Date de création du volume.

    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()              
    -- Dernière mise à jour (taille, clé, etc.).
    -- À mettre à jour via code/trigger lorsque les métadonnées changent.
);

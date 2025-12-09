CREATE TABLE users (                             -- Table principale pour stocker les comptes utilisateurs de l'appli

    id UUID PRIMARY KEY,                         
    -- Identifiant unique global (UUID) pour éviter les collisions et ne pas dépendre d'un simple entier auto-incrémenté.

    first_name TEXT NOT NULL,                    
    -- Prénom obligatoire : on veut toujours savoir comment afficher
    -- le nom de l'utilisateur, donc NOT NULL.

    last_name TEXT NOT NULL,                     
    -- Nom de famille obligatoire pour les mêmes raisons (affichage, recherche, identification).

    job_title TEXT,                              
    -- Intitulé de poste facultatif : l'utilisateur peut ne pas en avoir ou ne pas vouloir le renseigner → donc NULL autorisé.

    email TEXT UNIQUE NOT NULL,                  
    -- Email obligatoire pour se connecter / récupérer le compte.
    -- UNIQUE pour garantir qu’un email ne correspond qu’à un seul compte.

    role user_role NOT NULL DEFAULT 'USER',      
    -- Rôle de l'utilisateur (enum user_role) : par ex. USER, ADMIN...
    -- NOT NULL car tout user doit avoir un rôle.
    -- DEFAULT 'USER' car c’est le rôle standard à la création.

    status user_status NOT NULL DEFAULT 'ACTIVE',
    -- Statut du compte (enum user_status) : ACTIVE, SUSPENDED, etc.
    -- NOT NULL car un compte doit toujours avoir un état clair.
    -- DEFAULT 'ACTIVE' pour que le compte soit utilisable dès la création.

    recovery_code_hash TEXT NOT NULL,            
    -- Hash du code de récupération (pour reset mot de passe ou accès).
    -- Stocké en hash pour la sécurité, jamais en clair.
    -- NOT NULL car on impose qu’un code de récup soit généré à la création (ou tu adapteras selon ta logique métier).

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), 
    -- Date/heure de création du compte.
    -- TIMESTAMPTZ pour gérer correctement les fuseaux horaires.
    -- DEFAULT now() pour que Postgres remplisse tout seul à l’insertion.

    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()  
    -- Date/heure de dernière modification du compte.
    -- TIMESTAMPTZ pour la même raison.
    -- DEFAULT now() et tu le mettras à jour via triggers / code backend.
);


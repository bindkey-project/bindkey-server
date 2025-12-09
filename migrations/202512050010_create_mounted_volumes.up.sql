CREATE TABLE mounted_volumes (                                 
    -- Volumes actuellement montés sur des devices pour des users

    id UUID PRIMARY KEY,                                       
    -- Identifiant unique du "mount" (montage).

    volume_id UUID NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
    -- Volume qui a été monté.
    -- Si le volume est supprimé, on supprime aussi son historique de montages.

    user_id UUID NOT NULL REFERENCES users(id),                
    -- User qui a monté le volume (celui qui l’utilise).

    device_id UUID REFERENCES devices(id),                     
    -- Appareil où le volume est monté (optionnel si inconnu/abstrait).

    mounted_at TIMESTAMPTZ NOT NULL DEFAULT now(),             
    -- Moment où le volume a été monté.
    -- NOT NULL pour tracer tout montage.

    expires_at TIMESTAMPTZ,                                    
    -- Date limite d’accès .
    -- Optionnel.

    unmounted_at TIMESTAMPTZ,                                  
    -- Moment où le volume a été démonté.
    -- NULL = encore monté ou pas correctement fermé.

    device_info JSONB                                          
    -- Infos supplémentaires sur le device (IP, user-agent, OS détaillé…).
    -- JSONB pour être flexible et pouvoir faire des requêtes sur ce JSON.
);


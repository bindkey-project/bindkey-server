-- Suppression de l’index 
DROP INDEX IF EXISTS volumes_bindkey_id_unique;

-- Suppression de la contrainte FK
ALTER TABLE volumes
DROP CONSTRAINT IF EXISTS fk_volumes_bindkey;

-- Suppression de la colonne
ALTER TABLE volumes
DROP COLUMN IF EXISTS bindkey_id;


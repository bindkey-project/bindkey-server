-- 1. Supprimer la colonne challenge
ALTER TABLE sessions DROP COLUMN IF EXISTS auth_challenge;

-- 2. Remettre la contrainte NOT NULL sur les tokens
-- Note : On force une valeur par défaut ('temp_token') pour les lignes existantes qui seraient NULL
UPDATE sessions SET server_token = 'revoked' WHERE server_token IS NULL;
UPDATE sessions SET local_token = 'revoked' WHERE local_token IS NULL;

ALTER TABLE sessions ALTER COLUMN server_token SET NOT NULL;
ALTER TABLE sessions ALTER COLUMN local_token SET NOT NULL;
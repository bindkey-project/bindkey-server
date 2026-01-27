-- Ajouter la colonne challenge
ALTER TABLE sessions ADD COLUMN auth_challenge TEXT;

-- Permettre aux tokens d'être vides au début du processus d'auth
ALTER TABLE sessions ALTER COLUMN server_token DROP NOT NULL;
ALTER TABLE sessions ALTER COLUMN local_token DROP NOT NULL;
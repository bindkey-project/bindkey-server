-- migration cleanup_disks_table (UP)
BEGIN;

-- 1. Supprimer la contrainte de clé étrangère
ALTER TABLE volumes DROP CONSTRAINT IF EXISTS volumes_disk_id_fkey;

-- 2. Supprimer la colonne disk_id
ALTER TABLE volumes DROP COLUMN IF EXISTS disk_id;

-- 3. Supprimer la table disks
DROP TABLE IF EXISTS disks CASCADE;

COMMIT;
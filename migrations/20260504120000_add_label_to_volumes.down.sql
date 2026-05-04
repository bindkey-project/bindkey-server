ALTER TABLE volumes DROP CONSTRAINT IF EXISTS volumes_owner_label_unique;
ALTER TABLE volumes DROP COLUMN IF EXISTS label;

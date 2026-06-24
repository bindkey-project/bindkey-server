ALTER TABLE volumes DROP CONSTRAINT IF EXISTS volumes_label_unique;
ALTER TABLE volumes ADD CONSTRAINT volumes_owner_label_unique UNIQUE (owner_id, label);

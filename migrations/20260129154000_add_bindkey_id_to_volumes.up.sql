-- Ajout du lien volume -> bindkey
ALTER TABLE volumes
ADD COLUMN bindkey_id UUID;

-- Contrainte de clé étrangère
ALTER TABLE volumes
ADD CONSTRAINT fk_volumes_bindkey
FOREIGN KEY (bindkey_id)
REFERENCES bindkeys(id)
ON DELETE CASCADE;

-- plusieurs volume par BindKey
CREATE INDEX volumes_bindkey_id_unique
ON volumes(bindkey_id)
WHERE bindkey_id IS NOT NULL;

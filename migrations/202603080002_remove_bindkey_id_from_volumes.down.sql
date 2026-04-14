ALTER TABLE volumes
ADD COLUMN bindkey_id UUID;

ALTER TABLE volumes
ADD CONSTRAINT fk_volumes_bindkey
FOREIGN KEY (bindkey_id)
REFERENCES bindkeys(id)
ON DELETE CASCADE;

CREATE INDEX volumes_bindkey_id_unique
ON volumes(bindkey_id)
WHERE bindkey_id IS NOT NULL;
ALTER TABLE volumes ADD COLUMN label TEXT;

UPDATE volumes v
SET label = sub.computed_label
FROM (
    SELECT id,
           'bindkey-vol-' || lpad(
               row_number() OVER (PARTITION BY owner_id ORDER BY created_at, id)::text,
               4, '0'
           ) AS computed_label
    FROM volumes
) sub
WHERE v.id = sub.id;

ALTER TABLE volumes ALTER COLUMN label SET NOT NULL;
ALTER TABLE volumes ADD CONSTRAINT volumes_owner_label_unique UNIQUE (owner_id, label);

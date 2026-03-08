DROP INDEX IF EXISTS volumes_bindkey_id_unique;

ALTER TABLE volumes
DROP CONSTRAINT IF EXISTS fk_volumes_bindkey;

ALTER TABLE volumes
DROP COLUMN IF EXISTS bindkey_id;



--Pourquoi on le supprime

--Parce que :

--un volume appartient à un owner

--il est sur un disk

--il est partagé à des users

--les bindkeys de ces users récupèrent les droits au moment du sync

--Donc la liaison se fait via :

--volume_permissions

--puis la BindKey de l’utilisateur connecté

--Pas par volumes.bindkey_id.
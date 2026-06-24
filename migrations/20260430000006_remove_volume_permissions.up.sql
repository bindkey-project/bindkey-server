-- Suppression du système de permissions (remplacé par volume_shares).
-- Les enums permission_level / permission_status n'étaient utilisés
-- que par volume_permissions, on les supprime aussi.
DROP TABLE IF EXISTS volume_permissions;
DROP TYPE  IF EXISTS permission_status;
DROP TYPE  IF EXISTS permission_level;

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS mounted_volumes;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS bindkey_resets;
DROP TABLE IF EXISTS volume_permissions;
DROP TABLE IF EXISTS volumes;
DROP TABLE IF EXISTS disks;
DROP TABLE IF EXISTS bindkeys;
DROP TABLE IF EXISTS devices;  -- ✅ ajoute cette ligne si elle manque
DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS permission_level;
DROP TYPE IF EXISTS bindkey_status;
DROP TYPE IF EXISTS user_status;
DROP TYPE IF EXISTS user_role;

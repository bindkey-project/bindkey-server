-- Add down migration script here
DROP INDEX IF EXISTS idx_volumes_bindkey_id;
ALTER TABLE volumes DROP COLUMN IF EXISTS bindkey_id;
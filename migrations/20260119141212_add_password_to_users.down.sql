-- Add down migration script here
-- migrations/XXXXXXXX_add_password_to_users.down.sql
ALTER TABLE users DROP COLUMN password_hash;
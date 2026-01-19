-- Add up migration script here
-- migrations/XXXXXXXXXXXXXX_add_password_to_users.sql
ALTER TABLE users ADD COLUMN password_hash TEXT;
-- Ajout de la pubkey ECDH P-256 (slot 1 ATECC608) à chaque BindKey enrôlée.
-- Indispensable pour cibler un device lors d'un partage de volume.
-- Nullable : les BindKeys enrôlées avant cette feature n'ont pas ce champ
-- et ne pourront donc pas recevoir de partage tant qu'elles ne sont pas
-- ré-enrôlées.
ALTER TABLE bindkeys ADD COLUMN IF NOT EXISTS pub_ecdh TEXT;

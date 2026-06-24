-- Certificat X.509 signé par la Root CA, unique par BindKey.
-- La Root CA elle-même est stockée dans le Secret K8s `bindkey-rootca`,
-- pas en base.
ALTER TABLE bindkeys ADD COLUMN IF NOT EXISTS certificate TEXT;

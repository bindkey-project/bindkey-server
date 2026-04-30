-- Renommage cosmétique : la colonne `public_key` stocke en réalité PUB_SIGN,
-- la pubkey ECDSA P-256 (slot 0 ATECC608) utilisée pour vérifier les signatures.
-- Avec l'ajout de pub_ecdh (slot 1), il devient ambigu de l'appeler "public_key".
-- L'app/firmware ayant déjà fait le renommage, on s'aligne côté serveur.
ALTER TABLE bindkeys RENAME COLUMN public_key TO pub_sign;

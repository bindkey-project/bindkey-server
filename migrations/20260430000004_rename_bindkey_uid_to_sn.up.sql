-- Renommage cosmétique : `bindkey_uid` est en réalité le SN ATECC608
-- (Serial Number 9 bytes). Le firmware/app l'appelle `SN` partout dans le
-- protocole, on s'aligne côté serveur.
-- Les FK de volume_shares (source_sn, target_sn) sont automatiquement
-- mises à jour par PostgreSQL pour pointer vers la nouvelle colonne.
ALTER TABLE bindkeys RENAME COLUMN bindkey_uid TO sn;

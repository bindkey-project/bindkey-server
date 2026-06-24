-- Réactive le NOT NULL. À ne pas jouer si des lignes RESERVED (wrapped_blob IS NULL)
-- existent déjà — il faut d'abord les nettoyer ou les compléter.
ALTER TABLE volume_shares ALTER COLUMN wrapped_blob SET NOT NULL;

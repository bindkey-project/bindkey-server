-- On ajoute la colonne. 
-- NOTE : Si tu as déjà des données, enlève "NOT NULL" le temps de la migration ou mets une valeur par défaut.
ALTER TABLE volumes ADD COLUMN bindkey_id UUID NOT NULL REFERENCES bindkeys(id);

-- Optionnel : un index pour accélérer les recherches par clé
CREATE INDEX idx_volumes_bindkey_id ON volumes(bindkey_id);
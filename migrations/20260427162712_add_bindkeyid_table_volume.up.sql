DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='volumes' AND column_name='bindkey_id') THEN
        ALTER TABLE volumes ADD COLUMN bindkey_id UUID NOT NULL REFERENCES bindkeys(id);
    END IF;
END $$;

-- Pour l'index, on utilise IF NOT EXISTS (plus simple)
CREATE INDEX IF NOT EXISTS idx_volumes_bindkey_id ON volumes(bindkey_id);
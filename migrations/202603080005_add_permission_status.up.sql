-- migration add_permission_status (UP)
DO $$
BEGIN
    -- On vérifie si le type n'existe pas déjà avant de le créer
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'permission_status') THEN
        CREATE TYPE permission_status AS ENUM ('ACTIVE', 'REVOKED');
    END IF;
END
$$;
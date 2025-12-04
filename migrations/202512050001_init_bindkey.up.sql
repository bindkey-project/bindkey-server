-- enums
-- Roles utilisateurs
CREATE TYPE user_role AS ENUM ('USER', 'ENROLLER', 'ADMIN');

-- Statut utilisateur
CREATE TYPE user_status AS ENUM ('ACTIVE', 'DISABLED');

-- Statut BindKey
CREATE TYPE bindkey_status AS ENUM ('ACTIVE', 'RESET', 'LOST', 'BROKEN');

-- Permissions de volumes
CREATE TYPE permission_level AS ENUM ('READ', 'READ_WRITE');

-- table utilisateurs
CREATE TABLE users (
    id UUID PRIMARY KEY,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    job_title TEXT,
    email TEXT UNIQUE NOT NULL,
    role user_role NOT NULL DEFAULT 'USER',
    status user_status NOT NULL DEFAULT 'ACTIVE',
    recovery_code_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- table devices (machines utilisées par les utilisateurs)
CREATE TABLE devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    device_name TEXT NOT NULL,
    os TEXT,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- table bindkeys 
CREATE TABLE bindkeys (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bindkey_uid TEXT UNIQUE NOT NULL,
    fingerprint_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    status bindkey_status NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- table disks (les disques USB détectés)
CREATE TABLE disks (
    id UUID PRIMARY KEY,
    serial_number TEXT UNIQUE NOT NULL,
    capacity_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- table volume (les volumes chiffrés)
CREATE TABLE volumes (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    disk_id UUID NOT NULL REFERENCES disks(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    encrypted_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

--table volume_permissions (partage sécurisé des volumes)
CREATE TABLE volumes (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    disk_id UUID NOT NULL REFERENCES disks(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    encrypted_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- table bindkey_resets (rénitialisations des bindkeys)
CREATE TABLE bindkey_resets (
    id UUID PRIMARY KEY,
    bindkey_id UUID NOT NULL REFERENCES bindkeys(id) ON DELETE CASCADE,
    reset_type TEXT NOT NULL,
    performed_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- table session (gérer sessions d'accès, tokens, expiration et lien utilisateur + Bindkey)
CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bindkey_id UUID NOT NULL REFERENCES bindkeys(id) ON DELETE CASCADE,
    server_token TEXT NOT NULL,
    local_token TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    device_id UUID REFERENCES devices(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- table mounted_volumes (suivi des volumes montés par qui, sur quelle machine et pour combien de temps)
CREATE TABLE mounted_volumes (
    id UUID PRIMARY KEY,
    volume_id UUID NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    device_id UUID REFERENCES devices(id),
    mounted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    unmounted_at TIMESTAMPTZ,
    device_info TEXT
);

-- table audit_logs (trace toutes les actions critiques: montage, démontage, accès, reset, erreurs, etc)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    bindkey_id UUID REFERENCES bindkeys(id),
    action TEXT NOT NULL,
    details TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


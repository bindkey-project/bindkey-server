-- Table disks (les disques USB détectés)
CREATE TABLE disks (
    id UUID PRIMARY KEY,

    -- Numéro de série unique du disque (lu via USB)
    serial_number TEXT UNIQUE NOT NULL,

    -- Capacité totale du disque (en octets)
    capacity_bytes BIGINT NOT NULL,

    -- Un petit nom optionnel (ex: "SanDisk 32GB")
    label TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE disks (                                           
    -- Table pour représenter les disques physiques (ou logiques) dans le système

    id UUID PRIMARY KEY,                                       
    -- Identifiant unique du disque.

    serial_number TEXT UNIQUE NOT NULL,                        
    -- Numéro de série du disque (fourni par le hardware).
    -- UNIQUE pour ne pas avoir deux disques avec le même serial.

    capacity_bytes BIGINT NOT NULL,                            
    -- Capacité totale du disque en octets.
    -- BIGINT car on peut monter à des To facilement.

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()              
    -- Date de création de l’enregistrement du disque.
);

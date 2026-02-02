// src/api/models/disk.rs
// -----------------------------------------------------------------------------
// Disk (API/DB model)
//
// Représente un disque physique USB détecté par le système.
// Chaque Disk correspond à une ligne de la table SQL `disks`.
//
// Un disque est identifié de manière unique par son numéro de série.
// Les volumes sont créés "sur" un disque via la clé étrangère `disk_id`.
// -----------------------------------------------------------------------------

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Représentation d'un disque physique USB.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Disk {
    /// Identifiant unique (clé primaire).
    pub id: Uuid,

    /// Numéro de série unique du disque physique.
    ///
    /// Provient généralement de l'USB MSC / SCSI (ESP32, contrôleur USB, etc.).
    /// Champ UNIQUE en base de données.
    pub serial_number: String,

    /// Capacité totale du disque en octets.
    ///
    /// Exemple : 32 Go ≈ 32_000_000_000 bytes.
    /// BIGINT en SQL → i64 en Rust.
    pub capacity_bytes: i64,

    /// Label lisible optionnel du disque.
    ///
    /// Exemples :
    /// - "SanDisk Ultra 32GB"
    /// - "Kingston USB 3.0"
    ///
    /// Colonne TEXT nullable → Option<String>.
    pub label: Option<String>,

    /// Date de création en base de données.
    pub created_at: DateTime<Utc>,
}

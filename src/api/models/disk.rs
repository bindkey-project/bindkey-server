// ─────────────────────────────────────────────────────────────
// Struct Disk : représente un disque physique détecté
// ─────────────────────────────────────────────────────────────

use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Disk {
    pub id: Uuid,

    // Numéro de série unique du disque USB
    pub serial_number: String,

    // Capacité du disque (en octets)
    pub capacity_bytes: i64,

    pub created_at: DateTime<Utc>,
}

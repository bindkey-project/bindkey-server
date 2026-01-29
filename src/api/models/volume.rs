// ─────────────────────────────────────────────────────────────
// Struct Volume : représente un volume chiffré BindKey
// ─────────────────────────────────────────────────────────────

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Volume {
    pub id: Uuid,

    // bindkey_id
    pub bindkey_id: Option<Uuid>,

    // Propriétaire du volume
    pub owner_id: Uuid,

    // Disque physique sur lequel est stocké le volume
    pub disk_id: Uuid,

    // Nom du volume
    pub name: String,

    // Taille (en octets)
    pub size_bytes: i64,

    // Clé chiffrée du volume (chaîne Base64)
    pub encrypted_key: String,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

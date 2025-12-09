// ─────────────────────────────────────────────────────────────
// Struct Device : représente la table SQL "devices"
// ─────────────────────────────────────────────────────────────

use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Device {
    // Identifiant unique de l’appareil
    pub id: Uuid,

    // L’utilisateur auquel appartient cet appareil
    pub user_id: Uuid,

    // Nom de l’appareil (Ex : "Laptop-Marwa")
    pub device_name: String,

    // Système d’exploitation (Linux, Windows…)
    pub os: Option<String>,

    // Dernière fois où l'appareil a été utilisé
    pub last_seen: DateTime<Utc>,

    // Création de l’enregistrement
    pub created_at: DateTime<Utc>,
}

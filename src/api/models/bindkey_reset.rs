// ─────────────────────────────────────────────────────────────
// Struct BindkeyReset : audit des réinitialisations BindKey
// ─────────────────────────────────────────────────────────────

use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct BindkeyReset {
    pub id: Uuid,

    // BindKey concernée
    pub bindkey_id: Uuid,

    // Type de reset : perte, corruption, effacement
    pub reset_type: String,

    // Administrateur / utilisateur ayant effectué le reset
    pub performed_by: Uuid,

    pub created_at: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────
// Struct BindkeyReset : audit des réinitialisations BindKey
// ─────────────────────────────────────────────────────────────

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

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

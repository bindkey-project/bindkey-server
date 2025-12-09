// ─────────────────────────────────────────────────────────────
// Struct AuditLog : journalisation des actions critiques
// ─────────────────────────────────────────────────────────────

use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id: Uuid,

    // Action effectuée par un utilisateur (nullable)
    pub user_id: Option<Uuid>,

    // BindKey concernée si applicable
    pub bindkey_id: Option<Uuid>,

    // Type d’action : MOUNT, UNMOUNT, LOGIN, RESET, ERROR, etc.
    pub action: String,

    // Détails supplémentaires (IP, device, message…)
    pub details: Option<String>,

    // Niveau de sévérité (INFO, WARNING, CRITICAL…)
    pub severity: String,

    pub created_at: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────
// Struct Bindkey : représente une clé biométrique enregistrée
// ─────────────────────────────────────────────────────────────

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Bindkey {
    pub id: Uuid,

    // L’utilisateur auquel appartient la clé biométrique
    pub user_id: Uuid,

    // Identifiant unique interne du périphérique (USB/BIO)
    pub bindkey_uid: String,

    // Empreinte biométrique (hashée)
    pub fingerprint_template: String,

    // Clé publique pour déchiffrement et signature
    pub public_key: String,

    // Statut de la BindKey (ACTIVE, RESET, LOST, BROKEN)
    pub status: BindkeyStatus,

    pub created_at: DateTime<Utc>,
}

/// Enum SQL : bindkey_status
#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "bindkey_status", rename_all = "UPPERCASE")]
pub enum BindkeyStatus {
    ACTIVE,
    RESET,
    LOST,
    BROKEN,
}

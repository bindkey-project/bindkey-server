// ─────────────────────────────────────────────────────────────
// Struct Session : session d’accès sécurisée BindKey
// ─────────────────────────────────────────────────────────────

use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Session {
    pub id: Uuid,

    // L’utilisateur connecté
    pub user_id: Uuid,

    // Bindkey utilisée pour l’authentification
    pub bindkey_id: Uuid,

    pub server_token: Option<String>,
    pub local_token: Option<String>,

    // Expiration de la session
    pub expires_at: DateTime<Utc>,


    pub created_at: DateTime<Utc>,
    // Le challenge envoyé à la BindKey
    pub auth_challenge: Option<String>,
}

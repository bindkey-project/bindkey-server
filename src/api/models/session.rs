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

    // Token généré côté serveur (pour l’API)
    pub server_token: String,

    // Token généré côté client (clé locale)
    pub local_token: String,

    // Expiration de la session
    pub expires_at: DateTime<Utc>,


    pub created_at: DateTime<Utc>,
}

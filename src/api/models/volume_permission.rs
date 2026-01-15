// ─────────────────────────────────────────────────────────────
// Struct VolumePermission : partage sécurisé d’un volume
// ─────────────────────────────────────────────────────────────

use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct VolumePermission {
    pub id: Uuid,

    // Volume partagé
    pub volume_id: Uuid,

    // Utilisateur qui reçoit l’accès
    pub grantee_id: Uuid,

    // Niveau d’accès : READ | READ_WRITE
    pub permission: PermissionLevel,

    // Expiration du partage (nullable)
    pub expires_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,

    // Utilisateur qui a créé le partage
    pub created_by: Option<Uuid>,
}

/// ENUM SQL : permission_level
#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "permission_level", rename_all = "UPPERCASE")]
pub enum PermissionLevel {
    READ,
    ReadWrite,
}

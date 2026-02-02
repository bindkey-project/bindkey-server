// src/api/models/volume_permissions.rs
// -----------------------------------------------------------------------------
// VolumePermission (API/DB model)
//
// Représente une permission d'accès à un volume (partage).
// Un volume peut être partagé avec plusieurs utilisateurs.
//
// Cohérence SQL :
// - L'ENUM `permission_level` est généralement : 'READ', 'READ_WRITE'.
// - On utilise `rename_all = "UPPERCASE"` pour mapper proprement.
// -----------------------------------------------------------------------------

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Représente un partage / permission d'accès à un volume.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct VolumePermission {
    /// Identifiant unique (PK).
    pub id: Uuid,

    /// Volume partagé.
    pub volume_id: Uuid,

    /// Utilisateur qui reçoit l’accès (grantee).
    ///
    /// (Dans une ancienne version, ce champ pouvait s'appeler `user_id`.)
    pub grantee_id: Uuid,

    /// Niveau d’accès : READ | READ_WRITE
    pub permission: PermissionLevel,

    /// Expiration du partage (nullable).
    /// - None => partage permanent
    /// - Some(ts) => accès limité dans le temps
    pub expires_at: Option<DateTime<Utc>>,

    /// Date de création du partage.
    pub created_at: DateTime<Utc>,

    /// Utilisateur qui a créé le partage.
    ///
    /// Optionnel si tu autorises des partages "système" (ou migrations).
    pub created_by: Option<Uuid>,
}

/// ENUM SQL : permission_level
///
/// Exemple SQL :
///   CREATE TYPE permission_level AS ENUM ('READ', 'READ_WRITE');
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "permission_level", rename_all = "UPPERCASE")]
pub enum PermissionLevel {
    READ,
    ReadWrite,
}

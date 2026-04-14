// src/api/models/mounted_volume.rs
// -----------------------------------------------------------------------------
// MountedVolume (API/DB model)
//
// Représente un événement de montage d’un volume chiffré BindKey.
//
// Cette table est CRITIQUE pour :
// - la traçabilité (qui a monté quoi, quand)
// - l’audit sécurité
// - la gestion des sessions
// - la détection d’abus ou d’accès non autorisés
//
// Il s’agit d’un journal d’état, pas d’une simple table technique.
// -----------------------------------------------------------------------------

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Représente un volume actuellement (ou anciennement) monté.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MountedVolume {
    /// Identifiant unique du montage (clé primaire).
    pub id: Uuid,

    /// Utilisateur ayant monté le volume.
    pub user_id: Uuid,

    /// Volume chiffré concerné par le montage.
    pub volume_id: Uuid,

    /// Date et heure du montage effectif.
    ///
    /// Généralement remplie automatiquement à l’insertion.
    pub mounted_at: DateTime<Utc>,

    /// Date d’expiration du montage.
    ///
    /// - None → montage valide sans limite temporelle
    /// - Some(ts) → accès automatiquement limité dans le temps
    pub expires_at: Option<DateTime<Utc>>,

    /// Date de démontage réel.
    ///
    /// - None → volume actuellement monté
    /// - Some(ts) → volume démonté à ce moment-là
    pub unmounted_at: Option<DateTime<Utc>>,
}

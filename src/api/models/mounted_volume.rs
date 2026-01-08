// Permet de sérialiser / désérialiser la structure en JSON
// (réponses API, logs, éventuels échanges client-serveur)
use serde::{Serialize, Deserialize};

// Permet à SQLx de mapper automatiquement une ligne PostgreSQL
// vers la struct Rust MountedVolume
use sqlx::FromRow;

// UUID pour identifier de manière unique chaque événement de montage
use uuid::Uuid;

// Types DateTime avec gestion du fuseau horaire (UTC)
// Correspond à TIMESTAMPTZ côté PostgreSQL
use chrono::{DateTime, Utc};

//
// ─────────────────────────────────────────────────────────────
// STRUCT MountedVolume
// Représente un événement de montage d’un volume chiffré BindKey
// ─────────────────────────────────────────────────────────────
//
// Cette table est critique pour :
// - la traçabilité (qui a monté quoi, quand)
// - l’audit sécurité
// - la détection d’abus ou d’accès non autorisés
//

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct MountedVolume {
    /// Identifiant unique du montage
    /// (clé primaire de la table mounted_volumes)
    pub id: Uuid,

    /// Volume chiffré concerné par le montage
    pub volume_id: Uuid,

    /// Utilisateur ayant monté le volume
    pub user_id: Uuid,

    /// Date et heure du montage effectif
    /// (rempli automatiquement à l’insertion)
    pub mounted_at: DateTime<Utc>,

    /// Date d’expiration du montage
    /// - None = montage valide sans limite temporelle
    /// - Some(...) = accès automatiquement limité dans le temps
    pub expires_at: Option<DateTime<Utc>>,

    /// Date de démontage
    /// - None = volume actuellement monté
    /// - Some(...) = volume déjà démonté
    pub unmounted_at: Option<DateTime<Utc>>,
}

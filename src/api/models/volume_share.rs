// src/api/models/volume_share.rs
// -----------------------------------------------------------------------------
// VolumeShare (API/DB model)
//
// Représente un partage de volume entre deux BindKeys (source → target).
//
// Le serveur stocke un `wrapped_blob` opaque (60 bytes) chiffré par la BK source
// pour la BK cible via ECDH. Les clés privées vivent dans les SE ATECC608 :
// le serveur ne peut JAMAIS déchiffrer ce blob, c'est attendu par design.
//
// Identités : source_sn / target_sn correspondent à `bindkeys.sn`
// (SN ATECC608, 9 bytes), pas à `bindkeys.id`. C'est le SN qui est utilisé
// partout dans le protocole firmware.
// -----------------------------------------------------------------------------

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Représentation d'un partage de volume persisté.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct VolumeShare {
    /// Identifiant unique du partage (PK serveur).
    pub id: Uuid,

    /// SN de la BindKey propriétaire qui partage.
    pub source_sn: String,

    /// SN de la BindKey qui reçoit le partage.
    pub target_sn: String,

    /// Volume partagé (UUID = 16 bytes, aligné avec le volume_id firmware).
    pub volume_id: Uuid,

    /// Slot ATECC608 [10..14] où la clé sera stockée sur la BK cible.
    /// SMALLINT côté SQL → i16 côté Rust.
    pub target_slot: i16,

    /// Bundle chiffré opaque (nonce || ciphertext || tag), 60 bytes exactement.
    pub wrapped_blob: Vec<u8>,

    /// Statut de livraison.
    pub status: VolumeShareStatus,

    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

/// Enum SQL : `volume_share_status`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq, Eq)]
#[sqlx(type_name = "volume_share_status", rename_all = "UPPERCASE")]
pub enum VolumeShareStatus {
    PENDING,
    DELIVERED,
}

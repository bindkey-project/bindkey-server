// src/api/models/volume.rs
// -----------------------------------------------------------------------------
// Volume (API/DB model)
//
// Représente un volume chiffré BindKey appartenant à un utilisateur.
//
// Un volume :
// - appartient à un utilisateur (owner_id)
// - est stocké sur un disque physique (disk_id)
// - possède une clé symétrique chiffrée (encrypted_key)
// - a une taille fixe en octets (size_bytes)
//
// Les BindKeys ne stockent JAMAIS la clé brute.
// Elles servent uniquement à autoriser le déchiffrement via un protocole
// cryptographique sécurisé côté serveur.
// -----------------------------------------------------------------------------

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Représentation d’un volume chiffré.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Volume {
    /// Identifiant unique du volume (PK).
    pub id: Uuid,

    /// Utilisateur propriétaire du volume.
    ///
    /// Si l'utilisateur est supprimé, les volumes associés doivent l'être aussi
    /// (ON DELETE CASCADE en DB).
    pub owner_id: Uuid,
    pub bindkey_id: Uuid, // <-- Ajout ici
    /// Identifiant logique exposé au firmware (ex : "bindkey-vol-0001").
    pub label: String,
    /// Nom lisible du volume (ex : "Travail", "Photos", "Secret").
    pub name: String,

    /// Taille du volume en octets.
    ///
    /// Exemple : 1 Go = 1_073_741_824 bytes.
    pub size_bytes: i64,

    /// Date de création.
    pub created_at: DateTime<Utc>,

    /// Date de dernière mise à jour.
    pub updated_at: DateTime<Utc>,
}

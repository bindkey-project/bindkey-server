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

    /// BindKey associée au volume (si applicable).
    ///
    /// - Some(bindkey_id) : volume lié à une BindKey spécifique
    /// - None : volume non lié ou lien historique supprimé
    pub bindkey_id: Option<Uuid>,

    /// Utilisateur propriétaire du volume.
    ///
    /// Si l'utilisateur est supprimé, les volumes associés doivent l'être aussi
    /// (ON DELETE CASCADE en DB).
    pub owner_id: Uuid,

    /// Disque physique sur lequel le volume est stocké.
    ///
    /// Si le disque est supprimé, les volumes associés disparaissent également.
    pub disk_id: Uuid,

    /// Nom lisible du volume (ex : "Travail", "Photos", "Secret").
    pub name: String,

    /// Taille du volume en octets.
    ///
    /// Exemple : 1 Go = 1_073_741_824 bytes.
    pub size_bytes: i64,

    /// Clé symétrique du volume, CHIFFRÉE.
    ///
    /// ⚠️ IMPORTANT :
    /// - Ne contient JAMAIS la clé brute.
    /// - Stockée chiffrée avec la clé publique BindKey ou une clé maître serveur.
    /// - La clé déchiffrée n’est renvoyée qu’après validation cryptographique.
    pub encrypted_key: String,

    /// Date de création.
    pub created_at: DateTime<Utc>,

    /// Date de dernière mise à jour.
    pub updated_at: DateTime<Utc>,
}

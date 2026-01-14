use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};


/// Représente un volume chiffré appartenant à un utilisateur.
///
/// Un volume :
///   - appartient à un utilisateur (owner_id)
///   - est stocké sur un disque physique (disk_id)
///   - possède une clé symétrique chiffrée (encrypted_key)
///   - a une taille fixe en bytes (size_bytes)
///
/// Les BindKeys ne stockent **jamais** la clé brute.
/// Elles servent seulement à déverrouiller ce volume via un protocole sécurisé
/// côté serveur.

#[derive(Debug,Serialize,Deserialize,FromRow)]

pub struct Volume {

    pub id: Uuid,

    // L'utilisateur propriétaire du volume.
    /// Le volume sera supprimé automatiquement si ce user est supprimé.
    pub owner_id: Uuid,

    /// Le disque physique sur lequel le volume se trouve.
    /// Si le disque est supprimé, les volumes associés disparaissent aussi (CASCADE).
    pub disk_id: Uuid,

    /// Nom choisi par l'utilisateur (ex : "Travail", "Photos", "Secret").
    pub name: String,

    /// Taille du volume en octets (ex : 1073741824 = 1GB).
    pub size_bytes: i64,

    /// Clé symétrique du volume CHIFFRÉE (jamais en clair).
    ///
    /// ⚠️ IMPORTANT :
    ///    - Ce champ NE CONTIENT PAS la clé brute.
    ///    - Il contient une version chiffrée (avec la clé publique de la BindKey
    ///      ou une clé maître serveur).
    ///    - Le serveur renverra la version déchiffrée uniquement après un challenge
    ///      cryptographique validé par la BindKey.
    
    pub encrypted_key: String,
    
    pub created_at: DateTime<Utc>,

    pub updated_at: DateTime<Utc>,
}


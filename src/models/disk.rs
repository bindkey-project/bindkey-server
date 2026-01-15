use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};


/// Représente un disque physique USB détecté par le système.
/// 
/// Chaque ligne correspond à un disque réel branché à un ordinateur.
/// Les volumes sont obligatoirement créés "sur" un disque (via disk_id).
///
/// Correspond exactement à la table SQL `disks`.

#[derive(Debug,Serialize,Deserialize,FromRow)]

pub struct Disk{

    pub id: Uuid,

    /// Numéro de série du disque physique.
    /// Il vient de l'USB MSC / SCSI via ton ESP32.
    /// C'est un champ UNIQUE en base.
    pub serial_number: String,

    /// Capacité totale du disque en octets (ex : 32000000000 bytes pour un 32GB).
    ///
    /// BIGINT en SQL → i64 en Rust
    
    pub capacity_bytes: i64,

    /// Un label optionnel que tu pourras afficher dans le soft.
    /// Exemples :
    ///   "SanDisk Ultra 32GB"
    ///   "Kingston USB 3.0"
    ///
    /// TEXT nullable → Option<String> en Rust
    
    pub label: Option<String>,

    /// Horodatage de création en BDD.
    
    pub created_at: DateTime<Utc>,
}
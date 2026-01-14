use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};


/// Représente un volume actuellement (ou anciennement) monté.
///
/// Cette table sert de **journal d'état** :
/// - qui a monté quoi
/// - quand
/// - avec quelle session
/// - sur quelle machine
///
/// ⚠️ Ce n’est PAS une simple table technique :
/// elle est essentielle pour la sécurité, l’audit et la cohérence du système.


#[derive(Debug,Serialize,Deserialize,FromRow)]

pub struct MountedVolume{
 
pub id: Uuid,

///Qui à monter le volume 
pub user_id: Uuid,

///Avec quel session 
pub session_id: Uuid,


/// Volume qui a été monté.
pub volume_id: UUid,

/// Date et heure du montage.
pub mounted_at: DateTime<Utc>,

 /// Date d'expiration du montage.
    ///
    /// Exemple :
    /// - montage valide 30 minutes
    /// - démontage automatique après
pub expires_at: Option<DateTime<Utc>>,


/// Date de démontage réel.
    ///
    /// - None → volume encore monté
    /// - Some(ts) → volume démonté à ce moment-là
    pub unmounted_at: Option<DateTime<Utc>>,





}
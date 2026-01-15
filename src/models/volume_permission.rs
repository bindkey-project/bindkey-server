use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};


/// Représente une permission d'accès à un volume.
///
/// Un volume peut être partagé avec plusieurs utilisateurs.
/// Exemple :
///
///   - Alice crée un volume "Travail"
///   - Alice partage ce volume avec Bob en lecture seule
///   - Alice partage ce volume avec Claire en lecture/écriture
///
/// Chaque partage correspond à UNE ligne dans volume_permissions.

#[derive(Debug,Serialize,Deserialize,FromRow)]

pub struct volume_permission{

pub id: Uuid,

/// Volume auquel on donne accès.
pub volume_id: Uuid,

/// User à qui on donne l'accès 
pub user_id: Uuid,

/// Permission : READ ou READ_WRITE
pub permission: PermissionLevel,


/// Optionnel : expiration du partage
    ///
    /// Exemple :
    ///   - autoriser l'accès pour 12h
    ///   - ou accès permanent si None

pub expires_at: Option<DateTime<Utc>>,

pub created_at: DateTime<Utc>,

}

/// Enum correspondant à l'ENUM SQL:
///
///   CREATE TYPE permission_level AS ENUM ('READ', 'READ_WRITE');
///
/// SQLx::Type permet le mapping automatique :
///
///   Rust                        SQL
///   PermissionLevel::READ     → 'READ'
///   PermissionLevel::READ_WRITE → 'READ_WRITE'
#[derive(sqlx::Type, Serialize, Deserialize, Debug, Clone)]
#[sqlx(type_name = "permission_level", rename_all = "UPPERCASE")]

pub enum PermissionLevel{
    READ,
    READ_WRITE
}
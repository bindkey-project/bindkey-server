use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};


/// Représentation Rust de la table SQL `bindkeys`.
///
/// Cette struct correspond exactement 1:1 aux colonnes SQL :
///
///   - id : UUID
///   - user_id : UUID nullable → Option<Uuid>
///   - bindkey_uid : identifiant unique hardware de la BindKey
///   - fingerprint_hash : empreinte biométrique hashée
///   - public_key : clé publique associée à la BindKey
///   - status : ACTIVE | RESET | LOST | BROKEN
///   - created_at : DateTime<Utc>
///
/// SQLx utilisera automatiquement cette struct pour lire ou écrire des lignes
/// de la table `bindkeys`.

#[derive(Debug,Serialize,Deserialize,FromRow)]

pub struct BindKey{

/// Identifiant unique de la BindKey (clé primaire).   
pub id: Uuid,

pub user_id: Option<Uuid>,

/// L'identifiant unique hardware de la BindKey.
/// Exemple : UID généré par l'ESP32 ou par un secure element.
pub bindkey_uid: String,

pub fingerprint_template: String,

/// Clé publique de la BindKey, utilisée pour vérifier une signature
/// dans le mécanisme challenge/response.
pub public_key: String,

/// Statut de la BindKey : ACTIVE | RESET | LOST | BROKEN
/// Mappé sur l'ENUM SQL `bindkey_status`.
pub status: BindKeyStatus,

pub created_at: DateTime<Utc>,
}

/// Enum Rust représentant l'ENUM SQL `bindkey_status`.
///
/// SQLx::Type permet de convertir automatiquement :
///
///   Rust                   SQL
///   ------------------     --------------------
///   BindKeyStatus::ACTIVE → 'ACTIVE'
///   BindKeyStatus::RESET  → 'RESET'
///   BindKeyStatus::LOST   → 'LOST'
///   BindKeyStatus::BROKEN → 'BROKEN'
///
/// rename_all = "UPPERCASE" assure que les variantes Rust (ACTIVE, RESET...)
/// correspondent exactement aux valeurs SQL.
#[derive(sqlx::Type, Serialize, Deserialize, Debug, Clone)]
#[sqlx(type_name = "bindkey_status", rename_all = "UPPERCASE")]

pub enum BindKeyStatus{
    ACTIVE,
    RESET,
    LOST,
    BROKEN,
}




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

// src/api/models/bindkey.rs
// -----------------------------------------------------------------------------
// Bindkey (API/DB model)
//
// Ce module contient la représentation Rust de la table SQL `bindkeys`.
// Elle est utilisée par SQLx (FromRow) et peut être sérialisée en JSON (serde).
//
// Choix de nommage :
// - Bindkey / BindkeyStatus sont conservés pour rester cohérents avec
//   les handlers et le reste du projet.
// - user_id : Option<Uuid> car la colonne peut être NULL en base.
// -----------------------------------------------------------------------------

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Représentation d'une Bindkey enregistrée.
///
/// Correspond à une ligne de la table SQL `bindkeys`.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Bindkey {
    /// Identifiant unique (clé primaire).
    pub id: Uuid,

    /// Propriétaire de la Bindkey.
    ///
    /// Option<Uuid> si la colonne SQL `user_id` est nullable.
    pub user_id: Option<Uuid>,

    /// Identifiant unique interne du périphérique (USB/BIO).
    pub bindkey_uid: String,

    /// Clé publique associée (signature / chiffrement).
    pub public_key: String,

    /// Statut de la Bindkey (ENUM SQL `bindkey_status`).
    pub status: BindkeyStatus,

    /// Date de création.
    pub created_at: DateTime<Utc>,

    /// Certificat X.509 PEM signé par la Root CA.
    /// Généré lors de l'enrôlement. None si la BindKey a été créée avant cette feature.
    pub certificate: Option<String>,
}

/// Enum SQL : `bindkey_status`
///
/// `rename_all = "UPPERCASE"` aligne les variantes avec les valeurs en base
/// (ACTIVE, RESET, LOST, BROKEN).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "bindkey_status", rename_all = "UPPERCASE")]
pub enum BindkeyStatus {
    ACTIVE,
    RESET,
    LOST,
    BROKEN,
}

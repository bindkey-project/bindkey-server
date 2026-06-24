// src/api/models/user.rs
// -----------------------------------------------------------------------------
// User (API/DB model)
//
// Représente un utilisateur dans le système BindKey.
// Ce modèle est utilisé :
// - par SQLx (FromRow) pour mapper les lignes de la table `users`
// - par serde (Serialize/Deserialize) pour les réponses / requêtes API
//
// IMPORTANT :
// - Ce fichier a été nettoyé pour supprimer les doublons (imports + enums + struct).
// - Certains champs sont en Option<> pour rester compatibles si la DB diffère
//   selon tes migrations (ex: password_hash vs recovery_code_hash).
// -----------------------------------------------------------------------------

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Correspond à une ligne de la table `users`.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    /// Identifiant unique (UUID).
    pub id: Uuid,

    /// Prénom / Nom.
    pub first_name: String,
    pub last_name: String,

    /// Poste / intitulé (nullable).
    pub job_title: Option<String>,

    /// Email (souvent UNIQUE + NOT NULL).
    ///
    /// Si ta colonne SQL autorise NULL, change en `Option<String>`.
    pub email: String,

    /// Rôle utilisateur (ENUM SQL `user_role`).
    pub role: UserRole,

    /// Statut utilisateur (ENUM SQL `user_status`).
    pub status: UserStatus,

    /// Hash du mot de passe (si ton schéma utilise un mot de passe).
    ///
    /// Optionnel pour compatibilité si tu n’as pas cette colonne partout.
    pub password_hash: Option<String>,

    /// Hash d’un code de récupération (si ton schéma utilise recovery codes).
    ///
    /// Optionnel pour compatibilité si la colonne n’existe pas partout.
    pub recovery_code_hash: Option<String>,

    /// Dates (TIMESTAMPTZ).
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ENUM SQL : `user_role`
#[derive(sqlx::Type, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[sqlx(type_name = "user_role", rename_all = "UPPERCASE")]
pub enum UserRole {
    USER,
    ENROLLER,
    ADMIN,
}

/// ENUM SQL : `user_status`
#[derive(sqlx::Type, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[sqlx(type_name = "user_status", rename_all = "UPPERCASE")]
pub enum UserStatus {
    ACTIVE,
    DISABLED,
}

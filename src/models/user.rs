//Importation des traits Serialize et Deserialize.
// Ces deux traits permettent de convertir notre struct User
// vers du JSON (Serialize) et depuis du JSON (Deserialize).

use serde::{Serialize, Deserialize};

// FromRow est un trait indispensable pour utiliser SQLx.
// Il permet à SQLx de remplir automatiquement notre struct User
// avec les colonnes retournées par une requête SQL.

use sqlx::FromRow;

// UUID est utilisé pour représenter les identifiants en base.
// PostgreSQL stocke les UUID sous forme "uuid" -> Rust utilise uuid::Uuid.

use uuid::Uuid;

// DateTime<Utc> sert à représenter les TIMESTAMPTZ de PostgreSQL.
// Chaque fois que SQL retourne un TIMESTAMPTZ, SQLx le convertit en DateTime<Utc>.

use chrono::{DateTime, Utc};

/// Struct représentant une ligne de la table `users`.
///
/// Cette struct correspond 1:1 à ta table SQL :
///
///     CREATE TABLE users (
///         id UUID PRIMARY KEY,
///         first_name TEXT NOT NULL,
///         last_name TEXT NOT NULL,
///         email TEXT UNIQUE,
///         role user_role NOT NULL DEFAULT 'USER',
///         status user_status NOT NULL DEFAULT 'ACTIVE',
///         created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
///         updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
///     );
///
/// Chaque champ Rust correspond exactement à une colonne SQL.
/// SQLx remplira automatiquement la struct via le derive `FromRow`.


#[derive(Debug, Serialize, Deserialize, FromRow)]

pub struct User {
    /// Identifiant unique (UUID) de l'utilisateur.
    /// Correspond à la colonne SQL : id UUID PRIMARY KEY
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    /// Email - peut être NULL (dans ta table email n'est pas NOT NULL)
    /// Donc Rust utilise Option<String>
    ///
    /// - Some("hello@x.com") si email présent
    /// - None si NULL en base
    pub email: Option<String>,
    /// Rôle de l'utilisateur :
    /// USER | ENROLLER | ADMIN
    /// Ce champ utilise l'ENUM SQL : user_role
    pub role: UserRole,
    pub status: UserStatus,
    /// Date de création - TIMESTAMPTZ -> DateTime<Utc>
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub password_hash: String,
}



/// Enum représentant le type SQL : CREATE TYPE user_role AS ENUM (...);
///
/// SQLx::Type permet de mapper AUTOMATIQUEMENT les valeurs entre SQL et Rust.
/// rename_all = "UPPERCASE" signifie que l'on mappe :
///
/// - UserRole::USER -> "USER" en SQL
/// - UserRole::ENROLLER -> "ENROLLER"
/// - UserRole::ADMIN -> "ADMIN"
///
#[derive(sqlx::Type, Serialize, Deserialize, Debug, Clone)]
#[sqlx(type_name = "user_role", rename_all = "UPPERCASE")]
pub enum UserRole {
    USER,
    ENROLLER,
    ADMIN,
}


/// Pareil pour le statut utilisateur.
///
/// SQL : CREATE TYPE user_status AS ENUM ('ACTIVE','DISABLED');
///
#[derive(sqlx::Type, Serialize, Deserialize, Debug, Clone)]
#[sqlx(type_name = "user_status", rename_all = "UPPERCASE")]
pub enum UserStatus {
    ACTIVE,
    DISABLED,
}
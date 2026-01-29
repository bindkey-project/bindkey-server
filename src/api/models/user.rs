// ─────────────────────────────────────────────────────────────
// Imports des bibliothèques nécessaires
// ─────────────────────────────────────────────────────────────

// Permet de transformer les structs en JSON (Serialize)
// et d'accepter des données JSON en entrée API (Deserialize).
use serde::{Deserialize, Serialize};

// Permet à SQLx de convertir automatiquement une ligne SQL
// en instance de la struct (User, Device, etc.).
use sqlx::FromRow;

// UUID = identifiant unique universel pour les users, devices, etc.
use uuid::Uuid;

// DateTime<Utc> = type utilisé pour les timestamps PostgreSQL (TIMESTAMPTZ)
use chrono::{DateTime, Utc};

// ─────────────────────────────────────────────────────────────
// STRUCT User : correspond exactement à la table PostgreSQL "users"
// ─────────────────────────────────────────────────────────────

// #[derive(...)] génère automatiquement des traits utiles:
//
// - Debug : affiche le contenu d'un User dans les logs (pratique pour debug)
// - Serialize : convertit User → JSON (réponse API)
// - Deserialize : convertit JSON → User (entrées API)
// - FromRow : dit à SQLx comment mapper une ligne SQL → struct User
//
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    // UUID généré côté Rust ou PostgreSQL
    pub id: Uuid,

    // TEXT NOT NULL dans PostgreSQL → String en Rust
    pub first_name: String,
    pub last_name: String,

    // Option<String> ↔ champ nullable dans PostgreSQL (job_title peut être NULL)
    pub job_title: Option<String>,

    // UNIQUE NOT NULL
    pub email: String,

    // ENUM SQL user_role → enum Rust UserRole
    pub role: UserRole,

    // ENUM SQL user_status → enum Rust UserStatus
    pub status: UserStatus,

    // Hash du code de récupération (jamais stocker le vrai code !)
    pub recovery_code_hash: String,

    // TIMESTAMPTZ dans PostgreSQL ↔ DateTime<Utc> en Rust
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(sqlx::Type, serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[sqlx(type_name = "user_role", rename_all = "UPPERCASE")]
pub enum UserRole {
    USER,
    ENROLLER,
    ADMIN,
}

#[derive(sqlx::Type, serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[sqlx(type_name = "user_status", rename_all = "UPPERCASE")]
pub enum UserStatus {
    ACTIVE,
    DISABLED,
}

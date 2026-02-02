// src/api/models/session.rs
// -----------------------------------------------------------------------------
// Session (API/DB model)
//
// Représente une session d'accès créée après une authentification BindKey.
//
// Cohérence avec la table SQL `sessions` fournie :
// - server_token : TEXT NOT NULL UNIQUE  -> String
// - local_token  : TEXT NOT NULL UNIQUE  -> String
// - expires_at   : TIMESTAMPTZ NOT NULL  -> DateTime<Utc>
// - created_at   : TIMESTAMPTZ NOT NULL DEFAULT now() -> DateTime<Utc>
//
// Note sur `auth_challenge` :
// - présent dans ton ancien modèle API
// - si tu veux que SQLx::FromRow le remplisse depuis la DB,
//   il faut que la colonne existe dans la table `sessions`.
//   Sinon, enlève ce champ OU crée une struct DTO séparée.
// -----------------------------------------------------------------------------

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Représente une session d'accès sécurisée BindKey.
///
/// Tant que la session n'est pas expirée, le client peut faire des actions
/// non sensibles via le server_token.
/// Pour une action sensible (ex: monter un volume), le serveur peut exiger
/// une preuve cryptographique (challenge + signature BindKey).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Session {
    /// Identifiant unique de la session (PK).
    pub id: Uuid,

    /// Utilisateur connecté.
    pub user_id: Uuid,

    /// BindKey utilisée pour créer la session.
    pub bindkey_id: Uuid,

    /// Jeton côté serveur (stocké en DB).
    /// Utilisé pour identifier rapidement la session (ex: Authorization header).
    ///
    /// IMPORTANT : ne doit pas suffire seul pour une action sensible.
    pub server_token: String,

    /// Jeton côté client (stocké en DB).
    /// Permet de lier la session à un client/appareil.
    pub local_token: String,

    /// Date d'expiration de la session.
    /// Quand expires_at < now(), il faut refaire l'authentification.
    pub expires_at: DateTime<Utc>,

    /// Date de création (DEFAULT now()).
    pub created_at: DateTime<Utc>,

    /// Challenge (optionnel) utilisé lors d'étapes d'authentification fortes.
    ///
    /// ⚠️ Ce champ doit exister en DB si tu SELECT * et que tu relies via FromRow.
    /// Sinon, enlève-le ou gère-le dans une struct DTO séparée.
    pub auth_challenge: Option<String>,
}

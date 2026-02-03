// src/api/audit.rs
//
// Helper centralisé pour écrire dans la table audit_logs.
// Objectif :
// - Avoir UN SEUL point d’écriture des logs en base
// - Éviter de répéter du SQL dans tous les handlers
// - Faciliter le debug si un audit ne s’écrit pas

use crate::db::AppState; // Accès à la connexion PostgreSQL (pool SQLx)
use chrono::Utc;         // Gestion de la date/heure UTC
use uuid::Uuid;          // UUID pour l'identifiant du log

// ─────────────────────────────────────────────────────────────
// Niveau de sévérité du log d’audit
// ─────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub enum AuditSeverity {
    INFO,     // Action normale (login, create, mount, etc.)
    WARNING,  // Action sensible / anormale (forbidden, revoke, reset)
    ERROR,    // Erreur critique / échec système
}

// Conversion du enum vers une string stockée en base
impl AuditSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditSeverity::INFO => "INFO",
            AuditSeverity::WARNING => "WARNING",
            AuditSeverity::ERROR => "ERROR",
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Fonction principale : écriture d’un audit log en base
// ─────────────────────────────────────────────────────────────
/// Écrit un log dans la table audit_logs.
///
/// Paramètres :
/// - state       : état global de l’application (contient la DB)
/// - user_id     : utilisateur à l’origine de l’action (optionnel)
/// - bindkey_id  : bindkey concernée (optionnel)
/// - action      : nom court et explicite ("LOGIN", "MOUNT", ...)
/// - details     : détails lisibles (contexte, IDs, erreurs…)
/// - severity    : niveau de gravité (INFO / WARNING / ERROR)
///
/// Retour :
/// - Ok(()) si l’insertion a réussi
/// - Err(sqlx::Error) si l’insertion a échoué
pub async fn write_audit_log(
    state: &AppState,
    user_id: Option<Uuid>,
    bindkey_id: Option<Uuid>,
    action: &str,
    details: Option<String>,
    severity: AuditSeverity,
) -> Result<(), sqlx::Error> {

    // Génération d’un identifiant unique pour le log
    let id = Uuid::new_v4();

    // Date/heure UTC du log
    let now = Utc::now();

    // ─────────────────────────────────────────
    // Log local (stdout/stderr) pour debug
    // Utile pour vérifier que la fonction est bien appelée
    // ─────────────────────────────────────────
    eprintln!(
        "🚀 AUDIT ATTEMPT: action={} severity={} user_id={:?} bindkey_id={:?} details={:?}",
        action,
        severity.as_str(),
        user_id,
        bindkey_id,
        details
    );

    // ─────────────────────────────────────────
    // Insertion du log dans la base PostgreSQL
    // ─────────────────────────────────────────
    let res = sqlx::query(
        r#"
        INSERT INTO audit_logs (
            id,
            user_id,
            bindkey_id,
            action,
            details,
            severity,
            created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(id)                     // UUID du log
    .bind(user_id)                // user_id (nullable)
    .bind(bindkey_id)             // bindkey_id (nullable)
    .bind(action)                 // type d’action
    .bind(details)                // détails texte
    .bind(severity.as_str())      // niveau de sévérité
    .bind(now)                    // timestamp UTC
    .execute(&state.db)
    .await;

    // ─────────────────────────────────────────
    // Si l’insertion échoue :
    // - on affiche l’erreur SQL
    // - sinon elle serait silencieuse
    // ─────────────────────────────────────────
    if let Err(ref e) = res {
        eprintln!("❌ AUDIT INSERT FAILED: {e}");
    }

    // On retourne le résultat original
    // Ok(()) si succès, Err(sqlx::Error) sinon
    res.map(|_| ())
}

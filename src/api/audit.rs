// src/api/audit.rs
//
// Helper centralisé pour écrire dans la table audit_logs
// Objectif : éviter de répéter du SQL partout dans les handlers.

use crate::db::AppState;
use chrono::Utc;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub enum AuditSeverity {
    INFO,
    WARNING,
    ERROR,
}

impl AuditSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditSeverity::INFO => "INFO",
            AuditSeverity::WARNING => "WARNING",
            AuditSeverity::ERROR => "ERROR",
        }
    }
}

/// Écrit un log dans audit_logs.
/// - user_id / bindkey_id sont optionnels
/// - details est optionnel
/// - action : string courte ("LOGIN", "MOUNT", ...)
pub async fn write_audit_log(
    state: &AppState,
    user_id: Option<Uuid>,
    bindkey_id: Option<Uuid>,
    action: &str,
    details: Option<String>,
    severity: AuditSeverity,
) {
    let now = Utc::now();
    let id = Uuid::new_v4();

    // On prépare la requête
    let query_result = sqlx::query(
        r#"
        INSERT INTO audit_logs (id, user_id, bindkey_id, action, details, severity, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(bindkey_id)
    .bind(action)
    .bind(details)
    .bind(severity.as_str())
    .bind(now)
    .execute(&state.db)
    .await;

    // --- LE MATCH MAGIQUE ---
    match query_result {
        Ok(_) => {
            println!("✅ Audit inséré : {} pour l'utilisateur {:?}", action, user_id);
        }
        Err(e) => {
            // Ici on logue l'erreur spécifiquement sans faire crash l'API
            eprintln!("❌ ÉCHEC AUDIT [{}]:", action);
            
            match e {
                sqlx::Error::Database(db_err) => {
                    eprintln!("   -> Erreur DB : {}", db_err.message());
                    if let Some(code) = db_err.code() {
                        eprintln!("   -> Code SQL : {}", code); // Ex: 23505 pour violation d'unicité
                    }
                }
                sqlx::Error::PoolTimedOut => {
                    eprintln!("   -> Timeout : La base de données est trop lente ou saturée.");
                }
                _ => {
                    eprintln!("   -> Autre erreur SQLx : {:?}", e);
                }
            }
        }
    }
}

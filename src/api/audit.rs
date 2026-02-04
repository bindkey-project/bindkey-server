// src/api/audit.rs
//
// Helper centralisé pour écrire dans la table audit_logs
// Objectif : éviter de répéter du SQL partout dans les handlers.
 
use crate::db::AppState;
use chrono::Utc;
use uuid::Uuid;
use tracing::{info, error, debug};
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
    debug!("⏳ Tentative d'audit: action={} pour user={:?}", action, user_id);
 
    let query_result = sqlx::query(
        r#"
        INSERT INTO audit_logs (id, user_id, bindkey_id, action, details, severity, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(bindkey_id)
    .bind(action)
    .bind(details)
    .bind(severity.as_str())
    .bind(Utc::now())
    .execute(&state.db)
    .await;
 
    match query_result {
        Ok(_) => {
            info!("✅ Audit inséré : {} pour l'utilisateur {:?}", action, user_id);
        }
        Err(e) => {
            error!("❌ ÉCHEC AUDIT [{}]:", action);
            match e {
                sqlx::Error::Database(db_err) => {
                    error!("   -> Erreur DB : {}", db_err.message());
                    if let Some(code) = db_err.code() {
                        error!("   -> Code SQL : {}", code);
                    }
                }
                sqlx::Error::PoolTimedOut => {
                    error!("   -> Timeout : La base de données est trop lente ou saturée.");
                }
                _ => {
                    error!("   -> Autre erreur SQLx : {:?}", e);
                }
            }
        }
    }
}
 
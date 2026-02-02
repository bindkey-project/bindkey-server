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
) -> Result<(), sqlx::Error> {
    eprintln!("🚀 AUDIT ATTEMPT: action={}, user={:?}", action, user_id);
    let id = Uuid::new_v4();

    let now = Utc::now();

    sqlx::query(
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
    .await?;

    Ok(())
}

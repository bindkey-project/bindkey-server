// src/api/handlers/permission_handler.rs
//
// Endpoints :
//   - POST   /volumes/:id/share
//   - GET    /volumes/:id/permissions
//   - DELETE /permissions/:id
//
// Audit :
//   - VOLUME_PERMISSION_GRANT
//   - VOLUME_PERMISSION_REVOKE
//   - VOLUME_PERMISSION_FORBIDDEN (tentatives non autorisées)
 
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
 
use uuid::Uuid;
 
use crate::api::audit::{AuditSeverity, write_audit_log};
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;
use crate::api::models::volume_permission::{PermissionLevel, VolumePermission};
use crate::db::AppState;
 
//
// ─────────────────────────────────────────────────────────────
// POST /volumes/:id/share
// ─────────────────────────────────────────────────────────────
 
#[derive(serde::Deserialize)]
pub struct ShareVolumeRequest {
    pub grantee_id: Uuid,
    pub permission: PermissionLevel,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}
 
#[derive(serde::Serialize)]
pub struct ShareVolumeResponse {
    pub permission_id: Uuid,
    pub message: String,
}
 
pub async fn share_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(volume_id): Path<Uuid>,
    Json(payload): Json<ShareVolumeRequest>,
) -> Result<Json<ShareVolumeResponse>, (StatusCode, String)> {
    // 1) Récupérer owner_id du volume
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(volume_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;
 
    // 2) RBAC : owner ou ADMIN
    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);
 
    if !is_owner && !is_admin {
        // Audit tentative interdite
        let _ = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_PERMISSION_FORBIDDEN",
            Some(format!(
                "share denied volume_id={volume_id} grantee_id={}",
                payload.grantee_id
            )),
            AuditSeverity::WARNING,
        )
        .await;
 
        return Err((
            StatusCode::FORBIDDEN,
            "Only owner (or ADMIN) can share this volume".into(),
        ));
    }
 
    // 3) Préparer les valeurs (anti move + logs)
    // PermissionLevel n’est pas Copy -> on prépare le texte de log AVANT bind()
    let grantee_id = payload.grantee_id;
    let expires_at = payload.expires_at;
 
    // ✅ On convertit permission en String pour pouvoir loguer sans “move”
    let permission_str = format!("{:?}", payload.permission);
 
    // 4) Insert permission
    let perm_id = Uuid::new_v4();
 
    sqlx::query(
        r#"
        INSERT INTO volume_permissions (id, volume_id, grantee_id, permission, expires_at, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(perm_id)
    .bind(volume_id)
    .bind(grantee_id)
    .bind(payload.permission) // <-- move ici, OK car on ne l’utilise plus après
    .bind(expires_at)
    .bind(auth.user_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;
 
    // 5) Audit après INSERT OK
    let _ = write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_PERMISSION_GRANT",
        Some(format!(
            "permission_id={perm_id} volume_id={volume_id} grantee_id={grantee_id} permission={permission_str} expires_at={expires_at:?}"
        )),
        AuditSeverity::INFO,
    )
    .await;
 
    Ok(Json(ShareVolumeResponse {
        permission_id: perm_id,
        message: "Volume shared".into(),
    }))
}
 
//
// ─────────────────────────────────────────────────────────────
// GET /volumes/:id/permissions
// ─────────────────────────────────────────────────────────────
 
pub async fn list_volume_permissions(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(volume_id): Path<Uuid>,
) -> Result<Json<Vec<VolumePermission>>, (StatusCode, String)> {
    // 1) Vérifier droits via owner_id
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(volume_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;
 
    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);
 
    if !is_owner && !is_admin {
        // Audit tentative interdite
        let _ = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_PERMISSION_FORBIDDEN",
            Some(format!("list permissions denied volume_id={volume_id}")),
            AuditSeverity::WARNING,
        )
        .await;
 
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }
 
    // 2) Retourner la liste
    let list = sqlx::query_as::<_, VolumePermission>(
        "SELECT * FROM volume_permissions WHERE volume_id = $1 ORDER BY created_at DESC",
    )
    .bind(volume_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;
 
    Ok(Json(list))
}
 
//
// ─────────────────────────────────────────────────────────────
// DELETE /permissions/:id
// ─────────────────────────────────────────────────────────────
 
pub async fn revoke_permission(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(permission_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1) Retrouver volume_id (et grantee_id si tu veux le mettre dans le log)
    let row = sqlx::query_as::<_, (Uuid, Uuid)>(
        r#"
        SELECT volume_id, grantee_id
        FROM volume_permissions
        WHERE id = $1
        "#,
    )
    .bind(permission_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;
 
    let Some((volume_id, grantee_id)) = row else {
        return Err((StatusCode::NOT_FOUND, "Permission not found".into()));
    };
 
    // 2) Retrouver owner_id du volume
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(volume_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;
 
    // 3) RBAC owner/admin
    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);
 
    if !is_owner && !is_admin {
        let _ = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_PERMISSION_FORBIDDEN",
            Some(format!(
                "revoke denied permission_id={permission_id} volume_id={volume_id}"
            )),
            AuditSeverity::WARNING,
        )
        .await;
 
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }
 
    // 4) Update permission
    sqlx::query(
    r#"
    UPDATE volume_permissions
    SET status = 'REVOKED', revoked_at = now()
    WHERE id = $1
    "#
    )
    .bind(permission_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // 5) Audit après DELETE OK
    let _ = write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_PERMISSION_REVOKE",
        Some(format!(
            "permission_id={permission_id} volume_id={volume_id} grantee_id={grantee_id} revoked"
        )),
        AuditSeverity::WARNING,
    )
    .await;
 
    Ok(StatusCode::NO_CONTENT)
}
 
 
 
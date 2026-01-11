// Import Axum nécessaires :
// - Json : payloads JSON
// - State : accès à la DB (AppState)
// - Path : paramètres d’URL (/volumes/:id, /permissions/:id)
// - StatusCode : codes HTTP clairs
// - Extension : récupérer AuthUser injecté par le middleware
use axum::{
    Json,
    extract::{State, Path},
    http::StatusCode,
    Extension,
};

use uuid::Uuid;

use crate::db::AppState;

// Modèle + enum
use crate::api::models::volume_permission::{VolumePermission, PermissionLevel};

// Auth (RBAC)
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;

//
// ─────────────────────────────────────────────────────────────
// POST /volumes/:id/share
// Objectif : partager un volume
// Sécurité : owner obligatoire (+ ADMIN override possible)
// ─────────────────────────────────────────────────────────────
//

#[derive(serde::Deserialize)]
pub struct ShareVolumeRequest {
    pub grantee_id: Uuid,
    pub permission: PermissionLevel,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    //  pas de created_by dans le body (anti-spoof)
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
    // 1) Récupérer le owner_id du volume
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(volume_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    // 2) Vérifier RBAC : owner ou ADMIN
    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        return Err((StatusCode::FORBIDDEN, "Only owner (or ADMIN) can share this volume".into()));
    }

    // 3) Créer la permission
    let perm_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO volume_permissions (id, volume_id, grantee_id, permission, expires_at, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#
    )
    .bind(perm_id)
    .bind(volume_id)
    .bind(payload.grantee_id)
    .bind(payload.permission)
    .bind(payload.expires_at)
    .bind(auth.user_id) //  créé par l'utilisateur authentifié
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(ShareVolumeResponse {
        permission_id: perm_id,
        message: "Volume shared".into(),
    }))
}

//
// ─────────────────────────────────────────────────────────────
// GET /volumes/:id/permissions
// Objectif : lister toutes les permissions d’un volume
// Sécurité : owner ou ADMIN
// ─────────────────────────────────────────────────────────────
//

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
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    // 2) Retourner la liste
    let list = sqlx::query_as::<_, VolumePermission>(
        "SELECT * FROM volume_permissions WHERE volume_id = $1 ORDER BY created_at DESC"
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
// Objectif : révoquer une permission
// Sécurité : owner du volume ou ADMIN
// ─────────────────────────────────────────────────────────────
//

pub async fn revoke_permission(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(permission_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1) Retrouver le volume_id de cette permission
    let volume_id: Uuid = sqlx::query_scalar(
        "SELECT volume_id FROM volume_permissions WHERE id = $1"
    )
    .bind(permission_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "Permission not found".into()))?;

    // 2) Retrouver owner_id du volume
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(volume_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    // 3) Vérifier droits : owner ou ADMIN
    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    // 4) Supprimer la permission
    let res = sqlx::query("DELETE FROM volume_permissions WHERE id = $1")
        .bind(permission_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Permission not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

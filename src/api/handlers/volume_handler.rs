// src/api/handlers/volume_handler.rs
//
// Endpoints :
//   - POST   /volumes
//   - GET    /volumes/:id
//   - GET    /users/:id/volumes
//   - PATCH  /volumes/:id
//   - DELETE /volumes/:id
//
// Audit :
//   - VOLUME_CREATE
//   - VOLUME_UPDATE
//   - VOLUME_DELETE
//   - VOLUME_FORBIDDEN (tentatives non autorisées)
//
// Note sécurité : ne JAMAIS logger encrypted_key (clé chiffrée).
 
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid; //pour volume prepare
 
use crate::api::audit::{AuditSeverity, write_audit_log};
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;
use crate::api::models::volume::Volume;
use crate::db::AppState;
 
#[derive(serde::Deserialize)]
pub struct PrepareVolumeRequest {}
 
#[derive(serde::Serialize)]
pub struct PrepareVolumeResponse {
    pub exists: bool,
    pub volume_id: Uuid,
}
 
pub async fn prepare_volume(
    Extension(_auth): Extension<AuthUser>,
    State(_state): State<AppState>,
    Json(_payload): Json<PrepareVolumeRequest>,
) -> Result<Json<PrepareVolumeResponse>, (StatusCode, String)> {

    Ok(Json(PrepareVolumeResponse {
        exists: false,
        volume_id: Uuid::new_v4(),
    }))
}
 
// ─────────────────────────────────────────────────────────────
// POST /volumes
// ─────────────────────────────────────────────────────────────
 
#[derive(serde::Deserialize)]
pub struct CreateVolumeRequest {
    pub volume_id: Uuid,
    pub disk_id: Uuid,
    pub name: String,
    pub size_bytes: i64,
    pub encrypted_key: String,
}
 
#[derive(serde::Serialize)]
pub struct CreateVolumeResponse {
    pub volume_id: Uuid,
    pub message: String,
}
 
pub async fn create_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<CreateVolumeRequest>,
) -> Result<Json<CreateVolumeResponse>, (StatusCode, String)> {
 
    // INSERT dans volumes et volume_keys
    let mut tx = state.db.begin().await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    sqlx::query(
        r#"
        INSERT INTO volumes (id, owner_id, disk_id, name, size_bytes)
        VALUES ($1, $2, $3, $4, $5)
        "#
    )
    .bind(payload.volume_id)
    .bind(auth.user_id)
    .bind(payload.disk_id)
    .bind(&payload.name)
    .bind(payload.size_bytes)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    let volume_key_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO volume_keys (id, volume_id, encrypted_key, key_version, is_active)
        VALUES ($1, $2, $3, $4, $5)
        "#
    )
    .bind(volume_key_id)
    .bind(payload.volume_id)
    .bind(&payload.encrypted_key)
    .bind(1_i32)
    .bind(true)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    tx.commit().await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // Audit après succès
    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_CREATE",
        Some(format!("volume_id={}", payload.volume_id)),
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(CreateVolumeResponse {
        volume_id: payload.volume_id,
        message: "Volume created".into(),
    }))
}
 
// ─────────────────────────────────────────────────────────────
// GET /volumes/:id
// ─────────────────────────────────────────────────────────────
 
pub async fn get_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Volume>, (StatusCode, String)> {
    let v = sqlx::query_as::<_, Volume>("SELECT * FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;
 
    let is_owner = v.owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);
 
    if !is_owner && !is_admin {
        // ✅ Audit tentative interdite
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("get denied volume_id={}", id)),
            AuditSeverity::WARNING,
        )
        .await;
        
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }
 
    Ok(Json(v))
}
 
// ─────────────────────────────────────────────────────────────
// GET /users/:id/volumes
// ─────────────────────────────────────────────────────────────
 
pub async fn list_user_volumes(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Volume>>, (StatusCode, String)> {
    let is_self = auth.user_id == user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);
 
    if !is_self && !is_admin {
        // ✅ Audit tentative interdite
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("list denied target_user_id={}", user_id)),
            AuditSeverity::WARNING,
        )
        .await;
       
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }
 
    let list = sqlx::query_as::<_, Volume>(
        "SELECT * FROM volumes WHERE owner_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;
 
    Ok(Json(list))
}
 
// ─────────────────────────────────────────────────────────────
// PATCH /volumes/:id
// ─────────────────────────────────────────────────────────────
 
#[derive(serde::Deserialize)]
pub struct UpdateVolumeRequest {
    pub name: Option<String>,
    pub size_bytes: Option<i64>,
}
 
pub async fn update_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateVolumeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Vérif owner/admin (et récupérer owner_id)
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;
 
    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);
 
    if !is_owner && !is_admin {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("update denied volume_id={}", id)),
            AuditSeverity::WARNING,
        )
        .await;
    
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }
 
    // Sauver détails avant move
    let new_name = payload.name.clone();
    let new_size = payload.size_bytes;
 
    let res = sqlx::query(
        r#"
        UPDATE volumes
        SET name = COALESCE($1, name),
            size_bytes = COALESCE($2, size_bytes),
            updated_at = now()
        WHERE id = $3
        "#,
    )
    .bind(payload.name)
    .bind(payload.size_bytes)
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;
 
    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Volume not found".into()));
    }
 
    // ✅ Audit après succès
    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_UPDATE",
        Some(format!(
            "volume_id={} name={:?} size_bytes={:?}",
            id, new_name, new_size
        )),
        AuditSeverity::INFO,
    )
    .await;
   
    Ok(StatusCode::NO_CONTENT)
}
 
// ─────────────────────────────────────────────────────────────
// DELETE /volumes/:id
// ─────────────────────────────────────────────────────────────
 
pub async fn delete_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Vérif owner/admin
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;
 
    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);
 
    if !is_owner && !is_admin {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("delete denied volume_id={}", id)),
            AuditSeverity::WARNING,
        )
        .await;
       
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }
 
    // Delete
    let res = sqlx::query("DELETE FROM volumes WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;
 
    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Volume not found".into()));
    }
 
    // ✅ Audit après succès
    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_DELETE",
        Some(format!("volume_id={} deleted", id)),
        AuditSeverity::WARNING,
    )
    .await;
    
    Ok(StatusCode::NO_CONTENT)
}
// src/api/handlers/volume_handler.rs
//
// Endpoints :
//   - POST   /volumes/prepare (vérifie bindkey et existence)
//   - POST   /volumes/verify  (vérifie si le nom existe déjà)
//   - POST   /volumes         (création effective)
//   - GET    /volumes/:id
//   - GET    /users/:id/volumes
//   - PATCH  /volumes/:id
//   - DELETE /volumes/:id

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use sqlx::Row;
use uuid::Uuid;

use crate::api::audit::{AuditSeverity, write_audit_log};
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;
use crate::api::models::volume::Volume;
use crate::db::AppState;

// ─────────────────────────────────────────────────────────────
// STRUCTURES DE REQUÊTE / RÉPONSE
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct PrepareVolumeRequest {
    pub public_key: String,
}

#[derive(serde::Serialize)]
pub struct PrepareVolumeResponse {
    pub exists: bool,
    pub volume_id: Uuid,
}

#[derive(serde::Deserialize)]
pub struct CreateVolumeRequest {
    pub id: Uuid,         // volume_id.clone()
    pub name: String,     // clone_volume_name
    pub size_bytes: i64,  // clone_volume_size
}

#[derive(serde::Serialize)]
pub struct CreateVolumeResponse {
    pub volume_id: Uuid,
    pub message: String,
}

#[derive(serde::Deserialize)]
pub struct VerifyVolumeRequest {
    pub name: String,
}

#[derive(serde::Serialize)]
pub struct VerifyVolumeResponse {
    pub exists: bool,
    pub volume_id: Option<Uuid>,
}

// ─────────────────────────────────────────────────────────────
// HANDLERS
// ─────────────────────────────────────────────────────────────

pub async fn prepare_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<PrepareVolumeRequest>,
) -> Result<Json<PrepareVolumeResponse>, (StatusCode, String)> {
    let row = sqlx::query("SELECT id, user_id FROM bindkeys WHERE public_key = $1")
        .bind(&payload.public_key)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "BindKey not found".into()))?;

    let bindkey_id: Uuid = row.get("id");
    let owner_id: Uuid = row.get("user_id");

    if owner_id != auth.user_id {
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    if let Some(existing_id) =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM volumes WHERE bindkey_id = $1 LIMIT 1")
            .bind(bindkey_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?
    {
        return Ok(Json(PrepareVolumeResponse {
            exists: true,
            volume_id: existing_id,
        }));
    }

    Ok(Json(PrepareVolumeResponse {
        exists: false,
        volume_id: Uuid::new_v4(),
    }))
}

pub async fn verify_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<VerifyVolumeRequest>,
) -> Result<Json<VerifyVolumeResponse>, (StatusCode, String)> {
    let result = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM volumes WHERE owner_id = $1 AND name = $2 LIMIT 1"
    )
    .bind(auth.user_id)
    .bind(&payload.name)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(VerifyVolumeResponse {
        exists: result.is_some(),
        volume_id: result,
    }))
}

pub async fn create_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<CreateVolumeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1) Retrouver la bindkey de l'utilisateur
    let bindkey_id: Uuid = sqlx::query_scalar("SELECT id FROM bindkeys WHERE user_id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "BindKey not found for user".into()))?;

    // 2) INSERT (on enlève encrypted_key de l'insert car absente du payload)
    // Note : si ta colonne DB est NOT NULL, il faudra lui mettre une valeur par défaut ou l'autoriser à être NULL
    sqlx::query(
        r#"
        INSERT INTO volumes (id, owner_id, bindkey_id, name, size_bytes, encrypted_key)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(payload.id)
    .bind(auth.user_id)
    .bind(bindkey_id)
    .bind(&payload.name)
    .bind(payload.size_bytes)
    .bind("") // On met une chaîne vide pour l'instant si tu n'as pas encore la clé
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // 3) Audit
    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_CREATE",
        Some(format!("volume_id={} name={}", payload.id, payload.name)),
        AuditSeverity::INFO,
    )
    .await;

    // Retourne juste 201 OK sans JSON
    Ok(StatusCode::CREATED)
}

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

    if v.owner_id != auth.user_id && !require_role(&auth.role, &UserRole::ADMIN) {
        write_audit_log(&state, Some(auth.user_id), None, "VOLUME_FORBIDDEN", Some(format!("get denied id={}", id)), AuditSeverity::WARNING).await;
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    Ok(Json(v))
}

pub async fn list_user_volumes(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Volume>>, (StatusCode, String)> {
    if auth.user_id != user_id && !require_role(&auth.role, &UserRole::ADMIN) {
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

pub async fn update_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateVolumeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    if owner_id != auth.user_id && !require_role(&auth.role, &UserRole::ADMIN) {
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    let res = sqlx::query(
        r#"
        UPDATE volumes
        SET name = COALESCE($1, name),
            size_bytes = COALESCE($2, size_bytes),
            updated_at = now()
        WHERE id = $3
        "#,
    )
    .bind(&payload.name)
    .bind(payload.size_bytes)
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Volume not found".into()));
    }

    write_audit_log(&state, Some(auth.user_id), None, "VOLUME_UPDATE", Some(format!("id={}", id)), AuditSeverity::INFO).await;
   
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    if owner_id != auth.user_id && !require_role(&auth.role, &UserRole::ADMIN) {
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    let res = sqlx::query("DELETE FROM volumes WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Volume not found".into()));
    }

    write_audit_log(&state, Some(auth.user_id), None, "VOLUME_DELETE", Some(format!("id={} deleted", id)), AuditSeverity::WARNING).await;
    
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
pub struct UpdateVolumeRequest {
    pub name: Option<String>,
    pub size_bytes: Option<i64>,
}
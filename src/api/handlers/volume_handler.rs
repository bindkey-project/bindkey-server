// Axum :
// - Json : gestion des corps JSON
// - State : accès à l’état global (pool DB)
// - Path : paramètres d’URL (/volumes/:id)
// - StatusCode : codes HTTP explicites
use axum::{Json, extract::{State, Path}, http::StatusCode, Extension};

// UUID pour identifier volumes, users, disques
use uuid::Uuid;

// Accès à la base de données
use crate::db::AppState;

// Modèle Volume (correspond à la table PostgreSQL volumes)
use crate::api::models::volume::Volume;

// Auth (RBAC)
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;

//
// ─────────────────────────────────────────────────────────────
// POST /volumes
// Objectif : créer un volume chiffré BindKey
// ─────────────────────────────────────────────────────────────
//

#[derive(serde::Deserialize)]
pub struct CreateVolumeRequest {
    pub owner_id: Uuid,        // ⚠️ ignoré (owner = auth.user_id)
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
    Extension(auth): Extension<AuthUser>,     // ✅ utilisateur authentifié
    State(state): State<AppState>,
    Json(payload): Json<CreateVolumeRequest>,
) -> Result<Json<CreateVolumeResponse>, (StatusCode, String)> {

    // ✅ Owner réel = user connecté (anti-spoof)
    let owner_id = auth.user_id;

    let volume_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO volumes (
            id, owner_id, disk_id, name, size_bytes, encrypted_key
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        "#
    )
    .bind(volume_id)
    .bind(owner_id)
    .bind(payload.disk_id)
    .bind(&payload.name)
    .bind(payload.size_bytes)
    .bind(&payload.encrypted_key)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(CreateVolumeResponse {
        volume_id,
        message: "Volume created".into(),
    }))
}

//
// ─────────────────────────────────────────────────────────────
// GET /volumes/:id
// ─────────────────────────────────────────────────────────────
//

pub async fn get_volume(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Volume>, (StatusCode, String)> {

    let v = sqlx::query_as::<_, Volume>(
        "SELECT * FROM volumes WHERE id = $1"
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    Ok(Json(v))
}

//
// ─────────────────────────────────────────────────────────────
// GET /users/:id/volumes
// Objectif : lister les volumes dont l’utilisateur est propriétaire
// ─────────────────────────────────────────────────────────────
//

pub async fn list_user_volumes(
    Extension(auth): Extension<AuthUser>, // ✅ user connecté
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Volume>>, (StatusCode, String)> {

    // ✅ Protection simple : un USER ne peut lister que SES volumes
    // ADMIN peut lister ceux des autres
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);
    if auth.user_id != user_id && !is_admin {
        return Err((StatusCode::FORBIDDEN, "Owner or ADMIN required".into()));
    }

    let list = sqlx::query_as::<_, Volume>(
        r#"
        SELECT *
        FROM volumes
        WHERE owner_id = $1
        ORDER BY created_at DESC
        "#
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(list))
}

//
// ─────────────────────────────────────────────────────────────
// PATCH /volumes/:id
// Objectif : renommer ou redimensionner un volume
// ─────────────────────────────────────────────────────────────
//

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

    // ✅ Vérifier owner OU admin
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    let is_admin = require_role(&auth.role, &UserRole::ADMIN);
    if auth.user_id != owner_id && !is_admin {
        return Err((StatusCode::FORBIDDEN, "Owner or ADMIN required".into()));
    }

    let res = sqlx::query(
        r#"
        UPDATE volumes
        SET
            name = COALESCE($1, name),
            size_bytes = COALESCE($2, size_bytes),
            updated_at = now()
        WHERE id = $3
        "#
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

    Ok(StatusCode::NO_CONTENT)
}

//
// ─────────────────────────────────────────────────────────────
// DELETE /volumes/:id
// Objectif : supprimer définitivement un volume
// ─────────────────────────────────────────────────────────────
//

pub async fn delete_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {

    // ✅ Vérifier owner OU admin
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    let is_admin = require_role(&auth.role, &UserRole::ADMIN);
    if auth.user_id != owner_id && !is_admin {
        return Err((StatusCode::FORBIDDEN, "Owner or ADMIN required".into()));
    }

    let res = sqlx::query("DELETE FROM volumes WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Volume not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

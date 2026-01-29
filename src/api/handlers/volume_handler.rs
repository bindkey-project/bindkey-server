// Axum :
// - Json : payload JSON
// - State : accès à l’état global (DB)
// - Path : paramètres d’URL (/volumes/:id)
// - StatusCode : réponses HTTP claires
// - Extension : récupérer AuthUser injecté par le middleware
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};

// UUID
use uuid::Uuid;

// DB
use crate::db::AppState;

// Modèle Volume
use crate::api::models::volume::Volume;

// Auth (RBAC)
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;

//
// ─────────────────────────────────────────────────────────────
// POST /volumes
// Objectif : créer un volume chiffré
// Sécurité : owner_id vient DU TOKEN (pas du body)
// ─────────────────────────────────────────────────────────────
//

#[derive(serde::Deserialize)]
pub struct CreateVolumeRequest {
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
    Extension(auth): Extension<AuthUser>, // user authentifié
    State(state): State<AppState>,
    Json(payload): Json<CreateVolumeRequest>,
) -> Result<Json<CreateVolumeResponse>, (StatusCode, String)> {
    let volume_id = Uuid::new_v4();

    // owner = auth.user_id (anti-spoof)
    sqlx::query(
        r#"
        INSERT INTO volumes (id, owner_id, disk_id, name, size_bytes, encrypted_key)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(volume_id)
    .bind(auth.user_id)
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
// Objectif : récupérer un volume
// Sécurité : owner OU ADMIN
// ─────────────────────────────────────────────────────────────
//

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

    //  Vérif owner/admin
    let is_owner = v.owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    Ok(Json(v))
}

//
// ─────────────────────────────────────────────────────────────
// GET /users/:id/volumes
// Objectif : lister les volumes d’un user
// Sécurité : seulement soi-même OU ADMIN
// ─────────────────────────────────────────────────────────────
//

pub async fn list_user_volumes(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Volume>>, (StatusCode, String)> {
    // Un USER ne peut lister que ses propres volumes
    // ADMIN peut lister ceux des autres
    let is_self = auth.user_id == user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_self && !is_admin {
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

//
// ─────────────────────────────────────────────────────────────
// PATCH /volumes/:id
// Objectif : rename/resize
// Sécurité : owner OU ADMIN
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
    // 1) Récupérer owner_id pour vérifier droit
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    // 2) Update
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

    Ok(StatusCode::NO_CONTENT)
}

//
// ─────────────────────────────────────────────────────────────
// DELETE /volumes/:id
// Objectif : supprimer un volume
// Sécurité : owner OU ADMIN
// ─────────────────────────────────────────────────────────────
//

pub async fn delete_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1) Vérif droit via owner_id
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    // 2) Delete
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

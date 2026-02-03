// src/api/handlers/volume_handler.rs
//
// Endpoints :
//   - POST   /volumes
//   - GET    /volumes/:id
//   - GET    /users/:id/volumes
//   - PATCH  /volumes/:id
//   - DELETE /volumes/:id
//
// Audit (table audit_logs) :
//   - VOLUME_CREATE
//   - VOLUME_UPDATE
//   - VOLUME_DELETE
//   - VOLUME_FORBIDDEN (tentatives non autorisées)
//
// Modif principale pour être sûre que les logs s’écrivent en DB :
//   -> supprimer les `.await.ok()` qui masquent les erreurs
//   -> remplacer par `if let Err(e) = write_audit_log(...).await { eprintln!(...) }`
//
// ⚠️ Note sécurité : ne JAMAIS logger `encrypted_key` (clé chiffrée).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension,
    Json,
};

use uuid::Uuid;
use sqlx::Row; // pour prepare_volume

use crate::api::auth::{AuthUser, require_role};
use crate::api::audit::{write_audit_log, AuditSeverity};
use crate::api::models::user::UserRole;
use crate::api::models::volume::Volume;
use crate::db::AppState;

// ─────────────────────────────────────────────────────────────
// PREPARE /volumes (préparer un ID côté client)
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct PrepareVolumeRequest {
    pub public_key: String, // base64/PEM selon votre choix
}

#[derive(serde::Serialize)]
pub struct PrepareVolumeResponse {
    pub exists: bool,
    pub volume_id: Uuid,
}

pub async fn prepare_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<PrepareVolumeRequest>,
) -> Result<Json<PrepareVolumeResponse>, (StatusCode, String)> {
    // 1) Retrouver la bindkey via la public_key + vérifier ownership
    let row = sqlx::query("SELECT id, user_id FROM bindkeys WHERE public_key = $1")
        .bind(&payload.public_key)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "BindKey not found".into()))?;

    let bindkey_id: Uuid = row.get("id");
    let owner_id: Uuid = row.get("user_id");

    if owner_id != auth.user_id {
        // (Optionnel) audit forbidden ici aussi si tu veux tracer les tentatives
        if let Err(e) = write_audit_log(
            &state,
            Some(auth.user_id),
            Some(bindkey_id),
            "VOLUME_FORBIDDEN",
            Some("prepare denied: bindkey ownership mismatch".into()),
            AuditSeverity::WARNING,
        )
        .await
        {
            eprintln!("❌ AUDIT LOG FAILED (VOLUME_FORBIDDEN prepare): {e}");
        }

        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    // 2) Vérifier si un volume existe déjà pour cette bindkey
    if let Some(existing_id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM volumes WHERE bindkey_id = $1 LIMIT 1"
    )
    .bind(bindkey_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))? {
        return Ok(Json(PrepareVolumeResponse {
            exists: true,
            volume_id: existing_id,
        }));
    }

    // 3) Sinon, renvoyer un UUID au client (préparation)
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
    pub encrypted_key: String, // ⚠️ ne jamais logger
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
    // 1) user = 1 bindkey : retrouver bindkey_id
    let bindkey_id: Uuid = sqlx::query_scalar("SELECT id FROM bindkeys WHERE user_id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "BindKey not found for user".into()))?;

    // 2) INSERT volume
    sqlx::query(
        r#"
        INSERT INTO volumes (id, owner_id, bindkey_id, disk_id, name, size_bytes, encrypted_key)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(payload.volume_id)
    .bind(auth.user_id)
    .bind(bindkey_id)
    .bind(payload.disk_id)
    .bind(&payload.name)
    .bind(payload.size_bytes)
    .bind(&payload.encrypted_key) // ⚠️ jamais loguer cette valeur
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // 3) Audit après succès (ne pas cacher l’erreur)
    if let Err(e) = write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_CREATE",
        Some(format!("volume_id={} disk_id={} name={}", payload.volume_id, payload.disk_id, payload.name)),
        AuditSeverity::INFO,
    )
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED (VOLUME_CREATE): {e}");
    }

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
        // Audit tentative interdite (ne pas cacher l’erreur)
        if let Err(e) = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("get denied volume_id={}", id)),
            AuditSeverity::WARNING,
        )
        .await
        {
            eprintln!("❌ AUDIT LOG FAILED (VOLUME_FORBIDDEN get): {e}");
        }

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
        // Audit tentative interdite (ne pas cacher l’erreur)
        if let Err(e) = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("list denied target_user_id={}", user_id)),
            AuditSeverity::WARNING,
        )
        .await
        {
            eprintln!("❌ AUDIT LOG FAILED (VOLUME_FORBIDDEN list): {e}");
        }

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
    // 1) Vérif owner/admin
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        if let Err(e) = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("update denied volume_id={}", id)),
            AuditSeverity::WARNING,
        )
        .await
        {
            eprintln!("❌ AUDIT LOG FAILED (VOLUME_FORBIDDEN update): {e}");
        }

        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    // 2) Sauver détails AVANT move (pour les logs)
    let new_name = payload.name.clone();
    let new_size = payload.size_bytes;

    // 3) UPDATE
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

    // 4) Audit succès (ne pas cacher l’erreur)
    if let Err(e) = write_audit_log(
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
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED (VOLUME_UPDATE): {e}");
    }

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
    // 1) Vérif owner/admin
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        if let Err(e) = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("delete denied volume_id={}", id)),
            AuditSeverity::WARNING,
        )
        .await
        {
            eprintln!("❌ AUDIT LOG FAILED (VOLUME_FORBIDDEN delete): {e}");
        }

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

    // 3) Audit succès (ne pas cacher l’erreur)
    if let Err(e) = write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_DELETE",
        Some(format!("volume_id={} deleted", id)),
        AuditSeverity::WARNING,
    )
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED (VOLUME_DELETE): {e}");
    }

    Ok(StatusCode::NO_CONTENT)
}

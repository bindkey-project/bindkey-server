use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use sqlx::Row; // Crucial pour row.get()
use uuid::Uuid;

use crate::api::audit::{AuditSeverity, write_audit_log};
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;
use crate::api::models::volume::Volume;
use crate::db::AppState;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────
// STRUCTURES
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct PrepareVolumeRequest {
    pub pub_sign: String,
}

#[derive(serde::Serialize)]
pub struct PrepareVolumeResponse {
    pub exists: bool,
    pub volume_id: Uuid,
}

// --- Verify Volume ---
#[derive(Deserialize)]
pub struct VerifyVolumeRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct VerifyVolumeResponse {
    pub exists: bool,
    pub volume_id: Option<String>, // Envoyé en String au logiciel
}

// --- Create Volume ---
#[derive(Deserialize)]
pub struct CreateVolumeRequest {
    pub id: String, // Reçu en String ("bindkey-vol-0001") depuis le logiciel
    pub name: String,
    pub size_bytes: i64,
}

#[derive(Serialize)]
pub struct CreateVolumeResponse {
    pub volume_id: String,
    pub message: String,
}
#[derive(serde::Serialize)]
pub struct GetVolumeKeyResponse {
    pub volume_id: Uuid,
    pub encrypted_key: String,
    pub key_version: i32,
}

#[derive(serde::Deserialize)]
pub struct UpdateVolumeRequest {
    pub name: Option<String>,
    pub size_bytes: Option<i64>,
}

#[derive(Deserialize)]
pub struct FindVolumeIdQuery {
    pub name: String,
}

#[derive(Serialize)]
pub struct FindVolumeIdResponse {
    pub volume_id: String,
}

// ─────────────────────────────────────────────────────────────
// HANDLERS
// ─────────────────────────────────────────────────────────────

pub async fn prepare_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<PrepareVolumeRequest>,
) -> Result<Json<PrepareVolumeResponse>, (StatusCode, String)> {
    let row = sqlx::query("SELECT id, user_id FROM bindkeys WHERE pub_sign = $1")
        .bind(&payload.pub_sign)
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
    // 1. Recherche par nom user-friendly → renvoie le label firmware existant
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT label FROM volumes WHERE owner_id = $1 AND name = $2 LIMIT 1"
    )
    .bind(auth.user_id)
    .bind(&payload.name)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if let Some(label) = existing {
        return Ok(Json(VerifyVolumeResponse {
            exists: true,
            volume_id: Some(label),
        }));
    }

    // 2. Calcul du prochain label : MAX(suffixe existant) + 1 sur l'ensemble des
    //    volumes (le label est unique globalement), à défaut on démarre à 0002.
    let next_suffix: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(
            MAX(CAST(SUBSTRING(label FROM '[0-9]+$') AS BIGINT)) + 1,
            2
        )::BIGINT
        FROM volumes
        "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error count: {e}")))?;

    let next_id_str = format!("bindkey-vol-{:04}", next_suffix);

    tracing::info!("Verify: Volume '{}' non trouvé. Proposition label: {}", payload.name, next_id_str);

    Ok(Json(VerifyVolumeResponse {
        exists: false,
        volume_id: Some(next_id_str),
    }))
}

pub async fn create_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<CreateVolumeRequest>,
) -> Result<(StatusCode, Json<CreateVolumeResponse>), (StatusCode, String)> {
    // 1. Récupération de la BindKey la plus récente du user
    let bindkey_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM bindkeys WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "BindKey manquante".into()))?;

    // 2. INSERT idempotent : si (owner, label) existe déjà, on ne re-crée pas
    let vol_uuid = Uuid::new_v4();
    let inserted: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO volumes (id, owner_id, bindkey_id, label, name, size_bytes)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (label) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(vol_uuid)
    .bind(auth.user_id)
    .bind(bindkey_id)
    .bind(&payload.id)
    .bind(&payload.name)
    .bind(payload.size_bytes)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("SQL INSERT FAILED: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Erreur SQL: {e}"),
        )
    })?;

    let (status, message) = match inserted {
        Some(_) => (StatusCode::CREATED, "Volume créé avec succès".to_string()),
        None    => (StatusCode::OK,      "Volume déjà existant".to_string()),
    };

    let _ = write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_CREATE",
        Some(format!("label={} name={}", payload.id, payload.name)),
        AuditSeverity::INFO,
    )
    .await;

    Ok((
        status,
        Json(CreateVolumeResponse {
            volume_id: payload.id,
            message,
        }),
    ))
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
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("get denied id={}", id)),
            AuditSeverity::WARNING,
        )
        .await;
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

    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_UPDATE",
        Some(format!("id={}", id)),
        AuditSeverity::INFO,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(label): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row: (Uuid, Uuid) = sqlx::query_as(
        "SELECT id, owner_id FROM volumes WHERE label = $1",
    )
    .bind(&label)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    let (volume_id, owner_id) = row;

    if owner_id != auth.user_id && !require_role(&auth.role, &UserRole::ADMIN) {
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    let res = sqlx::query("DELETE FROM volumes WHERE id = $1")
        .bind(volume_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Volume not found".into()));
    }

    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_DELETE",
        Some(format!("label={} id={} deleted", label, volume_id)),
        AuditSeverity::WARNING,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_volume_by_label(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(label): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let res = sqlx::query("DELETE FROM volumes WHERE label = $1")
        .bind(&label)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Volume not found".into()));
    }

    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_DELETE",
        Some(format!("label={} deleted (no-owner-check)", label)),
        AuditSeverity::WARNING,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_volume_key(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(volume_id): Path<Uuid>,
) -> Result<Json<GetVolumeKeyResponse>, (StatusCode, String)> {
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(volume_id)
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
            Some(format!("key access denied volume_id={}", volume_id)),
            AuditSeverity::WARNING,
        )
        .await;
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    let row = sqlx::query_as::<_, (String, i32)>(
        r#"
        SELECT encrypted_key, key_version
        FROM volume_keys
        WHERE volume_id = $1
          AND is_active = TRUE
        LIMIT 1
        "#,
    )
    .bind(volume_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "Active volume key not found".into()))?;

    let (encrypted_key, key_version) = row;

    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_KEY_READ",
        Some(format!("volume_id={}", volume_id)),
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(GetVolumeKeyResponse {
        volume_id,
        encrypted_key,
        key_version,
    }))
}

pub async fn find_volume_id(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Query(params): Query<FindVolumeIdQuery>,
) -> Result<Json<FindVolumeIdResponse>, (StatusCode, String)> {
    // Match sur le nom user-friendly OU le label firmware ("bindkey-vol-XXXX"),
    // toujours scoppé au owner courant. On renvoie le label (jamais l'UUID)
    // car la bindkey ne comprend que ce format.
    let label: Option<String> = sqlx::query_scalar(
        "SELECT label FROM volumes WHERE owner_id = $1 AND (name = $2 OR label = $2) LIMIT 1",
    )
    .bind(auth.user_id)
    .bind(&params.name)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let label = label.ok_or((StatusCode::NOT_FOUND, "Volume non trouvé".into()))?;

    Ok(Json(FindVolumeIdResponse { volume_id: label }))
}

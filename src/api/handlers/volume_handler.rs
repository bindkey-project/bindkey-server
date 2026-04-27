
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use sqlx::Row; // Crucial pour row.get()
use uuid::Uuid;

use crate::api::audit::{write_audit_log, AuditSeverity};
use crate::api::auth::{require_role, AuthUser};
use crate::api::models::user::UserRole;
use crate::api::models::volume::Volume;
use crate::db::AppState;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────
// STRUCTURES
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
    
    // 1. Recherche du volume existant
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM volumes WHERE owner_id = $1 AND name = $2 LIMIT 1"
    )
    .bind(auth.user_id)
    .bind(&payload.name)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if let Some(id) = existing {
        // Conversion de l'UUID (octets) vers String lisible
        let id_str = String::from_utf8(id.as_bytes().to_vec())
            .unwrap_or_else(|_| id.to_string());

        return Ok(Json(VerifyVolumeResponse {
            exists: true,
            volume_id: Some(id_str),
        }));
    }

    // 2. Génération du prochain ID textuel si absent
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM volumes WHERE owner_id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let next_id_str = format!("bindkey-vol-{:04}", count + 1);

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
    
    // 1. Conversion du String reçu en Uuid (16 octets) pour la DB
    let vol_uuid = Uuid::from_bytes(
        payload.id.as_bytes().try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Format d'ID invalide (doit faire 16 car.)".into()))?
    );

    // 2. Récupération de la BindKey
    let bindkey_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM bindkeys WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "BindKey non trouvée".into()))?;

    // 3. Insertion SQL (Type UUID dans la DB)
    sqlx::query(
        r#"
        INSERT INTO volumes (id, owner_id, bindkey_id, name, size_bytes, encrypted_key)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(vol_uuid) // On insère l'objet UUID
    .bind(auth.user_id)
    .bind(bindkey_id)
    .bind(&payload.name)
    .bind(payload.size_bytes)
    .bind("") 
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // 4. Audit & Réponse (en String pour le logiciel)
    let _ = write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_CREATE",
        Some(format!("vol_id={} name={}", payload.id, payload.name)),
        AuditSeverity::INFO,
    ).await;

    Ok((
        StatusCode::CREATED,
        Json(CreateVolumeResponse {
            volume_id: payload.id, // On renvoie le String d'origine
            message: "Volume créé avec succès".into(),
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
    let mut has_permission = false;

    if !is_owner && !is_admin {
        let perm = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT 1
            FROM volume_permissions
            WHERE volume_id = $1
              AND grantee_id = $2
              AND status = 'ACTIVE'
              AND (expires_at IS NULL OR expires_at > now())
            LIMIT 1
            "#,
        )
        .bind(volume_id)
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))? ;

        if perm.is_some() {
            has_permission = true;
        }
    }

    if !is_owner && !is_admin && !has_permission {
        write_audit_log(&state, Some(auth.user_id), None, "VOLUME_FORBIDDEN", Some(format!("key access denied volume_id={}", volume_id)), AuditSeverity::WARNING).await;
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

    write_audit_log(&state, Some(auth.user_id), None, "VOLUME_KEY_READ", Some(format!("volume_id={}", volume_id)), AuditSeverity::INFO).await;

    Ok(Json(GetVolumeKeyResponse {
        volume_id,
        encrypted_key,
        key_version,
    }))
}
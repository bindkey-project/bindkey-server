// ─────────────────────────────────────────────────────────────
// mount_handler.rs
//
// Gère le cycle de montage des volumes :
//   - POST /mount        -> monter un volume
//   - POST /unmount/:id  -> démonter un volume
//
// Sécurité :
//   - Seul le propriétaire du volume ou un ADMIN peut monter
//   - Seul le propriétaire du mount ou un ADMIN peut démonter
//
// Audit :
//   - MOUNT / MOUNT_FAILED / MOUNT_FORBIDDEN
//   - UNMOUNT / UNMOUNT_FAILED / UNMOUNT_FORBIDDEN / UNMOUNT_CONFLICT
// ─────────────────────────────────────────────────────────────

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};

use uuid::Uuid;

use crate::api::audit::{AuditSeverity, write_audit_log};
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;
use crate::db::AppState;

#[derive(serde::Deserialize)]
pub struct MountRequest {
    pub volume_id: Uuid,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(serde::Serialize)]
pub struct MountResponse {
    pub mount_id: Uuid,
    pub message: String,
}

pub async fn mount_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<MountRequest>,
) -> Result<Json<MountResponse>, (StatusCode, String)> {
    let mount_id = Uuid::new_v4();

    let owner_id = match sqlx::query_scalar::<_, Uuid>("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(payload.volume_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            write_audit_log(
                &state,
                Some(auth.user_id),
                None,
                "MOUNT_FAILED",
                Some(format!("Volume not found: volume_id={}", payload.volume_id)),
                AuditSeverity::WARNING,
            )
            .await;

            return Err((StatusCode::NOT_FOUND, "Volume not found".into()));
        }
        Err(e) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")));
        }
    };

    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "MOUNT_FORBIDDEN",
            Some(format!("Access denied for volume_id={}", payload.volume_id)),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((
            StatusCode::FORBIDDEN,
            "Not allowed to mount this volume".into(),
        ));
    }

    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO mounted_volumes (
            id, volume_id, user_id, mounted_at, expires_at, unmounted_at
        )
        VALUES ($1, $2, $3, now(), $4, NULL)
        "#,
    )
    .bind(mount_id)
    .bind(payload.volume_id)
    .bind(auth.user_id)
    .bind(payload.expires_at)
    .execute(&state.db)
    .await
    {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "MOUNT_FAILED",
            Some(format!("Insert failed: {e}")),
            AuditSeverity::ERROR,
        )
        .await;

        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")));
    }

    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "MOUNT",
        Some(format!("Mounted volume_id={}", payload.volume_id)),
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(MountResponse {
        mount_id,
        message: "Mounted successfully".into(),
    }))
}

pub async fn unmount_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(mount_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row = match sqlx::query_as::<_, (Uuid, Option<chrono::DateTime<chrono::Utc>>, Uuid)>(
        r#"
        SELECT user_id, unmounted_at, volume_id
        FROM mounted_volumes
        WHERE id = $1
        "#,
    )
    .bind(mount_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            write_audit_log(
                &state,
                Some(auth.user_id),
                None,
                "UNMOUNT_FAILED",
                Some(format!("Mount not found: mount_id={}", mount_id)),
                AuditSeverity::WARNING,
            )
            .await;

            return Err((StatusCode::NOT_FOUND, "Mount not found".into()));
        }
        Err(e) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")));
        }
    };

    let (mount_owner, unmounted_at, volume_id) = row;

    let is_owner = mount_owner == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "UNMOUNT_FORBIDDEN",
            Some(format!("Access denied for mount_id={}", mount_id)),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((
            StatusCode::FORBIDDEN,
            "Not allowed to unmount this mount".into(),
        ));
    }

    if unmounted_at.is_some() {
        return Err((StatusCode::CONFLICT, "Mount already unmounted".into()));
    }

    if let Err(e) = sqlx::query("UPDATE mounted_volumes SET unmounted_at = now() WHERE id = $1")
        .bind(mount_id)
        .execute(&state.db)
        .await
    {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")));
    }

    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "UNMOUNT",
        Some(format!(
            "Unmounted mount_id={} volume_id={}",
            mount_id, volume_id
        )),
        AuditSeverity::INFO,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

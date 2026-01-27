// ─────────────────────────────────────────────────────────────
// mount_handler.rs
// Gère :
//   - POST /mount
//   - POST /unmount/:id
//
// + Ajout d'audit logs (MOUNT / MOUNT_FORBIDDEN / UNMOUNT / UNMOUNT_FORBIDDEN / etc.)
// ─────────────────────────────────────────────────────────────

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension,
    Json,
};
use uuid::Uuid;

use crate::db::AppState;
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;

// Audit
use crate::api::audit::{write_audit_log, AuditSeverity};

// ─────────────────────────────────────────────────────────────
// Structures
// ─────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────
// POST /mount
// ─────────────────────────────────────────────────────────────
pub async fn mount_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<MountRequest>,
) -> Result<Json<MountResponse>, (StatusCode, String)> {
    let mount_id = Uuid::new_v4();

    // 1) Vérifier volume + récupérer owner_id
    let owner_id_res: Result<Uuid, sqlx::Error> =
        sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
            .bind(payload.volume_id)
            .fetch_one(&state.db)
            .await;

    let owner_id = match owner_id_res {
        Ok(id) => id,
        Err(_) => {
            write_audit_log(
                &state,
                Some(auth.user_id),
                None,
                "MOUNT_FAILED",
                Some(format!("Volume not found: volume_id={}", payload.volume_id)),
                AuditSeverity::WARNING,
            )
            .await
            .ok();

            return Err((StatusCode::NOT_FOUND, "Volume not found".into()));
        }
    };

    // 2) RBAC / ACL : owner OR permission OR admin
    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    let mut has_permission = false;

    if !is_owner && !is_admin {
        let perm_res: Result<Option<i64>, sqlx::Error> = sqlx::query_scalar(
            r#"
            SELECT 1
            FROM volume_permissions
            WHERE volume_id = $1
              AND grantee_id = $2
              AND (expires_at IS NULL OR expires_at > now())
            LIMIT 1
            "#,
        )
        .bind(payload.volume_id)
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await;

        match perm_res {
            Ok(opt) => has_permission = opt.is_some(),
            Err(e) => {
                write_audit_log(
                    &state,
                    Some(auth.user_id),
                    None,
                    "MOUNT_FAILED",
                    Some(format!("DB error while checking permission: {e}")),
                    AuditSeverity::ERROR,
                )
                .await
                .ok();

                return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")));
            }
        }
    }

    if !is_owner && !is_admin && !has_permission {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "MOUNT_FORBIDDEN",
            Some(format!("User cannot mount volume_id={}", payload.volume_id)),
            AuditSeverity::WARNING,
        )
        .await
        .ok();

        return Err((StatusCode::FORBIDDEN, "Not allowed to mount this volume".into()));
    }

    // 3) Insérer le mount
    let ins_res = sqlx::query(
        r#"
        INSERT INTO mounted_volumes (
            id, volume_id, user_id, mounted_at, expires_at, unmounted_at
        )
        VALUES ($1, $2, $3, now(), $4, NULL)
        "#,
    )
    .bind(mount_id)
    .bind(payload.volume_id)
    .bind(auth.user_id) // anti-spoof
    .bind(payload.expires_at)
    .execute(&state.db)
    .await;

    if let Err(e) = ins_res {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "MOUNT_FAILED",
            Some(format!("Insert mounted_volumes failed: {e}")),
            AuditSeverity::ERROR,
        )
        .await
        .ok();

        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")));
    }

    // 4) Audit mount OK
    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "MOUNT",
        Some(format!("Mounted volume_id={}", payload.volume_id)),
        AuditSeverity::INFO,
    )
    .await
    .ok();

    Ok(Json(MountResponse {
        mount_id,
        message: "Mounted".into(),
    }))
}

// ─────────────────────────────────────────────────────────────
// POST /unmount/:id
// ─────────────────────────────────────────────────────────────
pub async fn unmount_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(mount_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1) Récupérer owner du mount + état unmounted_at
    let row_res = sqlx::query_as::<_, (Uuid, Option<chrono::DateTime<chrono::Utc>>, Uuid)>(
        r#"
        SELECT user_id, unmounted_at, volume_id
        FROM mounted_volumes
        WHERE id = $1
        "#,
    )
    .bind(mount_id)
    .fetch_optional(&state.db)
    .await;

    let (mount_owner, unmounted_at, volume_id) = match row_res {
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
            .await
            .ok();

            return Err((StatusCode::NOT_FOUND, "Mount not found".into()));
        }
        Err(e) => {
            write_audit_log(
                &state,
                Some(auth.user_id),
                None,
                "UNMOUNT_FAILED",
                Some(format!("DB error while reading mount: {e}")),
                AuditSeverity::ERROR,
            )
            .await
            .ok();

            return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")));
        }
    };

    // 2) RBAC : propriétaire du mount ou admin
    let is_self = mount_owner == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_self && !is_admin {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "UNMOUNT_FORBIDDEN",
            Some(format!("User tried to unmount mount_id={}", mount_id)),
            AuditSeverity::WARNING,
        )
        .await
        .ok();

        return Err((StatusCode::FORBIDDEN, "Not allowed to unmount this mount".into()));
    }

    // 3) Déjà démonté => 409
    if unmounted_at.is_some() {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "UNMOUNT_CONFLICT",
            Some(format!("Mount already unmounted: mount_id={}", mount_id)),
            AuditSeverity::WARNING,
        )
        .await
        .ok();

        return Err((StatusCode::CONFLICT, "Mount already unmounted".into()));
    }

    // 4) Update unmounted_at
    let upd_res = sqlx::query(
        r#"
        UPDATE mounted_volumes
        SET unmounted_at = now()
        WHERE id = $1
        "#,
    )
    .bind(mount_id)
    .execute(&state.db)
    .await;

    if let Err(e) = upd_res {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "UNMOUNT_FAILED",
            Some(format!("Update mount failed: {e}")),
            AuditSeverity::ERROR,
        )
        .await
        .ok();

        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")));
    }

    // 5) Audit unmount OK
    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "UNMOUNT",
        Some(format!("Unmounted mount_id={} volume_id={}", mount_id, volume_id)),
        AuditSeverity::INFO,
    )
    .await
    .ok();

    Ok(StatusCode::NO_CONTENT)
}

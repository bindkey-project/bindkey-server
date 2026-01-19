use axum::{
    Json,
    extract::{State, Path},
    http::StatusCode,
    Extension,
};
use uuid::Uuid;

// Chrono pour manipuler les dates (timestamps)
use chrono::Utc;
// 1. Pour l'utilisateur authentifié
use crate::api::auth::AuthUser;
use crate::api::auth::require_role;

// 2. Pour le rôle Admin
use crate::api::models::user::UserRole;

// Accès à la connexion PostgreSQL via AppState
use crate::db::AppState;

// Modèle représentant un volume monté (utilisé surtout pour cohérence métier)
use crate::api::models::mounted_volume::MountedVolume;

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

// POST /mount
pub async fn mount_volume(
    Extension(auth): Extension<AuthUser>, // utilisateur authentifié via middleware
    State(state): State<AppState>,
    Json(payload): Json<MountRequest>,
) -> Result<Json<MountResponse>, (StatusCode, String)> {
    let mount_id = Uuid::new_v4();

    // ─────────────────────────────────────────
    // 1) Vérifier que le volume existe + récupérer son owner
    // ─────────────────────────────────────────
    let owner_id: Uuid = sqlx::query_scalar(
        "SELECT owner_id FROM volumes WHERE id = $1"
    )
    .bind(payload.volume_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    // ─────────────────────────────────────────
    // 2) RBAC / ACL : owner OU permission valide
    //    - Owner : OK
    //    - Sinon : il faut une permission (READ/READ_WRITE) non expirée
    // ─────────────────────────────────────────
    let is_owner = owner_id == auth.user_id;

    // Admin override (optionnel mais pratique)
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    let mut has_permission = false;

    if !is_owner && !is_admin {
        // Vérifie si l'utilisateur a une permission sur ce volume
        // et qu'elle n'est pas expirée.
        let perm_exists: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT 1
            FROM volume_permissions
            WHERE volume_id = $1
              AND grantee_id = $2
              AND (expires_at IS NULL OR expires_at > now())
            LIMIT 1
            "#
        )
        .bind(payload.volume_id)
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

        has_permission = perm_exists.is_some();
    }

    if !is_owner && !is_admin && !has_permission {
        return Err((StatusCode::FORBIDDEN, "Not allowed to mount this volume".into()));
    }

    // ─────────────────────────────────────────
    // 3) Insérer le montage (user_id = auth.user_id)
    // ─────────────────────────────────────────
    sqlx::query(
        r#"
        INSERT INTO mounted_volumes (
            id, volume_id, user_id, mounted_at, expires_at, unmounted_at
        )
        VALUES ($1, $2, $3, now(), $4, NULL)
        "#
    )
    .bind(mount_id)
    .bind(payload.volume_id)
    .bind(auth.user_id)          // anti-spoof
    .bind(payload.expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(MountResponse {
        mount_id,
        message: "Mounted".into(),
    }))
}

// POST /unmount/:id
// POST /unmount/:id
pub async fn unmount_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(mount_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {

    // 1) Récupérer le user_id + unmounted_at du mount
    let row = sqlx::query_as::<_, (Uuid, Option<chrono::DateTime<chrono::Utc>>)>(
        r#"
        SELECT user_id, unmounted_at
        FROM mounted_volumes
        WHERE id = $1
        "#
    )
    .bind(mount_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    let Some((mount_owner, unmounted_at)) = row else {
        return Err((StatusCode::NOT_FOUND, "Mount not found".into()));
    };

    // 2) RBAC : seulement le propriétaire du mount ou ADMIN
    let is_self = mount_owner == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_self && !is_admin {
        return Err((StatusCode::FORBIDDEN, "Not allowed to unmount this mount".into()));
    }

    // 3) Si déjà démonté → 409 Conflict (plus clair qu’un 404)
    if unmounted_at.is_some() {
        return Err((StatusCode::CONFLICT, "Mount already unmounted".into()));
    }

    // 4) Sinon on démonte
    sqlx::query(
        r#"
        UPDATE mounted_volumes
        SET unmounted_at = now()
        WHERE id = $1
        "#
    )
    .bind(mount_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

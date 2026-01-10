// Import des éléments Axum nécessaires :
// - Json : pour lire/envoyer du JSON
// - State : pour accéder à l’état global (DB)
// - Path : pour lire les paramètres dans l’URL
// - StatusCode : pour renvoyer des codes HTTP propres
use axum::{
    Json,
    extract::{State, Path},
    http::StatusCode,
    Extension,
};

// UUID pour identifier de façon unique les montages
use uuid::Uuid;

// Chrono pour manipuler les dates (timestamps)
use chrono::Utc;

// Accès à la connexion PostgreSQL via AppState
use crate::db::AppState;

// Modèle représentant un volume monté (utilisé surtout pour cohérence métier)
use crate::api::models::mounted_volume::MountedVolume;

// Auth
use crate::api::auth::AuthUser;

//
// ─────────────────────────────────────────────────────────────
// STRUCTURES DE DONNÉES
// ─────────────────────────────────────────────────────────────
//

#[derive(serde::Deserialize)]
pub struct MountRequest {
    pub volume_id: Uuid,   // Volume à monter
    pub user_id: Uuid,     // ignoré (user = auth.user_id)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(serde::Serialize)]
pub struct MountResponse {
    pub mount_id: Uuid,
    pub message: String,
}

//
// ─────────────────────────────────────────────────────────────
// POST /mount
// Objectif : tracer le montage d’un volume par un utilisateur
// ─────────────────────────────────────────────────────────────
//

pub async fn mount_volume(
    Extension(auth): Extension<AuthUser>, // user connecté
    State(state): State<AppState>,
    Json(payload): Json<MountRequest>,
) -> Result<Json<MountResponse>, (StatusCode, String)> {

    let mount_id = Uuid::new_v4();

    // User réel (anti-spoof)
    let user_id = auth.user_id;

    // Check permission : owner OU permission active
    let has_access: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM volumes v
            WHERE v.id = $1 AND v.owner_id = $2
        )
        OR EXISTS(
            SELECT 1
            FROM volume_permissions p
            WHERE p.volume_id = $1
              AND p.grantee_id = $2
              AND (p.expires_at IS NULL OR p.expires_at > now())
        )
        "#
    )
    .bind(payload.volume_id)
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if !has_access {
        return Err((StatusCode::FORBIDDEN, "No access to this volume".into()));
    }

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
    .bind(user_id)
    .bind(payload.expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(MountResponse {
        mount_id,
        message: "Mounted".into(),
    }))
}

//
// ─────────────────────────────────────────────────────────────
// POST /unmount/:id
// Objectif : démonter un volume (fin d’accès)
// ─────────────────────────────────────────────────────────────
//

pub async fn unmount_volume(
    Extension(auth): Extension<AuthUser>, // user connecté
    State(state): State<AppState>,
    Path(mount_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {

    // Seul celui qui a monté peut démonter (simple & safe)
    let res = sqlx::query(
        r#"
        UPDATE mounted_volumes
        SET unmounted_at = now()
        WHERE id = $1
          AND user_id = $2
          AND unmounted_at IS NULL
        "#
    )
    .bind(mount_id)
    .bind(auth.user_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Mount not found / not yours / already unmounted".into()
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

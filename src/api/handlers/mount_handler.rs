// Import des éléments Axum nécessaires :
// - Json : pour lire/envoyer du JSON
// - State : pour accéder à l’état global (DB)
// - Path : pour lire les paramètres dans l’URL
// - StatusCode : pour renvoyer des codes HTTP propres
use axum::{
    Json,
    extract::{State, Path},
    http::StatusCode
};

// UUID pour identifier de façon unique les montages
use uuid::Uuid;

// Chrono pour manipuler les dates (timestamps)
use chrono::Utc;

// Accès à la connexion PostgreSQL via AppState
use crate::db::AppState;

// Modèle représentant un volume monté (utilisé surtout pour cohérence métier)
use crate::api::models::mounted_volume::MountedVolume;

//
// ─────────────────────────────────────────────────────────────
// STRUCTURES DE DONNÉES
// ─────────────────────────────────────────────────────────────
//

// Données reçues lors du montage d’un volume
#[derive(serde::Deserialize)]
pub struct MountRequest {
    pub volume_id: Uuid,   // Volume à monter
    pub user_id: Uuid,     // Utilisateur qui monte le volume
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>, 
    // Date d’expiration optionnelle (None = pas de limite)
}

// Réponse envoyée après un montage réussi
#[derive(serde::Serialize)]
pub struct MountResponse {
    pub mount_id: Uuid,    // ID du montage (trace en base)
    pub message: String,
}

//
// ─────────────────────────────────────────────────────────────
// POST /mount
// Objectif : tracer le montage d’un volume par un utilisateur
// ─────────────────────────────────────────────────────────────
//

pub async fn mount_volume(
    State(state): State<AppState>,      // Accès à la DB
    Json(payload): Json<MountRequest>,  // JSON reçu du client
) -> Result<Json<MountResponse>, (StatusCode, String)> {

    // Génération d’un identifiant unique pour ce montage
    let mount_id = Uuid::new_v4();

    // Insertion dans la table mounted_volumes
    // - mounted_at = now() → moment exact du montage
    // - unmounted_at = NULL → le volume est actuellement monté
    sqlx::query(
        r#"
        INSERT INTO mounted_volumes (
            id,
            volume_id,
            user_id,
            mounted_at,
            expires_at,
            unmounted_at
        )
        VALUES ($1, $2, $3, now(), $4, NULL)
        "#
    )
    .bind(mount_id)
    .bind(payload.volume_id)
    .bind(payload.user_id)
    .bind(payload.expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("SQL error: {e}")
    ))?;

    // Réponse de succès
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
    State(state): State<AppState>,   // Accès DB
    Path(mount_id): Path<Uuid>,      // ID du montage à fermer
) -> Result<StatusCode, (StatusCode, String)> {

    // Mise à jour du montage :
    // - on définit unmounted_at = now()
    // - uniquement si le volume n’a pas déjà été démonté
    let res = sqlx::query(
        "UPDATE mounted_volumes
         SET unmounted_at = now()
         WHERE id = $1 AND unmounted_at IS NULL"
    )
    .bind(mount_id)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("SQL error: {e}")
    ))?;

    // Si aucune ligne modifiée :
    // - soit le montage n’existe pas
    // - soit il est déjà démonté
    if res.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Mount not found or already unmounted".into()
        ));
    }

    // Succès → pas de contenu à renvoyer
    Ok(StatusCode::NO_CONTENT)
}

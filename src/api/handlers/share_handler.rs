// src/api/handlers/share_handler.rs
// -----------------------------------------------------------------------------
// Volume Sharing — endpoints serveur (cf. share_server.md)
//
// Ce module implémente le flux de partage sécurisé entre BindKeys.
//
// ⚠️ IMPORTANT :
// - Le serveur ne voit JAMAIS la clé en clair
// - Il stocke uniquement un blob chiffré (wrapped_blob)
// - Le chiffrement est fait côté hardware (ATECC608)
//
// Flux global :
//   B → /share_request     (préparation)
//   C → /share_complete    (stockage du wrapped)
//   D → /shares/received   (lecture côté cible)
//   E → accept / deny      (décision utilisateur)
//
// -----------------------------------------------------------------------------
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::auth::AuthUser;
use crate::db::AppState;

//
// ─────────────────────────────────────────────────────────────
// STRUCTURES — REQUEST / RESPONSE
// ─────────────────────────────────────────────────────────────
//

/// Payload envoyé par l'utilisateur source pour initier un partage
#[derive(Debug, Deserialize)]
pub struct ShareRequestPayload {
    pub volume_name: String,       // nom du volume à partager
    pub target_user_email: String, // utilisateur cible
}

/// Réponse contenant les infos nécessaires au chiffrement côté device
#[derive(Debug, Serialize)]
pub struct ShareRequestResponse {
    pub target_sn: String,          // SN de la BindKey cible
    pub target_pubkey_ecdh: String, // clé publique ECDH cible
    pub target_slot: i16,           // slot sécurisé alloué [10..14]
    pub volume_id: Uuid,            // identifiant du volume
}

//
// ─────────────────────────────────────────────────────────────
// POST /share_request — INITIATION DU PARTAGE
// ─────────────────────────────────────────────────────────────
//

pub async fn request_share(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<ShareRequestPayload>,
) -> Result<Json<ShareRequestResponse>, (StatusCode, String)> {
    // 1. Vérifier que le volume appartient à l'utilisateur
    let volume: Option<(Uuid, String)> = sqlx::query_as(
        r#"
        SELECT v.id, b.sn
        FROM volumes v
        JOIN bindkeys b ON b.id = v.bindkey_id
        WHERE v.name = $1 AND v.owner_id = $2
        ORDER BY v.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&payload.volume_name)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (volume_id, source_sn) =
        volume.ok_or((StatusCode::NOT_FOUND, "volume introuvable".into()))?;

    // 2. Trouver la BindKey cible (ACTIVE + pub_ecdh)
    let target: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT b.sn, b.pub_ecdh
        FROM bindkeys b
        JOIN users u ON u.id = b.user_id
        WHERE u.email = $1
          AND b.status = 'ACTIVE'
          AND b.pub_ecdh IS NOT NULL
        ORDER BY b.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&payload.target_user_email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (target_sn, target_pubkey_ecdh) = target.ok_or((
        StatusCode::UNPROCESSABLE_ENTITY,
        "cible invalide (pas de BindKey compatible)".into(),
    ))?;

    // 3. Trouver un slot libre [10..14]
    let slot: Option<(Option<i16>,)> = sqlx::query_as(
        r#"
        SELECT MIN(s)::SMALLINT
        FROM (VALUES (10),(11),(12),(13),(14)) AS slots(s)
        WHERE s NOT IN (
            SELECT target_slot FROM volume_shares WHERE target_sn = $1
        )
        "#,
    )
    .bind(&target_sn)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let target_slot = slot
        .and_then(|(s,)| s)
        .ok_or((StatusCode::CONFLICT, "aucun slot disponible".into()))?;

    // 4. Pré-réserver le partage en base (wrapped_blob = NULL)
    let share_id = Uuid::new_v4();

    let insert_res = sqlx::query(
        r#"
        INSERT INTO volume_shares
        (id, source_sn, target_sn, volume_id, target_slot, wrapped_blob, status)
        VALUES ($1, $2, $3, $4, $5, NULL, 'PENDING')
        "#,
    )
    .bind(share_id)
    .bind(&source_sn)
    .bind(&target_sn)
    .bind(volume_id)
    .bind(target_slot)
    .execute(&state.db)
    .await;

    // Gestion concurrence (slot déjà pris)
    if insert_res.is_err() {
        return Err((StatusCode::CONFLICT, "slot déjà pris".into()));
    }

    // 5. Retourner infos au client
    Ok(Json(ShareRequestResponse {
        target_sn,
        target_pubkey_ecdh,
        target_slot,
        volume_id,
    }))
}

//
// ─────────────────────────────────────────────────────────────
// POST /share_complete — FINALISATION
// ─────────────────────────────────────────────────────────────
//

#[derive(Debug, Deserialize)]
pub struct ShareCompletePayload {
    pub source_sn: String,
    pub target_sn: String,
    pub volume_id: Uuid,
    pub wrapped: String, // clé chiffrée en hex
}

#[derive(Debug, Serialize)]
pub struct ShareCompleteResponse {
    pub share_id: Uuid,
    pub status: &'static str,
}

pub async fn complete_share(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<ShareCompletePayload>,
) -> Result<Json<ShareCompleteResponse>, (StatusCode, String)> {
    // 1. Vérifier que la BindKey source appartient à l'utilisateur
    let owner: Option<(Uuid,)> = sqlx::query_as("SELECT user_id FROM bindkeys WHERE sn = $1")
        .bind(&payload.source_sn)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error".into()))?;

    let (user_id,) = owner.ok_or((StatusCode::NOT_FOUND, "source inconnue".into()))?;

    if user_id != auth.user_id {
        return Err((StatusCode::FORBIDDEN, "non autorisé".into()));
    }

    // 2. Convertir le wrapped (hex → bytes)
    let wrapped_bytes = hex::decode(&payload.wrapped)
        .map_err(|_| (StatusCode::BAD_REQUEST, "hex invalide".into()))?;

    if wrapped_bytes.len() != 60 {
        return Err((StatusCode::BAD_REQUEST, "taille invalide".into()));
    }

    // 3. Mettre à jour le partage
    let updated: Option<(Uuid,)> = sqlx::query_as(
        r#"
        UPDATE volume_shares
        SET wrapped_blob = $4
        WHERE id = (
            SELECT id FROM volume_shares
            WHERE source_sn = $1
              AND target_sn = $2
              AND volume_id = $3
              AND wrapped_blob IS NULL
            LIMIT 1
        )
        RETURNING id
        "#,
    )
    .bind(&payload.source_sn)
    .bind(&payload.target_sn)
    .bind(payload.volume_id)
    .bind(&wrapped_bytes)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error".into()))?;

    let (share_id,) = updated.ok_or((StatusCode::NOT_FOUND, "pas de share".into()))?;

    Ok(Json(ShareCompleteResponse {
        share_id,
        status: "PENDING",
    }))
}

//
// ─────────────────────────────────────────────────────────────
// GET /shares/received — LISTE DES PARTAGES REÇUS
// ─────────────────────────────────────────────────────────────
//

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReceivedShareResponse {
    pub share_id: Uuid,
    pub source_sn: String,
    pub volume_id: Uuid,
    pub target_slot: i16,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_received_shares(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
) -> Result<Json<Vec<ReceivedShareResponse>>, (StatusCode, String)> {
    // Retourne les partages prêts à être utilisés
    let shares = sqlx::query_as::<_, ReceivedShareResponse>(
        r#"
        SELECT vs.id, vs.source_sn, vs.volume_id, vs.target_slot,
               vs.status::text, vs.created_at
        FROM volume_shares vs
        JOIN bindkeys b ON b.sn = vs.target_sn
        WHERE b.user_id = $1
          AND vs.status = 'PENDING'
          AND vs.wrapped_blob IS NOT NULL
        "#,
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error".into()))?;

    Ok(Json(shares))
}

//
// ─────────────────────────────────────────────────────────────
// POST /shares/:id/accept — ACCEPTER
// ─────────────────────────────────────────────────────────────
//

pub async fn accept_share(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let res = sqlx::query(
        r#"
        UPDATE volume_shares vs
        SET status = 'DELIVERED', delivered_at = now()
        FROM bindkeys b
        WHERE vs.id = $1
          AND b.sn = vs.target_sn
          AND b.user_id = $2
        "#,
    )
    .bind(id)
    .bind(auth.user_id)
    .execute(&state.db)
    .await;

    if res.is_err() {
        return Err((StatusCode::NOT_FOUND, "share introuvable".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

//
// ─────────────────────────────────────────────────────────────
// POST /shares/:id/deny — REFUSER
// ─────────────────────────────────────────────────────────────
//

pub async fn deny_share(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let res = sqlx::query(
        r#"
        DELETE FROM volume_shares vs
        USING bindkeys b
        WHERE vs.id = $1
          AND b.sn = vs.target_sn
          AND b.user_id = $2
        "#,
    )
    .bind(id)
    .bind(auth.user_id)
    .execute(&state.db)
    .await;

    if res.is_err() {
        return Err((StatusCode::NOT_FOUND, "share introuvable".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct PendingSharesQuery {
    pub target_sn: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PendingShareResponse {
    pub share_id: Uuid,
    pub source_sn: String,
    pub volume_id: Uuid,
    pub target_slot: i16,
    pub wrapped: String,
}

pub async fn get_pending_shares(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Query(query): Query<PendingSharesQuery>,
) -> Result<Json<Vec<PendingShareResponse>>, (StatusCode, String)> {
    let owns_target_sn: Option<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM bindkeys WHERE sn = $1")
            .bind(&query.target_sn)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let Some((owner_id,)) = owns_target_sn else {
        return Err((StatusCode::NOT_FOUND, "target_sn not found".into()));
    };

    if owner_id != auth.user_id {
        return Err((
            StatusCode::FORBIDDEN,
            "target_sn does not belong to authenticated user".into(),
        ));
    }

    let shares = sqlx::query_as::<_, PendingShareResponse>(
        r#"
        SELECT
            id AS share_id,
            source_sn,
            volume_id,
            target_slot,
            encode(wrapped_blob, 'hex') AS wrapped
        FROM volume_shares
        WHERE target_sn = $1
          AND status = 'PENDING'
          AND wrapped_blob IS NOT NULL
        ORDER BY created_at ASC
        "#,
    )
    .bind(&query.target_sn)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(shares))
}

#[derive(Debug, Deserialize)]
pub struct ShareAckPayload {
    pub share_id: Uuid,
}

pub async fn acknowledge_share(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<ShareAckPayload>,
) -> Result<StatusCode, (StatusCode, String)> {
    let res = sqlx::query(
        r#"
        UPDATE volume_shares vs
        SET status = 'DELIVERED',
            delivered_at = now()
        FROM bindkeys b
        WHERE vs.id = $1
          AND b.sn = vs.target_sn
          AND b.user_id = $2
          AND vs.status = 'PENDING'
          AND vs.wrapped_blob IS NOT NULL
        "#,
    )
    .bind(payload.share_id)
    .bind(auth.user_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "share not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

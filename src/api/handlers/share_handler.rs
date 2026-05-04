// src/api/handlers/share_handler.rs
// -----------------------------------------------------------------------------
// Volume Sharing — endpoints serveur (cf. share_server.md)
//
// Ce module implémente le flux fonctionnel §4 de la spec : demande, stockage
// du wrapped, polling cible, ack. À ce stade : opérations B (request) et
// C (complete). Le polling et l'ack arriveront dans une étape suivante.
//
// Pré-réservation : à /share_request on insère déjà la ligne dans volume_shares
// avec wrapped_blob=NULL et le slot alloué. /share_complete fait un UPDATE
// pour poser le wrapped. Cela garantit que le slot retourné au client = slot
// persisté, sans demander au client de renvoyer target_slot.
// -----------------------------------------------------------------------------

use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::auth::AuthUser;
use crate::db::AppState;

// ─────────────────────────────────────────────────────────────────────────────
// POST /share_request — opération B (Demande de partage)
// ─────────────────────────────────────────────────────────────────────────────
//
// L'app source demande au serveur les infos nécessaires pour construire la
// commande UART `share_*` vers la BK source.
//
// Contrat firmware/protocole :
//
// Input :
//   - volume_name        : nom du volume à partager. Le serveur le résout en
//                          UUID en filtrant sur l'user authentifié.
//   - target_user_email  : email de l'utilisateur cible. Le serveur le résout
//                          en BindKey cible (la plus récente, ACTIVE, avec
//                          pub_ecdh enregistré).
//
// La source est identifiée implicitement par l'authentification (§5) : pas
// besoin de source_sn dans le payload, le BK source réinjectera son propre
// SN au moment de /share_complete (cf. step 5 du protocole UART).
//
// Action serveur :
//   1. Résoudre volume_name → volume_id (filtré sur owner = auth.user_id).
//   2. Résoudre target_user_email → user → BindKey cible (ACTIVE + pub_ecdh).
//   3. Allouer un target_slot libre dans [10..14] (cf. §3 — un slot est
//      considéré occupé tant qu'il y a un volume_share existant pour ce
//      target_sn, peu importe le statut, parce qu'on n'a pas de révocation
//      en v1).
//   4. Retourner (target_sn, target_pub_ecdh, target_slot, volume_id).
//
// Allocation à la volée : aucune réservation n'est posée en base avant
// /share_complete. Si deux requêtes parallèles obtiennent le même slot, la
// deuxième échouera au moment du complete via la contrainte UNIQUE
// (target_sn, target_slot) — au client de rejouer.

#[derive(Debug, Deserialize)]
pub struct ShareRequestPayload {
    pub volume_name: String,
    pub target_user_email: String,
}

#[derive(Debug, Serialize)]
pub struct ShareRequestResponse {
    pub target_sn: String,
    pub target_pubkey_ecdh: String,
    pub target_slot: i16,
    /// Label firmware du volume (ex: "bindkey-vol-0001"), seul format compris par la BindKey.
    pub volume_id: String,
}

pub async fn request_share(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<ShareRequestPayload>,
) -> Result<Json<ShareRequestResponse>, (StatusCode, String)> {
    // 1. Résoudre volume_name → (volume_id UUID, volume_label firmware, source_sn) :
    //    - filtre owner_id = auth.user_id (sécurité §5)
    //    - JOIN sur bindkey_id pour récupérer le SN de la BK source du volume
    //    - on accepte aussi le label firmware en entrée au cas où le client envoie "bindkey-vol-XXXX"
    let volume: Option<(Uuid, String, String)> = sqlx::query_as(
        r#"
        SELECT v.id, v.label, b.sn
        FROM volumes v
        JOIN bindkeys b ON b.id = v.bindkey_id
        WHERE (v.name = $1 OR v.label = $1) AND v.owner_id = $2
        ORDER BY v.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&payload.volume_name)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (volume_id, volume_label, source_sn) = volume.ok_or((
        StatusCode::NOT_FOUND,
        "volume introuvable pour cet utilisateur".into(),
    ))?;

    // 2. Résoudre target_user_email → BindKey cible.
    //    Critères : status ACTIVE, pub_ecdh non-NULL. Plus récente si plusieurs.
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
        "utilisateur cible introuvable ou sans BindKey ACTIVE avec pub_ecdh".into(),
    ))?;

    // 3. Allouer un slot libre dans [10..14] (cf. §3 — un slot est occupé
    //    tant qu'une ligne volume_shares existe pour ce target_sn, peu importe
    //    le statut ou le wrapped_blob, parce qu'on n'a pas de révocation v1).
    //    NULL si tous les 5 slots sont occupés → 409 CONFLICT.
    let slot: Option<(Option<i16>,)> = sqlx::query_as(
        r#"
        SELECT MIN(s)::SMALLINT
        FROM (VALUES (10::SMALLINT),(11),(12),(13),(14)) AS slots(s)
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
        .ok_or((
            StatusCode::CONFLICT,
            "tous les slots [10..14] sont occupés sur la BindKey cible".into(),
        ))?;

    // 4. Pré-réserver la ligne dans volume_shares avec wrapped_blob=NULL.
    //    /share_complete viendra UPDATE le wrapped_blob plus tard.
    //    L'INSERT peut échouer en concurrence sur la contrainte UNIQUE
    //    (target_sn, target_slot) : un autre /share_request a pris le même
    //    slot entre notre SELECT et notre INSERT → 409, le client rejoue.
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

    if let Err(e) = insert_res {
        if let Some(db_err) = e.as_database_error()
            && db_err.code() == Some(std::borrow::Cow::Borrowed("23505"))
        {
            return Err((
                StatusCode::CONFLICT,
                "slot pris en concurrence, rejouer la requête".into(),
            ));
        }
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")));
    }

    Ok(Json(ShareRequestResponse {
        target_sn,
        target_pubkey_ecdh,
        target_slot,
        volume_id: volume_label,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /share_complete — opération C (Stockage du wrapped)
// ─────────────────────────────────────────────────────────────────────────────
//
// L'app source a obtenu le `wrapped` (60 bytes) en réponse UART de la BK source
// au step 5 du protocole. Elle le pousse au serveur, qui finalise la ligne
// pré-réservée à /share_request en posant `wrapped_blob`.
//
// Body (cf. step 6 du protocole soft) :
//   { source_sn, target_sn, volume_id, wrapped }
// `wrapped` est attendu en hex (120 caractères = 60 bytes), comme sur l'UART.
//
// Sécurité §5 : source_sn doit appartenir à l'user authentifié.

#[derive(Debug, Deserialize)]
pub struct ShareCompletePayload {
    pub source_sn: String,
    pub target_sn: String,
    /// Label firmware ("bindkey-vol-XXXX") tel que renvoyé par /share_request.
    /// Le serveur le résout en UUID interne via (owner_id, label).
    pub volume_id: String,
    pub wrapped: String,
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
    // 1. Sécurité §5 : source_sn doit appartenir à l'user authentifié.
    let source_owner: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM bindkeys WHERE sn = $1",
    )
    .bind(&payload.source_sn)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (source_user_id,) = source_owner
        .ok_or((StatusCode::NOT_FOUND, "source_sn introuvable".into()))?;
    if source_user_id != auth.user_id {
        return Err((
            StatusCode::FORBIDDEN,
            "source_sn n'appartient pas à l'utilisateur authentifié".into(),
        ));
    }

    // 1bis. Résoudre le label firmware → UUID interne, scoppé au owner authentifié.
    //       Le client renvoie le label ("bindkey-vol-XXXX") qu'on lui a donné à /share_request.
    let resolved: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM volumes WHERE owner_id = $1 AND label = $2 LIMIT 1",
    )
    .bind(auth.user_id)
    .bind(&payload.volume_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (volume_uuid,) = resolved.ok_or((
        StatusCode::NOT_FOUND,
        "volume_id (label) introuvable pour cet utilisateur".into(),
    ))?;

    // 2. Décoder le wrapped depuis l'hex et vérifier la taille (60 bytes pile).
    let wrapped_bytes = hex::decode(payload.wrapped.trim()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "wrapped doit être une chaîne hexadécimale".into(),
        )
    })?;
    if wrapped_bytes.len() != 60 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "wrapped doit faire exactement 60 bytes ({} reçus)",
                wrapped_bytes.len()
            ),
        ));
    }

    // 3. UPDATE de la ligne pré-réservée la plus récente pour ce triplet.
    //    Match sur wrapped_blob IS NULL = filtre les RESERVED uniquement,
    //    impossible d'écraser un wrapped déjà posé (idempotence + sécurité).
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
            ORDER BY created_at DESC
            LIMIT 1
        )
        RETURNING id
        "#,
    )
    .bind(&payload.source_sn)
    .bind(&payload.target_sn)
    .bind(volume_uuid)
    .bind(&wrapped_bytes)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (share_id,) = updated.ok_or((
        StatusCode::NOT_FOUND,
        "aucun partage en attente pour (source_sn, target_sn, volume_id)".into(),
    ))?;

    Ok(Json(ShareCompleteResponse {
        share_id,
        status: "PENDING",
    }))
}

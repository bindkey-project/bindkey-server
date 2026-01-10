// Axum : framework web Rust
// Json      → gérer les bodies JSON
// State     → accéder à l’état global (DB, config)
// Path      → récupérer les paramètres dans l’URL
// StatusCode→ renvoyer des codes HTTP propres
// Extension → récupérer AuthUser injecté par le middleware (RBAC)
use axum::{
    Json,
    extract::{State, Path},
    http::StatusCode,
    Extension,
};

// UUID : identifiants uniques (users, bindkeys, etc.)
use uuid::Uuid;

// AppState : contient le pool de connexion PostgreSQL
use crate::db::AppState;

// Modèle Bindkey + enum de statut
use crate::api::models::bindkey::{Bindkey, BindkeyStatus};

// Auth (RBAC)
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;

//
// ─────────────────────────────────────────────────────────────
// 1) ENROLL — POST /bindkeys/enroll
// ─────────────────────────────────────────────────────────────
//
// Objectif :
// Associer une BindKey biométrique à un utilisateur
// → opération faite UNE SEULE FOIS lors de l’enrôlement
//

/// Données reçues depuis le client lors de l’enrôlement
#[derive(serde::Deserialize)]
pub struct EnrollBindkeyRequest {
    pub user_id: Uuid,                // Utilisateur propriétaire de la BindKey
    pub bindkey_uid: String,          // Identifiant matériel unique
    pub public_key: String,           // Clé publique (crypto)
    pub fingerprint_template: String, // Empreinte biométrique (hashée)
}

/// Réponse envoyée après enrôlement réussi
#[derive(serde::Serialize)]
pub struct EnrollBindkeyResponse {
    pub bindkey_id: Uuid, // ID généré côté serveur
    pub message: String,
}

/// Handler POST /bindkeys/enroll
pub async fn enroll_bindkey(
    Extension(auth): Extension<AuthUser>,      // Utilisateur authentifié (middleware)
    State(state): State<AppState>,             // Accès DB
    Json(payload): Json<EnrollBindkeyRequest>, // Body JSON
) -> Result<Json<EnrollBindkeyResponse>, (StatusCode, String)> {

    // RBAC : seul ENROLLER/ADMIN peut enrôler
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    // Génération d’un UUID pour la nouvelle BindKey
    let bindkey_id = Uuid::new_v4();

    // Requête SQL d’insertion
    // → statut initial forcé à ACTIVE
    let query = r#"
        INSERT INTO bindkeys (
            id,
            user_id,
            bindkey_uid,
            fingerprint_template,
            public_key,
            status
        )
        VALUES ($1, $2, $3, $4, $5, 'ACTIVE')
    "#;

    // Exécution SQL avec binding sécurisé
    sqlx::query(query)
        .bind(bindkey_id)
        .bind(payload.user_id)
        .bind(&payload.bindkey_uid)
        .bind(&payload.fingerprint_template)
        .bind(&payload.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Enroll BindKey failed: {}", e)
        ))?;

    // Réponse OK
    Ok(Json(EnrollBindkeyResponse {
        bindkey_id,
        message: "BindKey enrolled successfully".into(),
    }))
}

//
// ─────────────────────────────────────────────────────────────
// 2) GET — GET /bindkeys/:id
// ─────────────────────────────────────────────────────────────
//
// Objectif :
// Récupérer une BindKey précise par son UUID
//

pub async fn get_bindkey(
    State(state): State<AppState>,
    Path(id): Path<Uuid>, // UUID depuis l’URL
) -> Result<Json<Bindkey>, (StatusCode, String)> {

    let bindkey = sqlx::query_as::<_, Bindkey>(
        "SELECT * FROM bindkeys WHERE id = $1"
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (
        StatusCode::NOT_FOUND,
        "BindKey not found".into()
    ))?;

    Ok(Json(bindkey))
}

//
// ─────────────────────────────────────────────────────────────
// 3) GET — GET /users/:id/bindkeys
// ─────────────────────────────────────────────────────────────
//
// Objectif :
// Lister toutes les BindKeys associées à un utilisateur
//

pub async fn get_user_bindkeys(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Bindkey>>, (StatusCode, String)> {

    let bindkeys = sqlx::query_as::<_, Bindkey>(
        "SELECT * FROM bindkeys WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Failed to fetch bindkeys: {}", e)
    ))?;

    Ok(Json(bindkeys))
}

//
// ─────────────────────────────────────────────────────────────
// 4) PATCH — PATCH /bindkeys/:id/status
// ─────────────────────────────────────────────────────────────
//
// Objectif :
// Changer le statut d’une BindKey
// (ACTIVE / LOST / BROKEN / RESET)
//

/// Body JSON attendu
#[derive(serde::Deserialize)]
pub struct UpdateBindkeyStatusRequest {
    pub status: BindkeyStatus,
}

pub async fn update_bindkey_status(
    Extension(auth): Extension<AuthUser>, // Utilisateur authentifié
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateBindkeyStatusRequest>,
) -> Result<StatusCode, (StatusCode, String)> {

    // RBAC : seul ENROLLER/ADMIN
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let res = sqlx::query(
        "UPDATE bindkeys SET status = $1 WHERE id = $2"
    )
    .bind(payload.status)
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Failed to update status: {}", e)
    ))?;

    // Si aucune ligne modifiée → BindKey inexistante
    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "BindKey not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

//
// ─────────────────────────────────────────────────────────────
// 5) RESET — POST /bindkeys/:id/reset
// ─────────────────────────────────────────────────────────────
//
// Objectif :
// Tracer une réinitialisation de BindKey (audit & sécurité)
//

#[derive(serde::Deserialize)]
pub struct ResetBindkeyRequest {
    pub reset_type: String, // perte, corruption, effacement…
    // ⚠️ performed_by supprimé côté sécurité :
    // on utilise auth.user_id (sinon spoof possible)
}

pub async fn reset_bindkey(
    Extension(auth): Extension<AuthUser>, // Utilisateur authentifié
    State(state): State<AppState>,
    Path(bindkey_id): Path<Uuid>,
    Json(payload): Json<ResetBindkeyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {

    // RBAC : seul ENROLLER/ADMIN
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let reset_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO bindkey_resets (
            id,
            bindkey_id,
            reset_type,
            performed_by
        )
        VALUES ($1, $2, $3, $4)
        "#
    )
    .bind(reset_id)
    .bind(bindkey_id)
    .bind(&payload.reset_type)
    .bind(auth.user_id) // identifiant réel (depuis token)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Failed to reset bindkey: {}", e)
    ))?;

    Ok(StatusCode::NO_CONTENT)
}

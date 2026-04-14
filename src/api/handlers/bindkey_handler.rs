// Axum : framework web Rust
// Json      → gérer les bodies JSON
// State     → accéder à l’état global (DB, config)
// Path      → récupérer les paramètres dans l’URL
// StatusCode→ renvoyer des codes HTTP propres
// Extension → récupérer AuthUser injecté par le middleware (RBAC)
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
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
}
 
/// Réponse envoyée après enrôlement réussi
#[derive(serde::Serialize)]
pub struct EnrollBindkeyResponse {
    pub bindkey_id: Uuid, // ID généré côté serveur
    pub message: String,
}
 
/// Handler POST /bindkeys/enroll
pub async fn enroll_bindkey(
    Extension(auth): Extension<AuthUser>, // Utilisateur authentifié (middleware)
    State(state): State<AppState>,        // Accès DB
    Json(payload): Json<EnrollBindkeyRequest>, // Body JSON
) -> Result<Json<EnrollBindkeyResponse>, (StatusCode, String)> {
    // RBAC : seul ENROLLER/ADMIN peut enrôler
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }
 
    // Génération d’un UUID pour la nouvelle BindKey
 
    // 1. Génération d’un UUID pour la nouvelle BindKey
 
    let bindkey_id = Uuid::new_v4();
 
    // 2. Requête SQL d’insertion
    let query = r#"
        INSERT INTO bindkeys (
            id, user_id, bindkey_uid, public_key, status
        )
        VALUES ($1, $2, $3, $4, 'ACTIVE')
    "#;
 
    // 3. Exécution SQL avec gestion fine des erreurs
    sqlx::query(query)
        .bind(bindkey_id)
        .bind(payload.user_id)
        .bind(&payload.bindkey_uid)
        .bind(&payload.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| {
            // --- JE DÉBUTE L'AMÉLIORATION ICI ---
            if let Some(db_error) = e.as_database_error() {
                // Code 23505 = Violation d'unicité (Doublon de clé)
                if db_error.code() == Some(std::borrow::Cow::Borrowed("23505")) {
                    return (
                        StatusCode::CONFLICT, // Code HTTP 409
                        "Erreur : Cette BindKey est déjà associée à un utilisateur.".into(),
                    );
                }
 
                // Code 23503 = Violation de clé étrangère (L'utilisateur n'existe pas)
                if db_error.code() == Some(std::borrow::Cow::Borrowed("23503")) {
                    return (
                        StatusCode::NOT_FOUND, // Code HTTP 404
                        "Erreur : L'utilisateur spécifié est introuvable.".into(),
                    );
                }
            }
 
            // Si c'est une autre erreur inconnue, on garde le 500
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Erreur serveur interne : {}", e),
            )
            // --- FIN DE L'AMÉLIORATION ---
        })?;
 
    // 4. Réponse OK
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
    let bindkey = sqlx::query_as::<_, Bindkey>("SELECT * FROM bindkeys WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "BindKey not found".into()))?;
 
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
    let bindkeys = sqlx::query_as::<_, Bindkey>("SELECT * FROM bindkeys WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch bindkeys: {}", e),
            )
        })?;
 
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
 
    let res = sqlx::query("UPDATE bindkeys SET status = $1 WHERE id = $2")
        .bind(payload.status)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update status: {}", e),
            )
        })?;
 
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
        "#,
    )
    .bind(reset_id)
    .bind(bindkey_id)
    .bind(&payload.reset_type)
    .bind(auth.user_id) // identifiant réel (depuis token)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to reset bindkey: {}", e),
        )
    })?;
 
    Ok(StatusCode::NO_CONTENT)
}
 
 
 
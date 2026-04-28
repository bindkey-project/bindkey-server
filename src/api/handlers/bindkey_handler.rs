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

// Génération de certificat BindKey (nouvelle route)
use crate::api::middleware::ca::generate_bindkey_certificate;
 
// Modèle Bindkey + enum de statut
use crate::api::models::bindkey::{Bindkey, BindkeyStatus};
 
// Auth (RBAC)
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;
 

// Audit
use crate::api::audit::{AuditSeverity, write_audit_log};

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
    pub bindkey_id: Uuid,
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

/// Body JSON attendu pour :
/// PATCH /admin/bindkeys/:serial_number/status
///
/// Exemple :
/// {
///   "status": "ACTIVE"
/// }
#[derive(serde::Deserialize)]
pub struct AdminUpdateBindkeyStatusRequest {
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

/// PATCH /admin/bindkeys/:serial_number/status
///
/// Change le statut d'une BindKey à partir de son serial_number.
///
/// IMPORTANT :
/// - `serial_number` côté API correspond à `bindkey_uid` en base.
/// - seules les valeurs de l'enum BindkeyStatus sont acceptées :
///   ACTIVE, RESET, LOST, BROKEN
///
/// Sécurité : ADMIN uniquement.
pub async fn admin_update_bindkey_status_by_serial(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(serial_number): Path<String>,
    Json(payload): Json<AdminUpdateBindkeyStatusRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // ------------------------------------------------------------------
    // 1. Vérification du rôle ADMIN
    // ------------------------------------------------------------------
    //
    // On refuse l'accès à tout utilisateur qui n'est pas ADMIN.
    if !require_role(&auth.role, &UserRole::ADMIN) {
        return Err((StatusCode::FORBIDDEN, "ADMIN required".into()));
    }

    // ------------------------------------------------------------------
    // 2. Validation minimale
    // ------------------------------------------------------------------
    //
    // On évite une requête inutile si le serial_number est vide.
    if serial_number.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "serial_number is required".into()));
    }

    // On prépare une version texte du status AVANT le bind
    let status_for_log = format!("{:?}", payload.status);

    // ------------------------------------------------------------------
    // 3. Mise à jour de la BindKey
    // ------------------------------------------------------------------
    //
    // On met à jour le statut en recherchant la BindKey par bindkey_uid
    // (qui joue ici le rôle de serial_number côté API).
    let res = sqlx::query(
        r#"
        UPDATE bindkeys
        SET status = $1
        WHERE bindkey_uid = $2
        "#
    )
    .bind(payload.status)
    .bind(&serial_number)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("SQL error: {e}"),
        )
    })?;

    // ------------------------------------------------------------------
    // 4. Si aucune ligne n'a été modifiée
    // ------------------------------------------------------------------
    //
    // Cela signifie qu'aucune BindKey avec ce serial_number n'existe.
    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "BindKey not found".into()));
    }

    // ------------------------------------------------------------------
    // 5. Audit
    // ------------------------------------------------------------------
    //
    // On enregistre l'action admin dans les logs d'audit.
    let _ = write_audit_log(
    &state,
    Some(auth.user_id),
    None,
    "ADMIN_BINDKEY_STATUS_UPDATE",
    Some(format!(
        "serial_number={} new_status={}",
        serial_number, status_for_log
    )),
    AuditSeverity::WARNING,
)
.await;

    // ------------------------------------------------------------------
    // 6. Réponse attendue
    // ------------------------------------------------------------------
    Ok(StatusCode::OK)
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

//
// ─────────────────────────────────────────────────────────────
// 6) GENERATE CERTIFICATE — POST /bindkeys/:id/certificate
// ─────────────────────────────────────────────────────────────
//
// Génère un certificat X.509 pour une BindKey existante en utilisant SA propre
// clé publique (déjà stockée en base lors de l'enrôlement).
//
// La clé privée de la BindKey ne quitte JAMAIS le device — le serveur ne fait
// que SIGNER un certificat autour de la clé publique avec la Root CA.
//

#[derive(serde::Serialize)]
pub struct GenerateCertificateResponse {
    /// Certificat X.509 PEM signé par la Root CA.
    pub certificate_pem: String,
}

pub async fn generate_certificate_for_bindkey(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(bindkey_id): Path<Uuid>,
) -> Result<Json<GenerateCertificateResponse>, (StatusCode, String)> {
    // RBAC : ENROLLER ou ADMIN uniquement
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    // 1. Récupère user_id ET public_key de la BindKey en une seule requête
    let row: Option<(Option<Uuid>, String)> =
        sqlx::query_as("SELECT user_id, public_key FROM bindkeys WHERE id = $1")
            .bind(bindkey_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (user_id_opt, public_key) =
        row.ok_or((StatusCode::NOT_FOUND, "BindKey not found".into()))?;
    let user_id = user_id_opt.unwrap_or(Uuid::nil());

    // 2. Signature d'un certificat autour de la clé publique de la BindKey.
    //    Aucune clé privée client n'est manipulée par le serveur.
    let certificate_pem = generate_bindkey_certificate(
        &state.ca_cert_pem,
        &state.ca_key_pem,
        &public_key,
        &bindkey_id.to_string(),
        &user_id.to_string(),
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Erreur génération certificat: {e}")))?;

    // 3. Stockage du certificat en base (écrase l'ancien si existant)
    sqlx::query("UPDATE bindkeys SET certificate = $1 WHERE id = $2")
        .bind(&certificate_pem)
        .bind(bindkey_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Erreur stockage certificat: {e}")))?;

    // 4. Audit
    let _ = write_audit_log(
        &state,
        Some(auth.user_id),
        Some(bindkey_id),
        "BINDKEY_CERTIFICATE_GENERATED",
        Some(format!("bindkey_id={}", bindkey_id)),
        AuditSeverity::WARNING,
    )
    .await;

    Ok(Json(GenerateCertificateResponse { certificate_pem }))
}

//
// ─────────────────────────────────────────────────────────────
// 7) GET CERTIFICATE — GET /bindkeys/:id/certificate
// ─────────────────────────────────────────────────────────────
//
// Retourne le certificat X.509 PEM déjà généré pour cette BindKey.
//

pub async fn get_certificate_for_bindkey(
    State(state): State<AppState>,
    Path(bindkey_id): Path<Uuid>,
) -> Result<String, (StatusCode, String)> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT certificate FROM bindkeys WHERE id = $1")
            .bind(bindkey_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (cert_opt,) = row.ok_or((StatusCode::NOT_FOUND, "BindKey not found".into()))?;

    cert_opt.ok_or((
        StatusCode::NOT_FOUND,
        "Aucun certificat généré pour cette BindKey".into(),
    ))
}
 
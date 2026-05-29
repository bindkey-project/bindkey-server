// Axum : framework web Rust
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};

use uuid::Uuid;

use crate::api::audit::{AuditSeverity, write_audit_log};
use crate::api::auth::{AuthUser, require_role};
use crate::api::middleware::aes_chiffrement::{chiffrer_champ_sensible, dechiffrer_champ_sensible};
use crate::api::middleware::ca::generate_bindkey_certificate;
use crate::api::models::bindkey::{Bindkey, BindkeyStatus};
use crate::api::models::user::UserRole;
use crate::db::AppState;

// ─────────────────────────────────────────────────────────────
// 1) ENROLL — POST /bindkeys/enroll
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct EnrollBindkeyRequest {
    pub user_id: Uuid,
    pub sn: String,
    pub pub_sign: String,
    pub pub_ecdh: String,
}

#[derive(serde::Serialize)]
pub struct EnrollBindkeyResponse {
    pub bindkey_id: Uuid,
    pub message: String,
}

pub async fn enroll_bindkey(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<EnrollBindkeyRequest>,
) -> Result<Json<EnrollBindkeyResponse>, (StatusCode, String)> {
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let bindkey_id = Uuid::new_v4();

    // pub_ecdh est chiffrée avant stockage.
    // pub_sign reste en clair car elle sert à vérifier les signatures.
    let encrypted_pub_ecdh = chiffrer_champ_sensible(&payload.pub_ecdh);

    let query = r#"
        INSERT INTO bindkeys (
            id, user_id, sn, pub_sign, pub_ecdh, status
        )
        VALUES ($1, $2, $3, $4, $5, 'ACTIVE')
    "#;

    sqlx::query(query)
        .bind(bindkey_id)
        .bind(payload.user_id)
        .bind(&payload.sn)
        .bind(&payload.pub_sign)
        .bind(&encrypted_pub_ecdh)
        .execute(&state.db)
        .await
        .map_err(|e| {
            if let Some(db_error) = e.as_database_error() {
                if db_error.code() == Some(std::borrow::Cow::Borrowed("23505")) {
                    return (
                        StatusCode::CONFLICT,
                        "Erreur : Cette BindKey est déjà associée à un utilisateur.".into(),
                    );
                }

                if db_error.code() == Some(std::borrow::Cow::Borrowed("23503")) {
                    return (
                        StatusCode::NOT_FOUND,
                        "Erreur : L'utilisateur spécifié est introuvable.".into(),
                    );
                }
            }

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Erreur serveur interne : {e}"),
            )
        })?;

    Ok(Json(EnrollBindkeyResponse {
        bindkey_id,
        message: "BindKey enrolled successfully".into(),
    }))
}

// ─────────────────────────────────────────────────────────────
// 2) GET — GET /bindkeys/:id
// ─────────────────────────────────────────────────────────────

pub async fn get_bindkey(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Bindkey>, (StatusCode, String)> {
    let bindkey = sqlx::query_as::<_, Bindkey>("SELECT * FROM bindkeys WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "BindKey not found".into()))?;

    Ok(Json(bindkey))
}

// ─────────────────────────────────────────────────────────────
// 3) GET — GET /users/:id/bindkeys
// ─────────────────────────────────────────────────────────────

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
                format!("Failed to fetch bindkeys: {e}"),
            )
        })?;

    Ok(Json(bindkeys))
}

// ─────────────────────────────────────────────────────────────
// 4) PATCH — PATCH /bindkeys/:id/status
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct UpdateBindkeyStatusRequest {
    pub status: BindkeyStatus,
}

#[derive(serde::Deserialize)]
pub struct AdminUpdateBindkeyStatusRequest {
    pub status: BindkeyStatus,
}

pub async fn update_bindkey_status(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateBindkeyStatusRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
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
                format!("Failed to update status: {e}"),
            )
        })?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "BindKey not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn admin_update_bindkey_status_by_serial(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(serial_number): Path<String>,
    Json(payload): Json<AdminUpdateBindkeyStatusRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !require_role(&auth.role, &UserRole::ADMIN) {
        return Err((StatusCode::FORBIDDEN, "ADMIN required".into()));
    }

    if serial_number.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "serial_number is required".into()));
    }

    let status_for_log = format!("{:?}", payload.status);

    let res = sqlx::query(
        r#"
        UPDATE bindkeys
        SET status = $1
        WHERE sn = $2
        "#,
    )
    .bind(payload.status)
    .bind(&serial_number)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "BindKey not found".into()));
    }

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

    Ok(StatusCode::OK)
}

// ─────────────────────────────────────────────────────────────
// 5) RESET — POST /bindkeys/:id/reset
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ResetBindkeyRequest {
    pub reset_type: String,
}

pub async fn reset_bindkey(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(bindkey_id): Path<Uuid>,
    Json(payload): Json<ResetBindkeyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let reset_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO bindkey_resets (
            id, bindkey_id, reset_type, performed_by
        )
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(reset_id)
    .bind(bindkey_id)
    .bind(&payload.reset_type)
    .bind(auth.user_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to reset bindkey: {e}"),
        )
    })?;

    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// 6) GENERATE CERTIFICATE — POST /bindkeys/:id/certificate
// ─────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct GenerateCertificateResponse {
    pub certificate_pem: String,
}

pub async fn generate_certificate_for_bindkey(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(bindkey_id): Path<Uuid>,
) -> Result<Json<GenerateCertificateResponse>, (StatusCode, String)> {
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let row: Option<(Option<Uuid>, String)> =
        sqlx::query_as("SELECT user_id, pub_sign FROM bindkeys WHERE id = $1")
            .bind(bindkey_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (user_id_opt, pub_sign) = row.ok_or((StatusCode::NOT_FOUND, "BindKey not found".into()))?;
    let user_id = user_id_opt.unwrap_or(Uuid::nil());

    let certificate_pem = generate_bindkey_certificate(
        &state.ca_cert_pem,
        &state.ca_key_pem,
        &pub_sign,
        &bindkey_id.to_string(),
        &user_id.to_string(),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Erreur génération certificat: {e}"),
        )
    })?;

    // Certificat chiffré en base.
    // Réponse API : certificat clair, car le client doit pouvoir l’utiliser.
    let encrypted_certificate = chiffrer_champ_sensible(&certificate_pem);

    sqlx::query("UPDATE bindkeys SET certificate = $1 WHERE id = $2")
        .bind(&encrypted_certificate)
        .bind(bindkey_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Erreur stockage certificat: {e}"),
            )
        })?;

    let _ = write_audit_log(
        &state,
        Some(auth.user_id),
        Some(bindkey_id),
        "BINDKEY_CERTIFICATE_GENERATED",
        Some(format!("bindkey_id={bindkey_id}")),
        AuditSeverity::WARNING,
    )
    .await;

    Ok(Json(GenerateCertificateResponse { certificate_pem }))
}

// ─────────────────────────────────────────────────────────────
// 7) GET CERTIFICATE — GET /bindkeys/:id/certificate
// ─────────────────────────────────────────────────────────────

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

    let encrypted_cert = cert_opt.ok_or((
        StatusCode::NOT_FOUND,
        "Aucun certificat généré pour cette BindKey".into(),
    ))?;

    let decrypted_cert = dechiffrer_champ_sensible(&encrypted_cert);

    Ok(decrypted_cert)
}

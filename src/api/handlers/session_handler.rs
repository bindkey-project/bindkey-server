// ─────────────────────────────────────────────────────────────
// src/api/handlers/session_handler.rs
//
// POST /sessions/login
// POST /sessions/refresh
// POST /sessions/logout
//
// Auth : email + password (clair) -> verify avec users.password_hash (argon2)
//
// Audit : LOGIN / LOGIN_FAILED / REFRESH / LOGOUT
// ─────────────────────────────────────────────────────────────

use axum::{extract::State, http::StatusCode, Json};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::db::AppState;

// ✅ Audit helper
use crate::api::audit::{write_audit_log, AuditSeverity};

// ✅ Argon2 verify
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};

// ✅ Challenge nonce (rand 0.9)
use rand::distr::Alphanumeric;
use rand::Rng;

// ─────────────────────────────────────────────────────────────
// Structures
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String, // mot de passe en clair
}

#[derive(serde::Serialize)]
pub struct LoginResponse {
    pub session_id: Uuid,
    pub server_token: String,
    pub local_token: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub first_name: String,
    pub role: String,
    pub auth_challenge: String,
}

#[derive(serde::Deserialize)]
pub struct RefreshRequest {
    pub server_token: String,
}

#[derive(serde::Deserialize)]
pub struct LogoutRequest {
    pub server_token: String,
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/login
// ─────────────────────────────────────────────────────────────
pub async fn login_session(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    // 1) Récupérer user + bindkey + password_hash
    let row = sqlx::query!(
        r#"
        SELECT
            u.id as user_id,
            u.password_hash,
            u.first_name,
            u.role as "role: String",
            b.id as bindkey_id
        FROM users u
        INNER JOIN bindkeys b ON u.id = b.user_id
        WHERE u.email = $1
        "#,
        payload.email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let Some(row) = row else {
        // Audit: user not found / no bindkey
        let _ = write_audit_log(
            &state,
            None,
            None,
            "LOGIN_FAILED",
            Some(format!("Email not found or no bindkey linked: {}", payload.email)),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::UNAUTHORIZED, "Utilisateur ou BindKey non trouvé".into()));
    };

    // 2) Vérifier présence du hash en DB
    let Some(db_hash) = row.password_hash.clone() else {
        let _ = write_audit_log(
            &state,
            Some(row.user_id),
            Some(row.bindkey_id),
            "LOGIN_FAILED",
            Some("User has no password_hash set".to_string()),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::UNAUTHORIZED, "Mot de passe non configuré".into()));
    };

    // 3) Vérifier Argon2 (password clair -> hash)
    let parsed_hash = PasswordHash::new(&db_hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid password hash in DB".into()))?;

    let ok = Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_ok();

    if !ok {
        let _ = write_audit_log(
            &state,
            Some(row.user_id),
            Some(row.bindkey_id),
            "LOGIN_FAILED",
            Some("Wrong password".to_string()),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::UNAUTHORIZED, "Identifiants invalides".into()));
    }

    // 4) Génération du challenge (Nonce)
    let auth_challenge: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // 5) Création session
    let session_id = Uuid::new_v4();
    let server_token = Uuid::new_v4().to_string();
    let local_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(30);

    sqlx::query!(
        r#"
        INSERT INTO sessions (id, user_id, bindkey_id, server_token, local_token, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        session_id,
        row.user_id,
        row.bindkey_id,
        server_token,
        local_token,
        expires_at
    )
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // ✅ Audit succès (après insert OK)
    let _ = write_audit_log(
        &state,
        Some(row.user_id),
        Some(row.bindkey_id),
        "LOGIN",
        Some(format!("Session created, session_id={}", session_id)),
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(LoginResponse {
        session_id,
        server_token,
        local_token,
        expires_at,
        first_name: row.first_name,
        role: row.role,
        auth_challenge,
    }))
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/refresh
// ─────────────────────────────────────────────────────────────
pub async fn refresh_session(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    // 1) Récupérer session + infos user
    let row = sqlx::query!(
        r#"
        SELECT
            s.id as session_id,
            s.user_id,
            s.bindkey_id,
            u.first_name,
            u.role as "role: String"
        FROM sessions s
        INNER JOIN users u ON s.user_id = u.id
        WHERE s.server_token = $1
        "#,
        payload.server_token
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let Some(row) = row else {
        return Err((StatusCode::UNAUTHORIZED, "Invalid session".into()));
    };

    // 2) Générer nouveaux tokens (rotation)
    let new_server_token = Uuid::new_v4().to_string();
    let new_local_token = Uuid::new_v4().to_string();
    let new_expires = Utc::now() + Duration::minutes(30);

    // Challenge optionnel
    let new_challenge: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // 3) Update
    sqlx::query!(
        r#"
        UPDATE sessions
        SET server_token = $1, local_token = $2, expires_at = $3
        WHERE id = $4
        "#,
        new_server_token,
        new_local_token,
        new_expires,
        row.session_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // ✅ Audit refresh
    let _ = write_audit_log(
        &state,
        Some(row.user_id),
        Some(row.bindkey_id),
        "REFRESH",
        Some(format!("Session refreshed, session_id={}", row.session_id)),
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(LoginResponse {
        session_id: row.session_id,
        server_token: new_server_token,
        local_token: new_local_token,
        expires_at: new_expires,
        first_name: row.first_name,
        role: row.role,
        auth_challenge: new_challenge,
    }))
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/logout
// ─────────────────────────────────────────────────────────────
pub async fn logout_session(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // On récupère user/bindkey avant suppression (pour audit)
    let row = sqlx::query!(
        r#"SELECT user_id, bindkey_id FROM sessions WHERE server_token = $1"#,
        payload.server_token
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Delete
    let res = sqlx::query!(
        r#"DELETE FROM sessions WHERE server_token = $1"#,
        payload.server_token
    )
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Session not found".into()));
    }

    // ✅ Audit logout
    if let Some(row) = row {
        let _ = write_audit_log(
            &state,
            Some(row.user_id),
            Some(row.bindkey_id),
            "LOGOUT",
            Some("Session deleted".to_string()),
            AuditSeverity::INFO,
        )
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

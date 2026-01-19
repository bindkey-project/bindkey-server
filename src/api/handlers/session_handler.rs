use axum::{Json, extract::State, http::StatusCode};
use uuid::Uuid;
use chrono::{Utc, Duration};
use crate::db::AppState;
use crate::api::models::session::Session;

// Imports pour rand 0.9
use rand::Rng;
use rand::distr::Alphanumeric;

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password_hash: String,
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

// ─────────────────────────────────────────────────────────────
// POST /sessions/login
// ─────────────────────────────────────────────────────────────
pub async fn login_session(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    
    let row = sqlx::query!(
        r#"
        SELECT 
            u.id as user_id, u.password_hash, u.first_name, u.role as "role: String",
            b.id as bindkey_id 
        FROM users u
        INNER JOIN bindkeys b ON u.id = b.user_id
        WHERE u.email = $1
        "#, 
        payload.email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::UNAUTHORIZED, "Utilisateur ou BindKey non trouvé".into()))?;

    if row.password_hash != Some(payload.password_hash) {
        return Err((StatusCode::UNAUTHORIZED, "Identifiants invalides".into()));
    }

    // Génération du challenge (Nonce)
    let auth_challenge: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let session_id = Uuid::new_v4();
    let server_token = Uuid::new_v4().to_string();
    let local_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(30);

    sqlx::query(
        "INSERT INTO sessions (id, user_id, bindkey_id, server_token, local_token, expires_at) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(session_id)
    .bind(row.user_id)
    .bind(row.bindkey_id)
    .bind(&server_token)
    .bind(&local_token)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

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
#[derive(serde::Deserialize)]
pub struct RefreshRequest {
    pub server_token: String,
}

pub async fn refresh_session(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    
    let row = sqlx::query!(
        r#"
        SELECT 
            s.id, s.user_id, u.first_name, u.role as "role: String"
        FROM sessions s
        INNER JOIN users u ON s.user_id = u.id
        WHERE s.server_token = $1
        "#,
        payload.server_token
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::UNAUTHORIZED, "Invalid session".into()))?;

    let new_server_token = Uuid::new_v4().to_string();
    let new_local_token = Uuid::new_v4().to_string();
    let new_expires = Utc::now() + Duration::minutes(30);
    
    let new_challenge: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    sqlx::query("UPDATE sessions SET server_token=$1, local_token=$2, expires_at=$3 WHERE id=$4")
        .bind(&new_server_token)
        .bind(&new_local_token)
        .bind(new_expires)
        .bind(row.id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(LoginResponse {
        session_id: row.id,
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
#[derive(serde::Deserialize)]
pub struct LogoutRequest {
    pub server_token: String,
}

pub async fn logout_session(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let res = sqlx::query("DELETE FROM sessions WHERE server_token = $1")
        .bind(&payload.server_token)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Session not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}
use axum::{Json, extract::State, http::StatusCode};
use uuid::Uuid;
use chrono::{Utc, Duration};
use crate::db::AppState;
use crate::api::models::session::Session;

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub user_id: Uuid,
    pub bindkey_id: Uuid,
}

#[derive(serde::Serialize)]
pub struct LoginResponse {
    pub session_id: Uuid,
    pub server_token: String,
    pub local_token: String,
    pub expires_at: chrono::DateTime<Utc>,
}

pub async fn login_session(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let session_id = Uuid::new_v4();
    let server_token = Uuid::new_v4().to_string();
    let local_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(30);

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, bindkey_id, server_token, local_token, expires_at)
        VALUES ($1,$2,$3,$4,$5,$6)
        "#
    )
    .bind(session_id)
    .bind(payload.user_id)
    .bind(payload.bindkey_id)
    .bind(&server_token)
    .bind(&local_token)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(LoginResponse { session_id, server_token, local_token, expires_at }))
}

#[derive(serde::Deserialize)]
pub struct RefreshRequest {
    pub server_token: String,
}

pub async fn refresh_session(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    // retrouver session
    let s = sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE server_token = $1")
        .bind(&payload.server_token)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid session".into()))?;

    // nouvelles valeurs
    let new_server_token = Uuid::new_v4().to_string();
    let new_local_token = Uuid::new_v4().to_string();
    let new_expires = Utc::now() + chrono::Duration::minutes(30);

    sqlx::query(
        "UPDATE sessions SET server_token=$1, local_token=$2, expires_at=$3 WHERE id=$4"
    )
    .bind(&new_server_token)
    .bind(&new_local_token)
    .bind(new_expires)
    .bind(s.id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(LoginResponse {
        session_id: s.id,
        server_token: new_server_token,
        local_token: new_local_token,
        expires_at: new_expires,
    }))
}

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

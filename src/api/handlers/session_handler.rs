use axum::{Json, extract::State, http::StatusCode};
use uuid::Uuid;
use chrono::{Utc, Duration};
use crate::db::AppState;
use crate::api::middleware;

// Imports pour rand 0.9
use rand::{Rng, rng}; // On importe 'rng' au lieu de 'thread_rng'
use rand::distr::Alphanumeric; // Note : 'distributions' est devenu 'distr' en 0.9


#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password_hash: String,
}

#[derive(serde::Serialize)]
pub struct LoginResponse {
    pub session_id: Uuid,
    pub auth_challenge: String,
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/login
// ─────────────────────────────────────────────────────────────
pub async fn login_session(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    
    // 1. Recherche de l'utilisateur par email
    let row = sqlx::query!(
        r#"
        SELECT u.id, u.password_hash, b.id as bindkey_id 
        FROM users u
        INNER JOIN bindkeys b ON u.id = b.user_id
        WHERE u.email = $1
        "#, 
        payload.email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::UNAUTHORIZED, "Identifiants invalides".into()))?;

    // 2. Sécurité : Déchiffrement AES + Vérification Argon2
    let encrypted_blob = row.password_hash.ok_or((StatusCode::UNAUTHORIZED, "Identifiants invalides".into()))?;
    
    // Appel à tes nouveaux modules dans middleware
    let argon2_hash = middleware::aes_chiffrement::dechiffrer_aes(&encrypted_blob);
    let is_valid = middleware::hachage_argon2::verifier_hachage(&payload.password_hash, &argon2_hash);

    if !is_valid {
        return Err((StatusCode::UNAUTHORIZED, "Identifiants invalides".into()));
    }

    // 3. Génération du Challenge cryptographique (32 caractères aléatoires)
   let auth_challenge: String = rng() // Plus simple, plus court
    .sample_iter(&Alphanumeric)
    .take(32)
    .map(char::from)
    .collect();

    // 4. Création de la session "en attente" dans la BDD
    let session_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::minutes(5); // Durée de vie courte pour le challenge

    sqlx::query(
        "INSERT INTO sessions (id, user_id, bindkey_id, auth_challenge, expires_at) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(session_id)
    .bind(row.id)
    .bind(row.bindkey_id)
    .bind(&auth_challenge)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // 5. Réponse strictement limitée au nécessaire pour la suite
    Ok(Json(LoginResponse {
        session_id,
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
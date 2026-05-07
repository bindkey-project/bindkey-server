// ─────────────────────────────────────────────────────────────
// Session Handler
// ─────────────────────────────────────────────────────────────

use crate::api::audit::{AuditSeverity, write_audit_log};
use crate::api::middleware;
use crate::db::AppState;

use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use p256::EncodedPoint;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rand::{Rng, distr::Alphanumeric, rng};
use sha2::Sha256;
use sqlx::Row;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────
// Structures d’API (JSON)
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(serde::Serialize)]
pub struct LoginResponse {
    pub session_id: Uuid,
    pub auth_challenge: String,
}

#[derive(serde::Deserialize)]
pub struct VerifyRequest {
    pub session_id: Uuid,
    pub signature: String,
}

#[derive(serde::Serialize)]
pub struct VerifyResponse {
    pub server_token: String,
    pub local_token: String,
    pub first_name: String,
    pub role: String,
}

#[derive(serde::Deserialize)]
pub struct RefreshRequest {
    pub server_token: String,
}

#[derive(serde::Serialize)]
pub struct RefreshResponse {
    pub server_token: String,
    pub local_token: String,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(serde::Deserialize)]
pub struct LogoutRequest {
    pub server_token: String,
}

// ─────────────────────────────────────────────────────────────
// Helpers internes
// ─────────────────────────────────────────────────────────────

fn random_string(len: usize) -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn random_challenge_hex() -> String {
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);

    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

// HMAC-SHA256 utilisé pour stocker les tokens sous forme de hash.
// Le token original est donné au client une seule fois.
// En base, on stocke uniquement le hash.
type HmacSha256 = Hmac<Sha256>;

fn hash_token(token: &str) -> Result<String, String> {
    let secret =
        std::env::var("TOKEN_HASH_SECRET").map_err(|_| "TOKEN_HASH_SECRET manquant".to_string())?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| "Erreur création HMAC".to_string())?;

    mac.update(token.as_bytes());

    Ok(hex::encode(mac.finalize().into_bytes()))
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/login
// ─────────────────────────────────────────────────────────────

pub async fn login_session(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let row = sqlx::query(
        r#"
        SELECT u.id, u.password_hash, b.id AS bindkey_id
        FROM users u
        JOIN bindkeys b ON b.user_id = u.id
        WHERE u.email = $1
        ORDER BY b.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::UNAUTHORIZED, "Identifiants invalides".into()))?;

    let user_id: Uuid = row.get("id");
    let bindkey_id: Uuid = row.get("bindkey_id");
    let encrypted_hash: String = row.get("password_hash");

    let argon2_hash = middleware::aes_chiffrement::dechiffrer_aes(&encrypted_hash);
    let is_valid = middleware::hachage_argon2::verifier_hachage(&payload.password, &argon2_hash);

    if !is_valid {
        write_audit_log(
            &state,
            Some(user_id),
            Some(bindkey_id),
            "LOGIN_FAILED",
            Some("Wrong password".into()),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::UNAUTHORIZED, "Identifiants invalides".into()));
    }

    let session_id = Uuid::new_v4();
    let auth_challenge = random_challenge_hex();
    let expires_at = Utc::now() + Duration::minutes(5);

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, bindkey_id, auth_challenge, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .bind(bindkey_id)
    .bind(&auth_challenge)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    write_audit_log(
        &state,
        Some(user_id),
        Some(bindkey_id),
        "LOGIN_INITIATED",
        Some(format!("Session créée: {session_id}")),
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(LoginResponse {
        session_id,
        auth_challenge,
    }))
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/verify
// ─────────────────────────────────────────────────────────────

pub async fn verify_session(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    let row = sqlx::query(
        r#"
        SELECT s.user_id, s.bindkey_id, s.auth_challenge,
               b.pub_sign, u.first_name, u.role::text AS role
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        JOIN bindkeys b ON b.id = s.bindkey_id
        WHERE s.id = $1 AND s.expires_at > NOW()
        "#,
    )
    .bind(payload.session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((
        StatusCode::UNAUTHORIZED,
        "Session invalide ou expirée".into(),
    ))?;

    let user_id: Uuid = row.get("user_id");
    let bindkey_id: Uuid = row.get("bindkey_id");
    let challenge: String = row.get("auth_challenge");
    let public_key_raw: String = row.get("pub_sign");

    // Décodage adaptatif de la clé publique : hex ou base64.
    let mut pub_key_bytes = if let Ok(hex_bytes) = hex::decode(public_key_raw.trim()) {
        hex_bytes
    } else {
        general_purpose::STANDARD
            .decode(public_key_raw.trim())
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Clé publique: format inconnu".into(),
                )
            })?
    };

    // Ajout automatique du préfixe SEC1 si la clé est en 64 bytes.
    if pub_key_bytes.len() == 64 {
        let mut prefixed = vec![0x04];
        prefixed.extend_from_slice(&pub_key_bytes);
        pub_key_bytes = prefixed;
    }

    let encoded_point = EncodedPoint::from_bytes(&pub_key_bytes).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Format SEC1 clé publique invalide".into(),
        )
    })?;

    let verifying_key = VerifyingKey::from_encoded_point(&encoded_point).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Point sur la courbe P-256 invalide".into(),
        )
    })?;

    // Décodage de la signature hex.
    let mut sig_hex = payload.signature.replace(' ', "");

    if sig_hex.len() % 2 != 0 {
        sig_hex = format!("0{sig_hex}");
    }

    let mut sig_bytes = hex::decode(&sig_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Format hex de la signature invalide".into(),
        )
    })?;

    if sig_bytes.len() < 64 {
        let mut padded = vec![0u8; 64 - sig_bytes.len()];
        padded.extend_from_slice(&sig_bytes);
        sig_bytes = padded;
    }

    let signature = Signature::from_slice(&sig_bytes).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Format de signature ECDSA invalide".into(),
        )
    })?;

    let challenge_bytes = hex::decode(&challenge).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Challenge en base invalide".into(),
        )
    })?;

    // Vérification P-256 compatible matériel.
    use p256::ecdsa::signature::hazmat::PrehashVerifier;

    if let Err(e) = verifying_key.verify_prehash(&challenge_bytes, &signature)
        && verifying_key
            .verify(challenge.as_bytes(), &signature)
            .is_err()
    {
        let detail_err = format!("Signature invalide: {e}");

        write_audit_log(
            &state,
            Some(user_id),
            Some(bindkey_id),
            "VERIFY_FAILED",
            Some(detail_err.clone()),
            AuditSeverity::ERROR,
        )
        .await;

        return Err((StatusCode::UNAUTHORIZED, detail_err));
    }

    // Tokens donnés au client.
    let server_token = random_string(64);
    let local_token = random_string(64);

    // Hash HMAC stockés en base.
    let server_token_hash =
        hash_token(&server_token).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let local_token_hash =
        hash_token(&local_token).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let expires_at = Utc::now() + Duration::minutes(30);

    sqlx::query(
        r#"
        UPDATE sessions
        SET server_token = $1,
            local_token = $2,
            auth_challenge = NULL,
            expires_at = $3
        WHERE id = $4
        "#,
    )
    .bind(&server_token_hash)
    .bind(&local_token_hash)
    .bind(expires_at)
    .bind(payload.session_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    write_audit_log(
        &state,
        Some(user_id),
        Some(bindkey_id),
        "VERIFY_SUCCESS",
        None,
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(VerifyResponse {
        server_token,
        local_token,
        first_name: row.get("first_name"),
        role: row.get("role"),
    }))
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/refresh
// ─────────────────────────────────────────────────────────────

pub async fn refresh_session(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    // Le client envoie le token original.
    // Le serveur le hash et compare avec le hash stocké.
    let server_token_hash =
        hash_token(&payload.server_token).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let row = sqlx::query("SELECT id FROM sessions WHERE server_token = $1 AND expires_at > NOW()")
        .bind(&server_token_hash)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Session expirée".into()))?;

    let session_uuid: Uuid = row.get("id");

    let new_server_token = random_string(64);
    let new_local_token = random_string(64);

    let new_server_token_hash =
        hash_token(&new_server_token).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let new_local_token_hash =
        hash_token(&new_local_token).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let expires_at = Utc::now() + Duration::minutes(30);

    sqlx::query(
        r#"
        UPDATE sessions
        SET server_token = $1,
            local_token = $2,
            expires_at = $3
        WHERE id = $4
        "#,
    )
    .bind(&new_server_token_hash)
    .bind(&new_local_token_hash)
    .bind(expires_at)
    .bind(session_uuid)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(RefreshResponse {
        server_token: new_server_token,
        local_token: new_local_token,
        expires_at,
    }))
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/logout
// ─────────────────────────────────────────────────────────────

pub async fn logout_session(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let server_token_hash =
        hash_token(&payload.server_token).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let res = sqlx::query("DELETE FROM sessions WHERE server_token = $1")
        .bind(&server_token_hash)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Session non trouvée".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/test
// Route de démo : crée directement une session validée.
// Les tokens retournés au client restent en clair,
// mais la base stocke seulement leurs hash HMAC.
// ─────────────────────────────────────────────────────────────

pub async fn test_session(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    let row = sqlx::query(
        r#"
        SELECT u.id, u.password_hash, u.first_name, u.role::text AS role, b.id AS bindkey_id
        FROM users u
        JOIN bindkeys b ON b.user_id = u.id
        WHERE u.email = $1
        ORDER BY b.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::UNAUTHORIZED, "Utilisateur non trouvé".into()))?;

    let user_id: Uuid = row.get("id");
    let bindkey_id: Uuid = row.get("bindkey_id");
    let encrypted_hash: String = row.get("password_hash");

    let argon2_hash = middleware::aes_chiffrement::dechiffrer_aes(&encrypted_hash);
    let is_valid = middleware::hachage_argon2::verifier_hachage(&payload.password, &argon2_hash);

    if !is_valid {
        write_audit_log(
            &state,
            Some(user_id),
            Some(bindkey_id),
            "TEST_ROUTE_FAILED",
            Some("Wrong password".into()),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::UNAUTHORIZED, "Mot de passe incorrect".into()));
    }

    let session_id = Uuid::new_v4();
    let server_token = random_string(64);
    let local_token = random_string(64);

    let server_token_hash =
        hash_token(&server_token).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let local_token_hash =
        hash_token(&local_token).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let expires_at = Utc::now() + Duration::minutes(30);

    sqlx::query(
        r#"
        INSERT INTO sessions (
            id, user_id, bindkey_id, server_token, local_token, auth_challenge, expires_at
        )
        VALUES ($1, $2, $3, $4, $5, NULL, $6)
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .bind(bindkey_id)
    .bind(&server_token_hash)
    .bind(&local_token_hash)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    write_audit_log(
        &state,
        Some(user_id),
        Some(bindkey_id),
        "TEST_SESSION_CREATED",
        Some(format!("Full session via test route for {}", payload.email)),
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(VerifyResponse {
        server_token,
        local_token,
        first_name: row.get("first_name"),
        role: row.get("role"),
    }))
}

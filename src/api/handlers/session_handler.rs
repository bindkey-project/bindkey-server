// src/api/handlers/session_handler.rs
//
// Session Handler
//
// Endpoints :
//   - POST /sessions/login
//   - POST /sessions/verify
//   - POST /sessions/refresh
//   - POST /sessions/logout
//
// Objectif de cette version :
//   1) Écrire des logs d’audit EN BASE (table audit_logs)
//   2) Ne jamais “cacher” les erreurs d’audit : pas de `let _ = ...await;`
//      -> on fait `if let Err(e) = ... { eprintln!(...) }`
//   3) Ajouter les audits manquants : VERIFY_FAILED, SESSION_REFRESH, LOGOUT

use crate::api::audit::{AuditSeverity, write_audit_log};
use crate::api::middleware;
use crate::db::AppState;

use axum::{Json, extract::State, http::StatusCode};

use chrono::{Duration, Utc};
use uuid::Uuid;

use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use std::convert::TryInto;

use rand::{Rng, distr::Alphanumeric, rng};

use sqlx::Row;

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

// ─────────────────────────────────────────────────────────────
// POST /sessions/login
// ─────────────────────────────────────────────────────────────

pub async fn login_session(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    // 1) Récupérer user + bindkey + password_hash
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

    // 2) Vérifier le mot de passe
    let argon2_hash = middleware::aes_chiffrement::dechiffrer_aes(&encrypted_hash);
    let is_valid = middleware::hachage_argon2::verifier_hachage(&payload.password, &argon2_hash);

    if !is_valid {
        // Audit : login failed (mauvais mdp)
        if let Err(e) = write_audit_log(
            &state,
            Some(user_id),
            Some(bindkey_id),
            "LOGIN_FAILED",
            Some("Wrong password".into()),
            AuditSeverity::WARNING,
        )
        .await
        {
            eprintln!("❌ AUDIT LOG FAILED (LOGIN_FAILED): {e}");
        }

        return Err((StatusCode::UNAUTHORIZED, "Identifiants invalides".into()));
    }

    // 3) Créer la session (challenge court, 5 minutes)
    let session_id = Uuid::new_v4();
    let auth_challenge = random_string(32);
    let expires_at = Utc::now() + Duration::minutes(5);

    sqlx::query(
        "INSERT INTO sessions (id, user_id, bindkey_id, auth_challenge, expires_at) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(session_id)
    .bind(user_id)
    .bind(bindkey_id)
    .bind(&auth_challenge)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit : login success (challenge émis)
    if let Err(e) = write_audit_log(
        &state,
        Some(user_id),
        Some(bindkey_id),
        "LOGIN",
        Some(format!("session_id={session_id}")),
        AuditSeverity::INFO,
    )
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED (LOGIN): {e}");
    }

    Ok(Json(LoginResponse { session_id, auth_challenge }))
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/verify
// ─────────────────────────────────────────────────────────────

pub async fn verify_session(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    // 1) Récupération de la session + infos utilisateur/clé
    let row = sqlx::query(
        r#"
        SELECT s.user_id, s.bindkey_id, s.auth_challenge,
               b.public_key, u.first_name, u.role::text AS role
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
    .ok_or((StatusCode::UNAUTHORIZED, "Session invalide ou expirée".into()))?;

    let user_id: Uuid = row.get("user_id");
    let bindkey_id: Uuid = row.get("bindkey_id");
    let challenge: String = row.get("auth_challenge");
    let public_key_b64: String = row.get("public_key");

    // 2) Décodage clé publique Ed25519 (Base64)
    let pub_key_bytes = general_purpose::STANDARD
        .decode(&public_key_b64)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Clé publique invalide".into()))?;

    let pub_key_array: [u8; 32] = pub_key_bytes
        .try_into()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Taille clé publique incorrecte".into()))?;

    let verifying_key = VerifyingKey::from_bytes(&pub_key_array)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Format clé Ed25519 invalide".into()))?;

    // 3) Décodage signature reçue (Base64)
    let sig_bytes = general_purpose::STANDARD
        .decode(&payload.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Signature Base64 invalide".into()))?;

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Taille signature incorrecte".into()))?;

    let signature = Signature::from_bytes(&sig_array);

    // 4) Vérification cryptographique
    // Ici on veut logger VERIFY_FAILED si la signature est invalide.
    if let Err(_) = verifying_key.verify(challenge.as_bytes(), &signature) {
        if let Err(e) = write_audit_log(
            &state,
            Some(user_id),
            Some(bindkey_id),
            "VERIFY_FAILED",
            Some(format!("session_id={} invalid signature", payload.session_id)),
            AuditSeverity::WARNING,
        )
        .await
        {
            eprintln!("❌ AUDIT LOG FAILED (VERIFY_FAILED): {e}");
        }

        return Err((StatusCode::UNAUTHORIZED, "Signature invalide".into()));
    }

    // 5) Génération tokens (session validée) : 30 minutes
    let server_token = random_string(64);
    let local_token = random_string(64);
    let expires_at = Utc::now() + Duration::minutes(30);

    // Update session : set tokens + clear challenge (usage unique)
    sqlx::query(
        "UPDATE sessions SET server_token=$1, local_token=$2, auth_challenge=NULL, expires_at=$3 WHERE id=$4"
    )
    .bind(&server_token)
    .bind(&local_token)
    .bind(expires_at)
    .bind(payload.session_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 6) Audit : verify success
    if let Err(e) = write_audit_log(
        &state,
        Some(user_id),
        Some(bindkey_id),
        "VERIFY_SUCCESS",
        Some(format!("session_id={} verified", payload.session_id)),
        AuditSeverity::INFO,
    )
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED (VERIFY_SUCCESS): {e}");
    }

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
    // 1) Retrouver la session via server_token (et vérifier non expirée)
    let row = sqlx::query("SELECT id, user_id, bindkey_id FROM sessions WHERE server_token = $1 AND expires_at > NOW()")
        .bind(&payload.server_token)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Session expirée".into()))?;

    let session_uuid: Uuid = row.get("id");
    let user_id: Uuid = row.get("user_id");
    let bindkey_id: Uuid = row.get("bindkey_id");

    // 2) Générer nouveaux tokens
    let new_server_token = random_string(64);
    let new_local_token = random_string(64);
    let expires_at = Utc::now() + Duration::minutes(30);

    // 3) Update session avec nouveaux tokens
    sqlx::query("UPDATE sessions SET server_token=$1, local_token=$2, expires_at=$3 WHERE id=$4")
        .bind(&new_server_token)
        .bind(&new_local_token)
        .bind(expires_at)
        .bind(session_uuid)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit : refresh success
    if let Err(e) = write_audit_log(
        &state,
        Some(user_id),
        Some(bindkey_id),
        "SESSION_REFRESH",
        Some(format!("session_id={session_uuid}")),
        AuditSeverity::INFO,
    )
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED (SESSION_REFRESH): {e}");
    }

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
    // ⚠️ Pour auditer proprement, on récupère user_id + bindkey_id AVANT suppression
    let row = sqlx::query("SELECT id, user_id, bindkey_id FROM sessions WHERE server_token = $1")
        .bind(&payload.server_token)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let Some(row) = row else {
        return Err((StatusCode::NOT_FOUND, "Session non trouvée".into()));
    };

    let session_id: Uuid = row.get("id");
    let user_id: Uuid = row.get("user_id");
    let bindkey_id: Uuid = row.get("bindkey_id");

    // 2) Supprimer la session
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(session_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit : logout success
    if let Err(e) = write_audit_log(
        &state,
        Some(user_id),
        Some(bindkey_id),
        "LOGOUT",
        Some(format!("session_id={session_id}")),
        AuditSeverity::INFO,
    )
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED (LOGOUT): {e}");
    }

    Ok(StatusCode::NO_CONTENT)
}

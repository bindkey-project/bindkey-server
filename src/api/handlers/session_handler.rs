// ─────────────────────────────────────────────────────────────
// Session Handler
// ─────────────────────────────────────────────────────────────

use crate::api::audit::{AuditSeverity, write_audit_log};
use crate::api::middleware;
use crate::db::AppState;
use axum::{Json, extract::State, http::StatusCode};
use chrono::{Duration, Utc};
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose};
use std::convert::TryInto;
use rand::{Rng, distr::Alphanumeric, rng};
use sqlx::Row;
use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
use p256::EncodedPoint;


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
    let mut bytes = [0u8; 32]; // 16 octets =64 caractères hexadécimaux
    rand::rng().fill_bytes(&mut bytes);
    
    // Conversion en Hexa Majuscule
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
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
    .ok_or((StatusCode::UNAUTHORIZED, "Identifiants invalides v4".into()))?;

    let user_id: Uuid = row.get("id");
    let bindkey_id: Uuid = row.get("bindkey_id");
    let encrypted_hash: String = row.get("password_hash");

    let argon2_hash = middleware::aes_chiffrement::dechiffrer_aes(&encrypted_hash);
    let is_valid = middleware::hachage_argon2::verifier_hachage(&payload.password, &argon2_hash);

    if !is_valid {
        // Version simplifiée : on lance l'audit et on n'attend pas forcément le résultat 
        // pour bloquer l'utilisateur, mais on utilise notre nouvelle fonction avec match.
        write_audit_log(&state, Some(user_id), Some(bindkey_id), "LOGIN_FAILED", Some("Wrong password".into()), AuditSeverity::WARNING).await;
        
        return Err((StatusCode::UNAUTHORIZED, "Identifiants invalides".into()));
    }
    let session_id = Uuid::new_v4();
    let auth_challenge = random_challenge_hex();
    let expires_at = Utc::now() + Duration::minutes(5);

    sqlx::query("INSERT INTO sessions (id, user_id, bindkey_id, auth_challenge, expires_at) VALUES ($1, $2, $3, $4, $5)")
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
        Some(format!("Session créée: {}", session_id)), 
        AuditSeverity::INFO
    ).await;
    Ok(Json(LoginResponse { session_id, auth_challenge }))
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/verify
// ─────────────────────────────────────────────────────────────

pub async fn verify_session(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    
    // 1. Récupération de la session et des infos (Inchangé)
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

    // 2. Décodage de la clé publique ECDSA P-256
    let pub_key_bytes = general_purpose::STANDARD.decode(&public_key_b64)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Clé publique Base64 invalide".into()))?;
    
    // Pour ECDSA, on utilise from_encoded_point (supporte compressé/non-compressé SEC1)
    let encoded_point = EncodedPoint::from_bytes(&pub_key_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Format SEC1 clé publique invalide".into()))?;
        
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Point sur la courbe P-256 invalide".into()))?;

    // 3. Décodage de la signature avec gestion du padding
let mut sig_hex = payload.signature.replace(" ", "");

// Si la chaîne est impaire (ex: 127 chars), on ajoute un 0 au début pour la symétrie
if sig_hex.len() % 2 != 0 {
    sig_hex = format!("0{}", sig_hex);
}

let mut sig_bytes = hex::decode(&sig_hex)
    .map_err(|_| (StatusCode::BAD_REQUEST, "Format Hexa invalide".into()))?;

// Si on a moins de 64 octets (padding manquant), on complète par des zéros à GAUCHE
if sig_bytes.len() < 64 {
    let mut padded = vec![0u8; 64 - sig_bytes.len()];
    padded.extend_from_slice(&sig_bytes);
    sig_bytes = padded;
}

// Maintenant on peut créer la signature sans risque de crash
let signature = Signature::from_slice(&sig_bytes)
    .map_err(|_| (StatusCode::BAD_REQUEST, "Format de signature ECDSA invalide".into()))?;
    // 4. Vérification cryptographique
    // Note: p256::ecdsa réalise le hachage SHA-256 du message automatiquement 
    // lors de l'appel à .verify() si on utilise les bons traits.
    match verifying_key.verify(challenge.as_bytes(), &signature) {
        Ok(_) => {
            println!("🔒 Signature ECDSA P-256 vérifiée avec succès");
        },
        Err(e) => {
            write_audit_log(
                &state, 
                Some(user_id), 
                Some(bindkey_id), 
                "VERIFY_FAILED", 
                Some(format!("Signature ECDSA invalide pour la session {}: {}", payload.session_id, e)), 
                AuditSeverity::ERROR
            ).await;

            return Err((StatusCode::UNAUTHORIZED, "Signature invalide".into()));
        }
    }

    // 5. Génération des tokens (Inchangé)
    let server_token = random_string(64);
    let local_token = random_string(64);
    let expires_at = Utc::now() + Duration::minutes(30);

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

    // 6. Audit Log du succès
    write_audit_log(&state, Some(user_id), Some(bindkey_id), "VERIFY_SUCCESS", None, AuditSeverity::INFO).await;

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
    let row = sqlx::query("SELECT id FROM sessions WHERE server_token = $1 AND expires_at > NOW()")
        .bind(&payload.server_token)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Session expirée".into()))?;

    let session_uuid: Uuid = row.get("id");
    let new_server_token = random_string(64);
    let new_local_token = random_string(64);
    let expires_at = Utc::now() + Duration::minutes(30);

    sqlx::query("UPDATE sessions SET server_token=$1, local_token=$2, expires_at=$3 WHERE id=$4")
        .bind(&new_server_token).bind(&new_local_token).bind(expires_at).bind(session_uuid)
        .execute(&state.db).await
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
    let res = sqlx::query("DELETE FROM sessions WHERE server_token = $1")
        .bind(&payload.server_token)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Session non trouvée".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// POST /sessions/test (Route combinée pour Démo)
// ─────────────────────────────────────────────────────────────

pub async fn test_session(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    // 1. Authentification classique (identique au login)
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

    // Vérification du mot de passe
    let argon2_hash = middleware::aes_chiffrement::dechiffrer_aes(&encrypted_hash);
    let is_valid = middleware::hachage_argon2::verifier_hachage(&payload.password, &argon2_hash);

    if !is_valid {
        write_audit_log(&state, Some(user_id), Some(bindkey_id), "TEST_ROUTE_FAILED", Some("Wrong password".into()), AuditSeverity::WARNING).await;
        return Err((StatusCode::UNAUTHORIZED, "Mot de passe incorrect".into()));
    }

    // 2. Génération immédiate des tokens finaux (Skip du challenge cryptographique)
    let session_id = Uuid::new_v4();
    let server_token = random_string(64);
    let local_token = random_string(64);
    let expires_at = Utc::now() + Duration::minutes(30);

    // Insertion directe d'une session validée en base
    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, bindkey_id, server_token, local_token, auth_challenge, expires_at) 
        VALUES ($1, $2, $3, $4, $5, NULL, $6)
        "#
    )
    .bind(session_id)
    .bind(user_id)
    .bind(bindkey_id)
    .bind(&server_token)
    .bind(&local_token)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 3. Audit Log
    write_audit_log(
        &state, 
        Some(user_id), 
        Some(bindkey_id), 
        "TEST_SESSION_CREATED", 
        Some(format!("Full session via test route for {}", payload.email)), 
        AuditSeverity::INFO
    ).await;

    // 4. On renvoie la même structure que /sessions/verify
    Ok(Json(VerifyResponse {
        server_token,
        local_token,
        first_name: row.get("first_name"),
        role: row.get("role"),
    }))
}
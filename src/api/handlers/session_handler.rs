use axum::{Json, extract::State, http::StatusCode};
use uuid::Uuid;
use chrono::{Utc, Duration};
use crate::db::AppState;
use crate::api::middleware;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use base64::{engine::general_purpose, Engine as _};
use std::convert::TryInto; // Pour le try_into()
use serde::{Deserialize, Serialize};


// Imports pour rand 0.9
use rand::{Rng, rng}; // On importe 'rng' au lieu de 'thread_rng'
use rand::distr::Alphanumeric; // Note : 'distributions' est devenu 'distr' en 0.9


#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
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
// POST /sessions/verify
// ─────────────────────────────────────────────────────────────
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub session_id: Uuid,
    pub signature: String, 
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub server_token: String,
    pub local_token: String,
    pub first_name: String,
    pub role: String,
}

pub async fn verify_session(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    
    // 1. Récupération de la session + Clé Publique + Infos User
    // On vérifie aussi que la session n'est pas expirée
    let data = sqlx::query!(
        r#"
        SELECT 
            s.auth_challenge, 
            b.public_key, 
            u.first_name, 
            u.role as "role: String"
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        JOIN bindkeys b ON s.bindkey_id = b.id
        WHERE s.id = $1 AND s.expires_at > NOW()
        "#,
        payload.session_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::UNAUTHORIZED, "Session invalide ou expirée".into()))?;

    let challenge = data.auth_challenge.ok_or((StatusCode::UNAUTHORIZED, "Challenge déjà utilisé ou inexistant".into()))?;

    // 2. VÉRIFICATION DE LA SIGNATURE ECC

// a. Décoder la clé publique stockée en BDD
let pub_key_bytes_vec = general_purpose::STANDARD.decode(&data.public_key)
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Clé publique invalide (Base64 corrompu)".into()))?;

// Conversion Vec<u8> -> [u8; 32] (Ed25519 utilise des clés de 32 octets)
let pub_key_array: [u8; 32] = pub_key_bytes_vec.try_into()
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "La clé publique en BDD n'a pas la bonne taille (32 octets attendus)".into()))?;

let public_key = VerifyingKey::from_bytes(&pub_key_array)
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Format de clé publique Ed25519 invalide".into()))?;


// b. Décoder la signature reçue
let sig_bytes_vec = general_purpose::STANDARD.decode(&payload.signature)
    .map_err(|_| (StatusCode::BAD_REQUEST, "Signature Base64 invalide".into()))?;

// Conversion Vec<u8> -> [u8; 64] (Ed25519 utilise des signatures de 64 octets)
let sig_array: [u8; 64] = sig_bytes_vec.try_into()
    .map_err(|_| (StatusCode::BAD_REQUEST, "La signature reçue n'a pas la bonne taille (64 octets attendus)".into()))?;

let signature = Signature::from_bytes(&sig_array);


// c. Vérifier si la signature correspond au challenge original
fn generate_secure_token() -> String {
    use rand::{Rng, rng};
    use rand::distr::Alphanumeric;

    rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}
public_key.verify(challenge.as_bytes(), &signature)
    .map_err(|_| (StatusCode::UNAUTHORIZED, "Échec de la vérification : signature invalide pour ce challenge".into()))?;
    // 3. GÉNÉRATION DES TOKENS FINAUX
    let server_token = generate_secure_token(); 
    let local_token = generate_secure_token();

    // 4. VALIDATION DE LA SESSION EN BDD
    // On enregistre les tokens et on SUPPRIME le challenge (usage unique !)
    sqlx::query!(
        "UPDATE sessions SET server_token = $1, local_token = $2, auth_challenge = NULL WHERE id = $3",
        server_token,
        local_token,
        payload.session_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 5. RÉPONSE FINALE
    Ok(Json(VerifyResponse {
        server_token,
        local_token,
        first_name: data.first_name,
        role: data.role,
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
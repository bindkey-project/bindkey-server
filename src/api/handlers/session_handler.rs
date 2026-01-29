// ─────────────────────────────────────────────────────────────
// Session Handler
//
// Gère le cycle complet d’authentification BindKey :
//   - login    : vérifie mot de passe + génère un challenge
//   - verify   : vérifie signature bindkey + génère tokens
//   - refresh  : rotation des tokens
//   - logout   : suppression de la session
//
// Sécurité :
//   - Password stocké en DB = Argon2 hash chiffré en AES
//   - Challenge signé par la BindKey (Ed25519)
//   - Tokens aléatoires à usage serveur
// ─────────────────────────────────────────────────────────────

use axum::{Json, extract::State, http::StatusCode};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::db::AppState;

// Crypto middleware (AES + Argon2)
use crate::api::middleware;

// Ed25519 : vérification de signature
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::convert::TryInto;

// Génération aléatoire (rand 0.9)
use rand::{Rng, distr::Alphanumeric, rng};

// Accès SQL dynamique
use sqlx::Row;

// Audit
use crate::api::audit::{AuditSeverity, write_audit_log};

//
// ─────────────────────────────────────────────────────────────
// Structures d’API (JSON)
// ─────────────────────────────────────────────────────────────

/// Requête de login : mot de passe EN CLAIR (HTTPS obligatoire)
#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Réponse de login : session temporaire + challenge
#[derive(serde::Serialize)]
pub struct LoginResponse {
    pub session_id: Uuid,
    pub auth_challenge: String,
}

/// Requête de vérification : signature du challenge
#[derive(serde::Deserialize)]
pub struct VerifyRequest {
    pub session_id: Uuid,
    pub signature: String, // Base64(signature Ed25519)
}

/// Réponse finale après vérification
#[derive(serde::Serialize)]
pub struct VerifyResponse {
    pub server_token: String,
    pub local_token: String,
    pub first_name: String,
    pub role: String,
}

/// Requête de refresh
#[derive(serde::Deserialize)]
pub struct RefreshRequest {
    pub server_token: String,
}

/// Réponse de refresh
#[derive(serde::Serialize)]
pub struct RefreshResponse {
    pub server_token: String,
    pub local_token: String,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Requête de logout
#[derive(serde::Deserialize)]
pub struct LogoutRequest {
    pub server_token: String,
}

//
// ─────────────────────────────────────────────────────────────
// Helpers internes
// ─────────────────────────────────────────────────────────────

/// Génère une chaîne aléatoire sécurisée
fn random_string(len: usize) -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

//
// ─────────────────────────────────────────────────────────────
// POST /sessions/login
// ─────────────────────────────────────────────────────────────
//
// Étapes :
//  1) récupérer user + bindkey
//  2) déchiffrer password_hash (AES)
//  3) vérifier Argon2(password clair)
//  4) créer session temporaire + challenge
//

pub async fn login_session(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    // 1) Charger l’utilisateur + une bindkey associée
    // ⚠️ Si plusieurs bindkeys : prévoir bindkey_uid dans la requête
    let row = sqlx::query(
        r#"
        SELECT u.id, u.password_hash, b.id AS bindkey_id
        FROM users u
        JOIN bindkeys b ON b.user_id = u.id
        WHERE u.email = $1
        "#,
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::UNAUTHORIZED, "Identifiants invalides".into()))?;

    let user_id: Uuid = row.get("id");
    let bindkey_id: Uuid = row.get("bindkey_id");

    // 2) Récupérer le hash chiffré du mot de passe
    let encrypted_hash: Option<String> = row.get("password_hash");
    let encrypted_hash = encrypted_hash.ok_or((
        StatusCode::UNAUTHORIZED,
        "Mot de passe non configuré".into(),
    ))?;

    // 3) Déchiffrement AES → vérification Argon2
    let argon2_hash = middleware::aes_chiffrement::dechiffrer_aes(&encrypted_hash);
    let is_valid = middleware::hachage_argon2::verifier_hachage(&payload.password, &argon2_hash);

    if !is_valid {
        // Audit échec
        let _ = write_audit_log(
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

    // 4) Création de la session temporaire
    let session_id = Uuid::new_v4();
    let auth_challenge = random_string(32); // nonce à signer
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

    // Audit succès
    let _ = write_audit_log(
        &state,
        Some(user_id),
        Some(bindkey_id),
        "LOGIN",
        Some(format!("session_id={session_id}")),
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(LoginResponse {
        session_id,
        auth_challenge,
    }))
}

//
// ─────────────────────────────────────────────────────────────
// POST /sessions/verify
// ─────────────────────────────────────────────────────────────
//
// Étapes :
//  1) récupérer session + challenge + clé publique
//  2) décoder clé publique Ed25519
//  3) décoder signature
//  4) vérifier signature(challenge)
//  5) générer tokens définitifs
//

pub async fn verify_session(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    
    // 1. Récupération de la session + Clé Publique + Infos User
    let data = sqlx::query!(
    let row = sqlx::query(
        r#"
        SELECT s.user_id, s.bindkey_id, s.auth_challenge,
               b.public_key, u.first_name, u.role
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
    .ok_or((StatusCode::UNAUTHORIZED, "Session invalide".into()))?;

    let challenge: String = row.get("auth_challenge");
    let public_key_b64: String = row.get("public_key");

    // 2. VÉRIFICATION DE LA SIGNATURE ECC

    // a. Décoder la clé publique stockée en BDD
    let pub_key_bytes_vec = general_purpose::STANDARD.decode(&data.public_key)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Clé publique invalide (Base64 corrompu)".into()))?;

    let pub_key_array: [u8; 32] = pub_key_bytes_vec.try_into()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "La clé publique en BDD n'a pas la bonne taille (32 octets attendus)".into()))?;
    // Décodage clé publique
    let pub_key_bytes = general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid public key".into()))?;
    let pub_key: [u8; 32] = pub_key_bytes
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid key length".into()))?;

    let public_key = VerifyingKey::from_bytes(&pub_key_array)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Format de clé publique Ed25519 invalide".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_key)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Ed25519 key".into()))?;

    // b. Décoder la signature reçue
    let sig_bytes_vec = general_purpose::STANDARD.decode(&payload.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Signature Base64 invalide".into()))?;

    let sig_array: [u8; 64] = sig_bytes_vec.try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "La signature reçue n'a pas la bonne taille (64 octets attendus)".into()))?;
    // Décodage signature
    let sig_bytes = general_purpose::STANDARD
        .decode(&payload.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature".into()))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature length".into()))?;

    let signature = Signature::from_bytes(&sig_array);
    let signature = Signature::from_bytes(&sig_array);

    // --- AJOUT DES LOGS DE DEBUG ---
    println!("DEBUG: Challenge string: '{}'", challenge);
    println!("DEBUG: Challenge bytes: {:?}", challenge.as_bytes());
    println!("DEBUG: Signature bytes: {:?}", sig_array);
    // -------------------------------

    // c. Vérifier si la signature correspond au challenge original
    public_key.verify(challenge.as_bytes(), &signature)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Échec de la vérification : signature invalide pour ce challenge".into()))?;

    // 3. GÉNÉRATION DES TOKENS FINAUX
    fn generate_secure_token() -> String {
        use rand::{Rng, rng};
        use rand::distr::Alphanumeric;

        rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    }

    let server_token = generate_secure_token(); 
    let local_token = generate_secure_token();

    // 4. VALIDATION DE LA SESSION EN BDD
    sqlx::query!(
        "UPDATE sessions SET server_token = $1, local_token = $2, auth_challenge = NULL WHERE id = $3",
        server_token,
        local_token,
        payload.session_id
    )
    // Vérification cryptographique
    verifying_key
        .verify(challenge.as_bytes(), &signature)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Signature invalide".into()))?;

    // Génération des tokens définitifs
    let server_token = random_string(64);
    let local_token = random_string(64);
    let expires_at = Utc::now() + Duration::minutes(30);

    sqlx::query(
        r#"
        UPDATE sessions
        SET server_token=$1, local_token=$2,
            auth_challenge=NULL, expires_at=$3
        WHERE id=$4
        "#,
    )
    .bind(&server_token)
    .bind(&local_token)
    .bind(expires_at)
    .bind(payload.session_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(VerifyResponse {
        server_token,
        local_token,
        first_name: row.get("first_name"),
        role: row.get("role"),
    }))
}

//
// ─────────────────────────────────────────────────────────────
// POST /sessions/refresh
// ─────────────────────────────────────────────────────────────

/// Réponse de refresh
#[derive(serde::Serialize)]
pub struct RefreshResponse {
    pub server_token: String,
    pub local_token: String,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Requête de logout
#[derive(serde::Deserialize)]
pub struct LogoutRequest {
    pub server_token: String,
}

//
// ─────────────────────────────────────────────────────────────
// Helpers internes
// ─────────────────────────────────────────────────────────────

/// Génère une chaîne aléatoire sécurisée
fn random_string(len: usize) -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

//
// ─────────────────────────────────────────────────────────────
// POST /sessions/login
// ─────────────────────────────────────────────────────────────
//
// Étapes :
//  1) récupérer user + bindkey
//  2) déchiffrer password_hash (AES)
//  3) vérifier Argon2(password clair)
//  4) créer session temporaire + challenge
//

pub async fn login_session(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    let row = sqlx::query("SELECT id FROM sessions WHERE server_token = $1 AND expires_at > NOW()")
        .bind(&payload.server_token)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Session expirée".into()))?;

    let new_server_token = random_string(64);
    let new_local_token = random_string(64);
    let expires_at = Utc::now() + Duration::minutes(30);

    sqlx::query("UPDATE sessions SET server_token=$1, local_token=$2, expires_at=$3 WHERE id=$4")
        .bind(&new_server_token)
        .bind(&new_local_token)
        .bind(expires_at)
        .bind(row.get::<Uuid, _>("id"))
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(RefreshResponse {
        server_token: new_server_token,
        local_token: new_local_token,
        expires_at,
    }))
}

//
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

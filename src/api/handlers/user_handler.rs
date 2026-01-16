// Import Axum :
// - Json : pour gérer les corps de requêtes/réponses JSON
// - State : pour accéder à l’état global de l’application (DB)
// - Path : pour lire les paramètres dans l’URL (/users/:id)
// - Query : pour lire les paramètres de requête (?email=...)
// - StatusCode : pour renvoyer des codes HTTP explicites
// - Extension : récupérer AuthUser injecté par le middleware (RBAC)

// rand : permet de générer du hasard "cryptographiquement sûr"
use rand::{rngs::OsRng, RngCore};

// base64 : pour transformer des bytes random en string copiable (URL-safe)
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

// argon2 : hash sécurisé (comme pour un mot de passe)
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};

// ─────────────────────────────────────────────────────────────
// Imports Axum
// ─────────────────────────────────────────────────────────────
use axum::{
    Json,
    extract::{State, Path, Query},
    http::StatusCode,
    Extension,
};

// UUID pour identifier de manière unique les utilisateurs
use uuid::Uuid;

// Accès à la base de données (pool PostgreSQL)
use crate::db::AppState;

// Modèle User + enums associés (rôle et statut)
use crate::api::models::user::{UserRole, User, UserStatus};

// Auth (RBAC)
use crate::api::auth::{AuthUser, require_role};

//
// ─────────────────────────────────────────────────────────────
// POST /users
// Objectif : créer un utilisateur BindKey
// Sécurité :
// - ENROLLER / ADMIN uniquement
// - Génération d’un recovery code réel
// - Stockage du HASH uniquement
// - Le code n’est affiché qu’UNE FOIS
// ─────────────────────────────────────────────────────────────
//

#[derive(serde::Deserialize)]
pub struct CreateUserRequest {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
}

#[derive(serde::Serialize)]
pub struct CreateUserResponse {
    pub id: Uuid,
    pub message: String,

    // affiché UNE SEULE FOIS (mode onboarding)
    pub recovery_code: String,
}

pub async fn create_user(
    Extension(auth): Extension<AuthUser>, // utilisateur authentifié
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<CreateUserResponse>, (StatusCode, String)> {

    // ─────────────────────────────────────────
    // RBAC : ENROLLER ou ADMIN uniquement
    // ─────────────────────────────────────────
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let user_id = Uuid::new_v4();

    // ─────────────────────────────────────────
    // 1️ Génération du recovery code (16 bytes random)
    // ─────────────────────────────────────────
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);

    // Ex: "F8k2P7...Xw"
    let recovery_code = URL_SAFE_NO_PAD.encode(raw);

    // ─────────────────────────────────────────
    // 2️ Hash Argon2 du recovery code
    // ─────────────────────────────────────────
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let recovery_code_hash = argon2
        .hash_password(recovery_code.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Hash error: {e}")))?
        .to_string();

    // ─────────────────────────────────────────
    // 3️ Insertion DB
    // - role fixé côté serveur (anti-spoof)
    // - status ACTIVE par défaut
    // ─────────────────────────────────────────
    let query = r#"
        INSERT INTO users (
            id,
            first_name,
            last_name,
            email,
            job_title,
            role,
            status,
            recovery_code_hash
        )
        VALUES ($1, $2, $3, $4, NULL, 'USER', 'ACTIVE', $5)
    "#;

    sqlx::query(query)
        .bind(user_id)
        .bind(&payload.first_name)
        .bind(&payload.last_name)
        .bind(&payload.email)
        .bind(recovery_code_hash)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // ─────────────────────────────────────────
    // 4️ Réponse
    // ─────────────────────────────────────────
    Ok(Json(CreateUserResponse {
        id: user_id,
        message: "Utilisateur créé avec succès".into(),
        recovery_code, // ⚠️ UNE seule fois
    }))
}

//
// ─────────────────────────────────────────────────────────────
// GET /users/:id
// RBAC :
// - USER → son propre profil
// - ENROLLER / ADMIN → tous
// ─────────────────────────────────────────────────────────────
//

pub async fn get_user_by_id(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<User>, (StatusCode, String)> {

    let is_self = auth.user_id == user_id;
    let can_read_any = require_role(&auth.role, &UserRole::ENROLLER);

    if !is_self && !can_read_any {
        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "User not found".into()))?;

    Ok(Json(user))
}

//
// ─────────────────────────────────────────────────────────────
// GET /users?email=...
// RBAC : ENROLLER / ADMIN uniquement
// ─────────────────────────────────────────────────────────────
//

#[derive(serde::Deserialize)]
pub struct UserEmailQuery {
    pub email: String,
}

pub async fn get_user_by_email(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Query(q): Query<UserEmailQuery>,
) -> Result<Json<User>, (StatusCode, String)> {

    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE email = $1"
    )
    .bind(&q.email)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "User not found".into()))?;

    Ok(Json(user))
}

//
// ─────────────────────────────────────────────────────────────
// PATCH /users/:id/status
// RBAC : ENROLLER / ADMIN
// ─────────────────────────────────────────────────────────────
//

#[derive(serde::Deserialize)]
pub struct UpdateUserStatusRequest {
    pub status: UserStatus,
}

pub async fn update_user_status(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(payload): Json<UpdateUserStatusRequest>,
) -> Result<StatusCode, (StatusCode, String)> {

    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let res = sqlx::query(
        "UPDATE users
         SET status = $1, updated_at = now()
         WHERE id = $2"
    )
    .bind(payload.status)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "User not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}
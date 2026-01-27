// src/api/handlers/user_handler.rs
//
// Endpoints couverts (selon ton fichier actuel) :
//   - POST   /users
//   - GET    /users/:id
//   - GET    /users?email=...
//   - PATCH  /users/:id/status
//
// Sécurité :
//   - ENROLLER/ADMIN requis pour create + search + status update
//   - USER peut lire son profil
//
// Audit :
//   - USER_CREATE
//   - USER_PASSWORD_SET (si password fourni au create)
//   - USER_ENABLE / USER_DISABLE

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};

use uuid::Uuid;

use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::{User, UserRole, UserStatus};
use crate::db::AppState;

// Recovery code (random + base64 url safe)
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

// Argon2 hashing (pour recovery_code et password)
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};

// ✅ Audit helper
use crate::api::audit::{AuditSeverity, write_audit_log};

//
// ─────────────────────────────────────────────────────────────
// POST /users
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct CreateUserRequest {
    pub first_name: String,
    pub last_name: String,
    pub email: String,

    // si tu veux garder password_hash : on accepte un password EN CLAIR,
    // et on stocke SON HASH (argon2) en DB (jamais le password en clair)
    pub password: Option<String>,
}

#[derive(serde::Serialize)]
pub struct CreateUserResponse {
    pub id: Uuid,
    pub message: String,
    pub recovery_code: String, // affiché une seule fois
}

pub async fn create_user(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<CreateUserResponse>, (StatusCode, String)> {
    // RBAC : ENROLLER/ADMIN
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let user_id = Uuid::new_v4();

    // 1) Générer recovery_code
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    let recovery_code = URL_SAFE_NO_PAD.encode(raw);

    // 2) Hash recovery_code (argon2)
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let recovery_code_hash = argon2
        .hash_password(recovery_code.as_bytes(), &salt)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Hash error: {e}"),
            )
        })?
        .to_string();

    // 3) Si password fourni => hash password (argon2) et stocker password_hash
    let password_hash: Option<String> = if let Some(pwd) = &payload.password {
        let salt = SaltString::generate(&mut OsRng);
        Some(
            argon2
                .hash_password(pwd.as_bytes(), &salt)
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Password hash error: {e}"),
                    )
                })?
                .to_string(),
        )
    } else {
        None
    };

    // 4) INSERT user
    // Note: role fixé côté serveur (anti-spoof) + status ACTIVE
    let query = r#"
        INSERT INTO users (
            id, first_name, last_name, email, job_title, role, status,
            recovery_code_hash, password_hash
        )
        VALUES ($1, $2, $3, $4, NULL, 'USER', 'ACTIVE', $5, $6)
    "#;

    sqlx::query(query)
        .bind(user_id)
        .bind(&payload.first_name)
        .bind(&payload.last_name)
        .bind(&payload.email)
        .bind(recovery_code_hash)
        .bind(password_hash.clone())
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // ✅ Audit : USER_CREATE (après INSERT OK)
    let _ = write_audit_log(
        &state,
        Some(auth.user_id), // acteur
        None,
        "USER_CREATE",
        Some(format!("created_user_id={user_id} email={}", payload.email)),
        AuditSeverity::INFO,
    )
    .await;

    // ✅ Audit : USER_PASSWORD_SET (si password fourni)
    if password_hash.is_some() {
        let _ = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "USER_PASSWORD_SET",
            Some(format!(
                "password set at create for user_id={user_id} email={}",
                payload.email
            )),
            AuditSeverity::INFO,
        )
        .await;
    }

    Ok(Json(CreateUserResponse {
        id: user_id,
        message: "Utilisateur créé avec succès".into(),
        recovery_code,
    }))
}

//
// ─────────────────────────────────────────────────────────────
// GET /users/:id
// ─────────────────────────────────────────────────────────────

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

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "User not found".into()))?;

    Ok(Json(user))
}

//
// ─────────────────────────────────────────────────────────────
// GET /users?email=...
// ─────────────────────────────────────────────────────────────

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

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(&q.email)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "User not found".into()))?;

    Ok(Json(user))
}

//
// ─────────────────────────────────────────────────────────────
// PATCH /users/:id/status
// ─────────────────────────────────────────────────────────────

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
        r#"
        UPDATE users
        SET status = $1, updated_at = now()
        WHERE id = $2
        "#,
    )
    .bind(payload.status) // UserStatus doit être sqlx-compatible (déjà chez toi)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "User not found".into()));
    }

    // ✅ Audit : USER_ENABLE / USER_DISABLE (après UPDATE OK)
    let action = match payload.status {
        UserStatus::ACTIVE => "USER_ENABLE",
        UserStatus::DISABLED => "USER_DISABLE",
    };

    let _ = write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        action,
        Some(format!(
            "target_user_id={user_id} status={:?}",
            payload.status
        )),
        AuditSeverity::WARNING,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

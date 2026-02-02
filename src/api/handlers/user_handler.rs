use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};

use uuid::Uuid;

use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::{User, UserRole, UserStatus};
use crate::db::AppState;

// Crypto
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

// Middleware crypto
use crate::api::middleware;

// Audit
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
    pub password: Option<String>, // password EN CLAIR
}

#[derive(serde::Serialize)]
pub struct CreateUserResponse {
    pub id: Uuid,
    pub message: String,
    pub recovery_code: String, // affiché UNE seule fois
}

pub async fn create_user(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<CreateUserResponse>, (StatusCode, String)> {
    // RBAC
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let user_id = Uuid::new_v4();

    // ── Recovery code (random + hash)
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    let recovery_code = URL_SAFE_NO_PAD.encode(raw);

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);

    let recovery_code_hash = argon2
        .hash_password(recovery_code.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();

    // ── Password (optionnel)
    let password_hash_encrypted: Option<String> = if let Some(password) = &payload.password {
        let argon2_hash = middleware::hachage_argon2::hasher_mot_de_passe(password);
        Some(middleware::aes_chiffrement::chiffrer_aes(&argon2_hash))
    } else {
        None
    };

    // ── INSERT user
    sqlx::query(
        r#"
        INSERT INTO users (
            id, first_name, last_name, email,
            role, status,
            password_hash, recovery_code_hash,
            created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4,
            'USER', 'ACTIVE',
            $5, $6,
            now(), now()
        )
        "#,
    )
    .bind(user_id)
    .bind(&payload.first_name)
    .bind(&payload.last_name)
    .bind(&payload.email)
    .bind(password_hash_encrypted)
    .bind(recovery_code_hash)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // ── Audit
    let _ = write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "USER_CREATE",
        Some(format!("created_user_id={user_id} email={}", payload.email)),
        AuditSeverity::INFO,
    )
    .await;

    if payload.password.is_some() {
        let _ = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "USER_PASSWORD_SET",
            Some(format!("user_id={user_id}")),
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
    .bind(payload.status)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "User not found".into()));
    }

    let action = match payload.status {
        UserStatus::ACTIVE => "USER_ENABLE",
        UserStatus::DISABLED => "USER_DISABLE",
    };

    let _ = write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        action,
        Some(format!("target_user_id={user_id}")),
        AuditSeverity::WARNING,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

//
// ─────────────────────────────────────────────────────────────
// GET /admin/users (accessible ADMIN uniquement)
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ListUsersQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// Réponse "safe" pour l'UI (pas de password_hash, pas de recovery_code_hash, etc.)
#[derive(serde::Serialize, sqlx::FromRow)]
pub struct UserListItem {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub role: String,   // si en DB c'est TEXT/ENUM, String marche
    pub status: String, // idem
}

pub async fn list_users(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Query(q): Query<ListUsersQuery>,
) -> Result<Json<Vec<UserListItem>>, (StatusCode, String)> {
    // ✅ Admin only
    if !require_role(&auth.role, &UserRole::ADMIN) {
        return Err((StatusCode::FORBIDDEN, "ADMIN required".into()));
    }

    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0).max(0);

    let users = sqlx::query_as::<_, UserListItem>(
        r#"
        SELECT id, first_name, last_name, email, role::text as role, status::text as status
        FROM users
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(users))
}

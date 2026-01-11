// Import Axum :
// - Json : pour gérer les corps de requêtes/réponses JSON
// - State : pour accéder à l’état global de l’application (DB)
// - Path : pour lire les paramètres dans l’URL (/users/:id)
// - Query : pour lire les paramètres de requête (?email=...)
// - StatusCode : pour renvoyer des codes HTTP explicites
// - Extension : récupérer AuthUser injecté par le middleware (RBAC)
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
// Objectif : créer un nouvel utilisateur BindKey
// RBAC : seul ENROLLER / ADMIN peut créer des utilisateurs
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
}

pub async fn create_user(
    Extension(auth): Extension<AuthUser>, //  utilisateur authentifié (middleware)
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<CreateUserResponse>, String> {

    // RBAC : ENROLLER ou ADMIN
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err("ENROLLER/ADMIN required".into());
    }

    let user_id = Uuid::new_v4();
    let role = UserRole::USER;
    let recovery_code_hash = "TODO_HASH".to_string();

    let query = r#"
        INSERT INTO users (
            id, first_name, last_name, email,
            job_title, role, status, recovery_code_hash
        )
        VALUES ($1, $2, $3, $4, NULL, $5, 'ACTIVE', $6)
    "#;

    sqlx::query(query)
        .bind(user_id)
        .bind(&payload.first_name)
        .bind(&payload.last_name)
        .bind(&payload.email)
        .bind(role)
        .bind(recovery_code_hash)
        .execute(&state.db)
        .await
        .map_err(|e| format!("Erreur SQL: {}", e))?;

    Ok(Json(CreateUserResponse {
        id: user_id,
        message: "Utilisateur créé avec succès".into(),
    }))
}

//
// ─────────────────────────────────────────────────────────────
// GET /users/:id
// Objectif : récupérer un utilisateur par son ID
//  RBAC :
// - USER peut lire uniquement son propre profil
// - ENROLLER/ADMIN peuvent lire n’importe quel profil
// ─────────────────────────────────────────────────────────────
//

pub async fn get_user_by_id(
    Extension(auth): Extension<AuthUser>, // ✅ utilisateur authentifié
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<User>, (StatusCode, String)> {

    // USER : accès uniquement à lui-même
    // ENROLLER/ADMIN : accès à tous
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
    .map_err(|_| (
        StatusCode::NOT_FOUND,
        "User not found".into()
    ))?;

    Ok(Json(user))
}

//
// ─────────────────────────────────────────────────────────────
// GET /users?email=...
// Objectif : retrouver un utilisateur via son email
// RBAC : ENROLLER/ADMIN uniquement (évite l’énumération d’emails)
// ─────────────────────────────────────────────────────────────
//

#[derive(serde::Deserialize)]
pub struct UserEmailQuery {
    pub email: String,
}

pub async fn get_user_by_email(
    Extension(auth): Extension<AuthUser>, //  utilisateur authentifié
    State(state): State<AppState>,
    Query(q): Query<UserEmailQuery>,
) -> Result<Json<User>, (StatusCode, String)> {

    // RBAC : ENROLLER ou ADMIN
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE email = $1"
    )
    .bind(&q.email)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (
        StatusCode::NOT_FOUND,
        "User not found".into()
    ))?;

    Ok(Json(user))
}

//
// ─────────────────────────────────────────────────────────────
// PATCH /users/:id/status
// Objectif : activer / désactiver un compte utilisateur
// RBAC : ENROLLER / ADMIN
// ─────────────────────────────────────────────────────────────
//

#[derive(serde::Deserialize)]
pub struct UpdateUserStatusRequest {
    pub status: UserStatus, // ACTIVE | DISABLED
}

pub async fn update_user_status(
    Extension(auth): Extension<AuthUser>, // utilisateur authentifié
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(payload): Json<UpdateUserStatusRequest>,
) -> Result<StatusCode, (StatusCode, String)> {

    // RBAC : ENROLLER ou ADMIN
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    let res = sqlx::query(
        "UPDATE users
         SET status = $1,
             updated_at = now()
         WHERE id = $2"
    )
    .bind(payload.status)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Erreur SQL: {}", e)
    ))?;

    if res.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "User not found".into()
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

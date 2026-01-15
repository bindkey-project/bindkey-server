// Import Axum :
// - Json : pour gérer les corps de requêtes/réponses JSON
// - State : pour accéder à l’état global de l’application (DB)
// - Path : pour lire les paramètres dans l’URL (/users/:id)
// - Query : pour lire les paramètres de requête (?email=...)
// - StatusCode : pour renvoyer des codes HTTP explicites
use axum::{
    Json,
    extract::{State, Path, Query},
    http::StatusCode,
};

// UUID pour identifier de manière unique les utilisateurs
use uuid::Uuid;

// Accès à la base de données (pool PostgreSQL)
use crate::db::AppState;

// Modèle User + enums associés (rôle et statut)
use crate::api::models::user::{UserRole, User, UserStatus};

//
// ─────────────────────────────────────────────────────────────
// POST /users
// Objectif : créer un nouvel utilisateur BindKey
// ─────────────────────────────────────────────────────────────
//

/// Données reçues lors de la création d’un utilisateur
#[derive(serde::Deserialize)]
pub struct CreateUserRequest {
    pub first_name: String,  // Prénom
    pub last_name: String,   // Nom
    pub email: String,   
    pub role: UserRole,   
}

/// Réponse envoyée après création
#[derive(serde::Serialize)]
pub struct CreateUserResponse {
    pub id: Uuid,            // UUID du nouvel utilisateur
    pub message: String,
}

pub async fn create_user(
    State(state): State<AppState>,          // Accès DB
    Json(payload): Json<CreateUserRequest>, // Données envoyées par le client
) -> Result<Json<CreateUserResponse>, String> {

    // 1️⃣ Génération d’un UUID unique pour l’utilisateur
    let user_id = Uuid::new_v4();

    // 2️⃣ Valeurs par défaut
                  // Rôle standard
    let recovery_code_hash = "TODO_HASH".to_string();
    // ⚠️ En production : générer et hasher un vrai code de récupération

    // 3️⃣ Insertion en base de données
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
        VALUES ($1, $2, $3, $4, NULL, $5, 'ACTIVE', $6)
    "#;

    sqlx::query(query)
        .bind(user_id)
        .bind(&payload.first_name)
        .bind(&payload.last_name)
        .bind(&payload.email)
        .bind(&payload.role)
        .bind(recovery_code_hash)
        .execute(&state.db)
        .await
        .map_err(|e| format!("Erreur SQL: {}", e))?;

    // 4️⃣ Réponse au client
    Ok(Json(CreateUserResponse {
        id: user_id,
        message: "Utilisateur créé avec succès".into(),
    }))
}

//
// ─────────────────────────────────────────────────────────────
// GET /users/:id
// Objectif : récupérer un utilisateur par son ID
// ─────────────────────────────────────────────────────────────
//

pub async fn get_user_by_id(
    State(state): State<AppState>,   // Accès DB
    Path(user_id): Path<Uuid>,       // ID de l’utilisateur depuis l’URL
) -> Result<Json<User>, (StatusCode, String)> {

    // Recherche de l’utilisateur par ID
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
// (utile pour l’enrôlement BindKey)
// ─────────────────────────────────────────────────────────────
//

/// Paramètre de requête ?email=...
#[derive(serde::Deserialize)]
pub struct UserEmailQuery {
    pub email: String,
}

pub async fn get_user_by_email(
    State(state): State<AppState>,     // Accès DB
    Query(q): Query<UserEmailQuery>,   // Paramètre email depuis l’URL
) -> Result<Json<User>, (StatusCode, String)> {

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
// (ADMIN / ENROLLER)
// ─────────────────────────────────────────────────────────────
//

/// Données envoyées pour modifier le statut d’un utilisateur
#[derive(serde::Deserialize)]
pub struct UpdateUserStatusRequest {
    pub status: UserStatus, // ACTIVE | DISABLED
}

pub async fn update_user_status(
    State(state): State<AppState>,     // Accès DB
    Path(user_id): Path<Uuid>,         // ID de l’utilisateur
    Json(payload): Json<UpdateUserStatusRequest>,
) -> Result<StatusCode, (StatusCode, String)> {

    // Mise à jour du statut + timestamp updated_at
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

    // Si aucun utilisateur modifié → ID invalide
    if res.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "User not found".into()
        ));
    }

    // Succès sans contenu
    Ok(StatusCode::NO_CONTENT)
}

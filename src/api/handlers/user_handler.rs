// Import des outils Axum pour gérer les requêtes JSON et l'état partagé
use axum::{Json, extract::State};
// UUID pour générer des identifiants uniques
use uuid::Uuid;

// Accès à la connexion PostgreSQL via AppState
use crate::db::AppState;
// Import de l’ENUM UserRole (utilisé pour définir le rôle par défaut)
use crate::api::models::user::UserRole;

//
// Structure représentant les données reçues lors de la création d’un utilisateur
//
#[derive(serde::Deserialize)]
pub struct CreateUserRequest {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
}

//
// Structure renvoyée au client après création
//
#[derive(serde::Serialize)]
pub struct CreateUserResponse {
    pub id: Uuid,
    pub message: String,
}

//
// Handler HTTP POST /users
// Reçoit un JSON → crée un utilisateur → renvoie un JSON
//
pub async fn create_user(
    State(state): State<AppState>,              // Récupère la connexion DB depuis l’état global
    Json(payload): Json<CreateUserRequest>,     // Désérialise automatiquement le JSON reçu
) -> Result<Json<CreateUserResponse>, String> {

    // 1️⃣ Génération d’un UUID unique pour l’utilisateur
    let user_id = Uuid::new_v4();

    // 2️⃣ Définition des valeurs par défaut (non fournies par le client)
    let role = UserRole::USER;                   // Rôle par défaut
    let recovery_code_hash: String = "TODO_HASH".to_string(); // À remplacer par un vrai hash plus tard

    // 3️⃣ Requête SQL correspondant exactement à la structure de la table "users"
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

    // 4️⃣ Exécution SQL (chaque bind correspond à une valeur $1 → $6)
    sqlx::query(query)
        .bind(user_id)               // $1 : UUID
        .bind(&payload.first_name)   // $2 : prénom
        .bind(&payload.last_name)    // $3 : nom
        .bind(&payload.email)        // $4 : email
        .bind(role)                  // $5 : rôle (ENUM)
        .bind(recovery_code_hash)    // $6 : hash du code de recovery
        .execute(&state.db)
        .await
        .map_err(|e| format!("Erreur SQL: {}", e))?;

    // 5️⃣ Réponse envoyée au client
    Ok(Json(CreateUserResponse {
        id: user_id,
        message: "Utilisateur créé avec succès".into(),
    }))
}

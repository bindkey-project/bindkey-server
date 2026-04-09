// src/api/routes/user_routes_module.rs
// -----------------------------------------------------------------------------
// Déclaration des routes HTTP liées aux utilisateurs.
// Chaque route est associée à un handler défini dans user_handler.rs
// -----------------------------------------------------------------------------

use axum::{
    Router,
    routing::{get, patch, post},
};

// Import des handlers utilisateurs
use crate::api::handlers::user_handler::{
    create_user,           // créer un utilisateur
    get_user_by_email,     // récupérer un user via email
    get_user_by_id,        // récupérer un user via UUID
    update_user_status,    // activer / désactiver un user
    register_user_with_key,// enrôlement complet user + bindkey
    delete_user,           // supprimer un utilisateur
    list_users,            // liste admin des utilisateurs
};

// Fonction appelée par api/mod.rs pour enregistrer les routes
pub fn user_routes() -> Router<crate::db::AppState> {
    Router::new()

        // POST /users -> création d’un utilisateur
        .route("/users", post(create_user))

        // GET /users/:id -> récupérer un utilisateur
        // DELETE /users/:id -> supprimer un utilisateur
        .route("/users/:id", get(get_user_by_id).delete(delete_user))

        // GET /users?email=... -> rechercher par email
        .route("/users", get(get_user_by_email))

        // PATCH /users/:id/status -> modifier le statut
        .route("/users/:id/status", patch(update_user_status))

        // GET /admin/users -> liste des utilisateurs (admin)
        .route("/admin/users", get(list_users))

        // POST /auth/register -> enrôlement complet user + bindkey
        .route("/auth/register", post(register_user_with_key))
}
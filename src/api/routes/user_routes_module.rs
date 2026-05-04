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
    admin_search_user,
    create_user,
    delete_user,
    get_user_by_email,
    get_user_by_id,
    list_users,
    register_user_with_key,
    search_user_by_email,
    update_user_status,
};

// Fonction appelée par api/mod.rs pour enregistrer les routes
pub fn user_routes() -> Router<crate::db::AppState> {
    Router::new()
        // POST /users -> création d’un utilisateur
        // GET /users?email=... -> rechercher par email (renvoie le User complet, ENROLLER+)
        .route("/users", post(create_user).get(get_user_by_email))

        // GET /users/search?email=... -> recherche minimale (first_name, last_name, email, role)
        // Accessible à tout utilisateur authentifié.
        .route("/users/search", get(search_user_by_email))

        // GET /users/:id -> récupérer un utilisateur
        .route("/users/:id", get(get_user_by_id))
        // PATCH /users/:id/status -> modifier le statut
        .route("/users/:id/status", patch(update_user_status))
        // GET /admin/users -> liste des utilisateurs (admin)
        .route("/admin/users", get(list_users))
        // GET /admin/users/search?email=...
        .route("/admin/users/search", get(admin_search_user))
        // DELETE /admin/users/:id
        .route("/admin/users/:id", axum::routing::delete(delete_user))
        // POST /auth/register -> enrôlement complet user + bindkey
        .route("/auth/register", post(register_user_with_key))
}

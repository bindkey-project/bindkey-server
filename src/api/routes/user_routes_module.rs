use crate::api::handlers::user_handler::list_users;

// ─────────────────────────────────────────────────────────────
// user_routes_module.rs
// Déclare toutes les routes /users et les associe aux handlers
// ─────────────────────────────────────────────────────────────

use axum::{
    Router,
    routing::{get, patch, post},
};

// On importe explicitement les handlers Users
use crate::api::handlers::user_handler::{
    create_user, get_user_by_email, get_user_by_id, update_user_status,register_user_with_key,
};

// Fonction appelée depuis api/mod.rs via .merge(user_routes())
pub fn user_routes() -> Router<crate::db::AppState> {
    Router::new()
        // POST /users : créer un user
        .route("/users", post(create_user))
        // GET /users/:id : récupérer un user par UUID
        .route("/users/:id", get(get_user_by_id))
        // GET /users?email=... : chercher un user par email
        .route("/users", get(get_user_by_email))
        // PATCH /users/:id/status : activer/désactiver
        .route("/users/:id/status", patch(update_user_status))
        // GET /admin/users
        .route("/admin/users", get(list_users))
        .route("/auth/register", post(register_user_with_key))
}

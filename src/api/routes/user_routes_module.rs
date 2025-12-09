// Gestion des routes liées aux utilisateurs (User)

use axum::{Router, routing::post};
use crate::db::AppState;
use crate::api::handlers::user_handler::create_user;

// Déclare toutes les routes du module "users"
pub fn user_routes() -> Router<AppState> {
    Router::new()
        .route("/users", post(create_user)) // Endpoint POST /users
}

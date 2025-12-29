// Déclaration des sous-modules de `api`
pub mod models;
pub mod handlers;
pub mod routes;
use axum::{Router, routing::get, extract::State};
use crate::db::AppState;
use crate::api::routes::{user_routes, bindkey_routes};


// Construit le routeur principal de l'API (BindKey)
pub fn create_app(state: AppState) -> Router {
    Router::new()
        .merge(user_routes())                // Ajoute les routes /users
        .merge(bindkey_routes())
        .route("/health", get(health_check)) // Endpoint simple pour vérifier l'état du serveur
        .with_state(state)                   // Partage AppState (connexion DB) avec tous les handlers
}

// Route GET /health → indique que l'API fonctionne
async fn health_check(
    State(_state): State<AppState>,          // Le state est reçu mais pas utilisé ici
) -> &'static str {
    "OK"
}

// ─────────────────────────────────────────────────────────────
// Déclaration des sous-modules de l’API
// ─────────────────────────────────────────────────────────────
pub mod audit;
pub mod auth;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod routes;

use axum::{Router, extract::State, routing::get};

// État global de l’application
use crate::db::AppState;
// Import correct du middleware
use crate::api::middleware::auth_middleware::auth_middleware;

// Import des différents groupes de routes
use crate::api::routes::{
    bindkey_routes, mount_routes, permission_routes, session_routes, user_routes,
    volume_routes,
};

// ─────────────────────────────────────────────────────────────
// Construction du routeur principal de l’API BindKey
// ─────────────────────────────────────────────────────────────
pub fn create_app(state: AppState) -> Router {
    // 1. Routes publiques (Toujours accessibles)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .merge(session_routes());

    // 2. Routes protégées
    let protected_routes = Router::new()
        .merge(user_routes())
        .merge(bindkey_routes())
        .merge(volume_routes())
        .merge(mount_routes())
        .merge(permission_routes());

    // 3. Application CONDITIONNELLE du middleware
    // 'not(test)' signifie : inclus ce code pour 'cargo run' mais IGNORE-LE pour 'cargo test'
    #[cfg(not(test))]
    let protected_routes = protected_routes.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth_middleware, // Utilise l'import simplifié
    ));

    // 4. Fusion finale
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
}

// GET /health
async fn health_check(State(_state): State<AppState>) -> &'static str {
    "OK"
}
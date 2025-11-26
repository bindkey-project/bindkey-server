use axum::{
    routing::get,
    Router,
};

/// Crée et retourne le routeur principal de l’API BindKey.
///
/// Pour l’instant, il ne contient qu’une seule route :
///   - GET /health  → renvoie "OK"
pub fn create_app() -> Router {
    Router::new()
        .route("/health", get(health_check))
}

/// Handler pour la route GET /health.
/// Cette fonction est appelée quand un client fait une requête HTTP GET
/// sur /health.
async fn health_check() -> &'static str {
    "OK"
}

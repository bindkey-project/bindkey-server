use axum::{
    extract::State,
    routing::get,
    Router,
};

use crate::db::AppState; // ⬅️ on importe le type AppState

/// Crée le router principal de l'API BindKey.
///
/// On lui passe un `AppState` qui contient la connexion DB.
/// Axum va cloner ce state pour chaque handler.
pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .with_state(state) // ⬅️ on associe le state à toutes les routes
}

/// Handler pour GET /health.
/// Ici on montre comment récupérer le state, même si on ne l'utilise pas encore.
async fn health_check(
    State(_state): State<AppState>, // ⬅️ `_state` = on dit à Rust "je sais qu'il existe"
) -> &'static str {
    "OK"
}

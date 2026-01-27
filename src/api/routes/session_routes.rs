// Axum Router : permet de définir les routes HTTP
// post : méthode utilisée pour créer, renouveler et fermer des sessions
use axum::{Router, routing::post};

// Import des handlers de gestion des sessions
// Ces handlers implémentent la logique d’authentification BindKey
use crate::api::handlers::session_handler::{
    login_session,   // POST /sessions/login
    logout_session,  // POST /sessions/logout
    refresh_session, // POST /sessions/refresh
};

//
// ─────────────────────────────────────────────────────────────
// Déclaration des routes Sessions / Tokens
// ─────────────────────────────────────────────────────────────
//
// Ces routes sont au cœur de la sécurité BindKey :
// - elles créent des sessions temporaires
// - elles limitent l’accès dans le temps (offline window)
// - elles permettent une révocation immédiate
//

pub fn session_routes() -> Router<crate::db::AppState> {
    Router::new()
        // ─────────────────────────────────────────
        // POST /sessions/login
        // Création d’une session sécurisée BindKey
        // → génération de tokens serveur et local
        // ─────────────────────────────────────────
        .route("/sessions/login", post(login_session))
        // ─────────────────────────────────────────
        // POST /sessions/refresh
        // Renouvelle une session existante
        // → rotation des tokens + nouvelle expiration
        // ─────────────────────────────────────────
        .route("/sessions/refresh", post(refresh_session))
        // ─────────────────────────────────────────
        // POST /sessions/logout
        // Suppression explicite d’une session
        // → révocation immédiate de l’accès
        // ─────────────────────────────────────────
        .route("/sessions/logout", post(logout_session))
}

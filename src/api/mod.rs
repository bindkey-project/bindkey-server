// ─────────────────────────────────────────────────────────────
// Déclaration des sous-modules de l’API
// ─────────────────────────────────────────────────────────────
//
// - models   : structures représentant les tables PostgreSQL
// - handlers : logique métier (fonctions appelées par les routes)
// - routes   : déclaration et organisation des endpoints HTTP
// - auth     : logique d’authentification (extractor, rôles)
// - middleware : middlewares globaux (auth, logs, etc.)
//
pub mod models;
pub mod handlers;
pub mod routes;
pub mod auth;
pub mod middleware;

// Import Axum :
// - Router : permet de construire le routeur principal
// - get    : méthode HTTP GET
// - State  : extraction de l’état global (AppState)
// - from_fn_with_state : middleware avec accès à l’état global
use axum::{Router, routing::get, extract::State};
use axum::middleware::from_fn_with_state;

// État global de l’application (connexion DB, config, etc.)
use crate::db::AppState;

use crate::api::middleware::auth_middleware::auth_middleware;

// Import des différents groupes de routes
use crate::api::routes::{
    user_routes,        // Gestion des utilisateurs
    bindkey_routes,     // Gestion des BindKeys
    disk_routes,        // Gestion des disques physiques
    volume_routes,      // Gestion des volumes chiffrés
    permission_routes,  // Partage et permissions
    session_routes,     // Sessions et tokens
    mount_routes,       // Montage / démontage des volumes
};

//
// ─────────────────────────────────────────────────────────────
// Construction du routeur principal de l’API BindKey
// ─────────────────────────────────────────────────────────────
//
// Cette fonction assemble toutes les routes de l’application
// en un seul Router Axum, partagé avec un état global (AppState).
//
pub fn create_app(state: AppState) -> Router {
    // ─────────────────────────────────────────
    // Routes publiques (pas d’auth requise)
    // ─────────────────────────────────────────
    let public = Router::new()
        

        // Routes de gestion des sessions
        // (login, refresh, logout)
        .merge(session_routes())

        // Endpoint de supervision
        // GET /health
        .route("/health", get(health_check));

    // ─────────────────────────────────────────
    // Routes protégées (Bearer token requis)
    // ─────────────────────────────────────────
    let protected = Router::new()
        // Gestion des BindKeys
        .merge(bindkey_routes())

        // Gestion des disques physiques
        .merge(disk_routes())

        // Gestion des volumes chiffrés
        .merge(volume_routes())

        // Partage et permissions
        .merge(permission_routes())

        // Montage / démontage des volumes
        .merge(mount_routes())

        // Routes liées aux utilisateurs
        // (/users, /users/:id, etc.)
        .merge(user_routes())
        
        // Middleware global d’authentification
        // → valide le Bearer token avant d’atteindre les handlers
        .layer(from_fn_with_state(state.clone(), auth_middleware));

    // Assemblage final de l’API
    Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state)
}

//
// ─────────────────────────────────────────────────────────────
// GET /health
// Objectif : vérifier que l’API est opérationnelle
// ─────────────────────────────────────────────────────────────
//
async fn health_check(State(_state): State<AppState>) -> &'static str {
    "OK"
}

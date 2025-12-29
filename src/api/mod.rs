// ─────────────────────────────────────────────────────────────
// Déclaration des sous-modules de l’API
// ─────────────────────────────────────────────────────────────
//
// - models   : structures représentant les tables PostgreSQL
// - handlers : logique métier (fonctions appelées par les routes)
// - routes   : déclaration et organisation des endpoints HTTP
//
pub mod models;
pub mod handlers;
pub mod routes;

// Import Axum :
// - Router : permet de construire le routeur principal
// - get    : méthode HTTP GET
// - State  : extraction de l’état global (AppState)
use axum::{Router, routing::get, extract::State};

// État global de l’application (connexion DB, config, etc.)
use crate::db::AppState;

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
    Router::new()

        // ─────────────────────────────────────────
        // Routes liées aux utilisateurs
        // (/users, /users/:id, etc.)
        // ─────────────────────────────────────────
        .merge(user_routes())

        // ─────────────────────────────────────────
        // Routes liées aux BindKeys
        // (enrôlement, statut, reset)
        // ─────────────────────────────────────────
        .merge(bindkey_routes())

        // ─────────────────────────────────────────
        // Routes liées aux disques physiques
        // ─────────────────────────────────────────
        .merge(disk_routes())

        // ─────────────────────────────────────────
        // Routes liées aux volumes chiffrés
        // ─────────────────────────────────────────
        .merge(volume_routes())

        // ─────────────────────────────────────────
        // Routes de partage et permissions
        // ─────────────────────────────────────────
        .merge(permission_routes())

        // ─────────────────────────────────────────
        // Routes de gestion des sessions (login, refresh, logout)
        // ─────────────────────────────────────────
        .merge(session_routes())

        // ─────────────────────────────────────────
        // Routes de montage / démontage des volumes
        // ─────────────────────────────────────────
        .merge(mount_routes())

        // ─────────────────────────────────────────
        // GET /health
        // Endpoint de supervision (healthcheck)
        // ─────────────────────────────────────────
        .route("/health", get(health_check))

        // ─────────────────────────────────────────
        // Partage de l’état global (DB) à tous les handlers
        // ─────────────────────────────────────────
        .with_state(state)
}

//
// ─────────────────────────────────────────────────────────────
// GET /health
// Objectif : vérifier que l’API est opérationnelle
// ─────────────────────────────────────────────────────────────
//

async fn health_check(
    State(_state): State<AppState>, // L’état est injecté mais non utilisé ici
) -> &'static str {
    "OK"
}

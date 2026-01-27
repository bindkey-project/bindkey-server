// Router Axum : permet de déclarer les routes HTTP
// post / get / patch : méthodes HTTP utilisées par l’API
use axum::{
    Router,
    routing::{get, patch, post},
};

// Import des handlers BindKey
// Chaque handler contient la logique métier associée à la route
use crate::api::handlers::bindkey_handler::{
    enroll_bindkey,        // POST /bindkeys/enroll
    get_bindkey,           // GET  /bindkeys/:id
    get_user_bindkeys,     // GET  /users/:id/bindkeys
    reset_bindkey,         // POST /bindkeys/:id/reset
    update_bindkey_status, // PATCH /bindkeys/:id/status
};

//
// ─────────────────────────────────────────────────────────────
// Déclaration des routes BindKey
// ─────────────────────────────────────────────────────────────
//
// Ce routeur regroupe toutes les routes liées :
// - à l’enrôlement des BindKeys
// - à leur consultation
// - à leur cycle de vie (statut, reset)
//

pub fn bindkey_routes() -> Router<crate::db::AppState> {
    Router::new()
        // ─────────────────────────────────────────
        // POST /bindkeys/enroll
        // Associe une BindKey à un utilisateur
        // (enrôlement biométrique sécurisé)
        // ─────────────────────────────────────────
        .route("/bindkeys/enroll", post(enroll_bindkey))
        // ─────────────────────────────────────────
        // GET /bindkeys/:id
        // Récupère les informations d’une BindKey
        // ─────────────────────────────────────────
        .route("/bindkeys/:id", get(get_bindkey))
        // ─────────────────────────────────────────
        // GET /users/:id/bindkeys
        // Liste toutes les BindKeys appartenant à un utilisateur
        // ─────────────────────────────────────────
        .route("/users/:id/bindkeys", get(get_user_bindkeys))
        // ─────────────────────────────────────────
        // PATCH /bindkeys/:id/status
        // Met à jour l’état d’une BindKey :
        // ACTIVE | LOST | BROKEN | RESET
        // ─────────────────────────────────────────
        .route("/bindkeys/:id/status", patch(update_bindkey_status))
        // ─────────────────────────────────────────
        // POST /bindkeys/:id/reset
        // Trace une réinitialisation (audit sécurité)
        // ─────────────────────────────────────────
        .route("/bindkeys/:id/reset", post(reset_bindkey))
}

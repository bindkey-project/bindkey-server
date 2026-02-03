// src/api/routes/session_routes.rs
//
// Router Axum : regroupe toutes les routes liées aux sessions (auth)
//
// Endpoints :
//   - POST /sessions/login   -> crée une session temporaire + challenge
//   - POST /sessions/verify  -> vérifie la signature bindkey + génère tokens
//   - POST /sessions/refresh -> rotation des tokens + nouvelle expiration
//   - POST /sessions/logout  -> supprime/révoque la session
//
// Ces routes sont au cœur de la sécurité BindKey :
// - challenge-response (BindKey signe un challenge)
// - tokens serveur pour protéger les routes API
// - expiration + révocation immédiate
//

use axum::{Router, routing::post};

// Import unique et propre des handlers (pas de doublons)
use crate::api::handlers::session_handler::{
    login_session, logout_session, refresh_session, verify_session,test_session
};

use crate::db::AppState;

/// Déclare toutes les routes /sessions/...
pub fn session_routes() -> Router<AppState> {
    Router::new()
        // ─────────────────────────────────────────
        // POST /sessions/login
        // 1) Vérifie email/password
        // 2) Crée une session "pending"
        // 3) Retourne session_id + auth_challenge
        // ─────────────────────────────────────────
        .route("/sessions/login", post(login_session))
        // ─────────────────────────────────────────
        // POST /sessions/verify
        // 1) Vérifie signature Ed25519(challenge) avec la clé publique stockée
        // 2) Si OK : génère server_token + local_token
        // ─────────────────────────────────────────
        .route("/sessions/verify", post(verify_session))
        // ─────────────────────────────────────────
        // POST /sessions/refresh
        // Rotation des tokens et extension de la durée de vie
        // ─────────────────────────────────────────
        .route("/sessions/refresh", post(refresh_session))
        // ─────────────────────────────────────────
        // POST /sessions/logout
        // Révocation immédiate : suppression de la session
        // ─────────────────────────────────────────
        .route("/sessions/logout", post(logout_session))
        //─────────────────────────────────────────
        //POST /sessions/login
        // 1) Vérifie email/password
        // 2) Crée une session "pending
        //route pour tester 
        .route("/sessions/test", post(test_session))

}

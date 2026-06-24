// ─────────────────────────────────────────────────────────────
// Router Axum : permet de déclarer les routes HTTP
// - get    → lecture
// - post   → création / action
// - patch  → modification partielle
// ─────────────────────────────────────────────────────────────
use axum::{
    Router,
    routing::{get, patch, post},
};

// ─────────────────────────────────────────────────────────────
// Import des handlers BindKey
// Chaque handler contient la logique métier associée à la route
// ─────────────────────────────────────────────────────────────
use crate::api::handlers::bindkey_handler::{
    admin_update_bindkey_status_by_serial, // PATCH /admin/bindkeys/:serial_number/status
    enroll_bindkey,                        // POST  /bindkeys/enroll
    generate_certificate_for_bindkey,      // POST  /bindkeys/:id/certificate
    get_bindkey,                           // GET   /bindkeys/:id
    get_certificate_for_bindkey,           // GET   /bindkeys/:id/certificate
    get_user_bindkeys,                     // GET   /users/:id/bindkeys
    reset_bindkey,                         // POST  /bindkeys/:id/reset
    update_bindkey_status,                 // PATCH /bindkeys/:id/status
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
// - aux opérations administrateur
//

pub fn bindkey_routes() -> Router<crate::db::AppState> {
    Router::new()
        // ─────────────────────────────────────────
        // POST /bindkeys/enroll
        // Associe une BindKey à un utilisateur
        // → enrôlement biométrique sécurisé
        // ─────────────────────────────────────────
        .route("/bindkeys/enroll", post(enroll_bindkey))
        // ─────────────────────────────────────────
        // GET /bindkeys/:id
        // Récupère les informations d’une BindKey
        // via son UUID
        // ─────────────────────────────────────────
        .route("/bindkeys/:id", get(get_bindkey))
        // ─────────────────────────────────────────
        // GET /users/:id/bindkeys
        // Liste toutes les BindKeys d’un utilisateur
        // ─────────────────────────────────────────
        .route("/users/:id/bindkeys", get(get_user_bindkeys))
        // ─────────────────────────────────────────
        // PATCH /bindkeys/:id/status
        // Met à jour le statut d’une BindKey :
        // ACTIVE | LOST | BROKEN | RESET
        //
        // Accessible ENROLLER / ADMIN
        // ─────────────────────────────────────────
        .route("/bindkeys/:id/status", patch(update_bindkey_status))
        // ─────────────────────────────────────────
        // POST /bindkeys/:id/reset
        // Trace une réinitialisation :
        // - perte
        // - corruption
        // - effacement
        //
        // Important pour l’audit sécurité
        // ─────────────────────────────────────────
        .route("/bindkeys/:id/reset", post(reset_bindkey))
        // ─────────────────────────────────────────
        // PATCH /admin/bindkeys/:serial_number/status
        //
        // Route ADMIN :
        // Permet de modifier le statut d’une BindKey à partir de son identifiant matériel (serial_number)
        //
        // - serial_number côté API = colonne `sn` en base (SN ATECC608)
        //
        // Utilisé pour :
        // - déclarer une clé perdue
        // - désactiver une clé compromise
        // - réactiver une clé
        // ─────────────────────────────────────────
        .route(
            "/admin/bindkeys/:serial_number/status",
            patch(admin_update_bindkey_status_by_serial),
        )
        // ─────────────────────────────────────────
        // POST /bindkeys/:id/certificate
        // Génère un certificat X.509 signé pour cette BindKey.
        // Retourne le cert PEM + la clé privée PEM (une seule fois).
        // Accessible ENROLLER / ADMIN
        // ─────────────────────────────────────────
        .route(
            "/bindkeys/:id/certificate",
            post(generate_certificate_for_bindkey),
        )
        // ─────────────────────────────────────────
        // GET /bindkeys/:id/certificate
        // Retourne le certificat X.509 PEM déjà généré.
        // ─────────────────────────────────────────
        .route(
            "/bindkeys/:id/certificate",
            get(get_certificate_for_bindkey),
        )
}

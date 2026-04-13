// Axum Router : permet de définir les routes HTTP
use axum::{
    Router,
    routing::{delete, get, patch, post},
};

// Import des handlers liés aux volumes chiffrés
use crate::api::handlers::volume_handler::{
    create_volume,     // POST   /volumes
    delete_volume,     // DELETE /volumes/:id
    get_volume,        // GET    /volumes/:id
    list_user_volumes, // GET    /users/:id/volumes
    prepare_volume,    // POST   /volumes/prepare
    verify_volume,     // POST   /volumes/verify  <-- Nouveau handler
    update_volume,     // PATCH  /volumes/:id
};

// ─────────────────────────────────────────────────────────────
// Déclaration des routes Volumes
// ─────────────────────────────────────────────────────────────
// Ces routes permettent la gestion complète du cycle de vie
// des volumes chiffrés BindKey.

pub fn volume_routes() -> Router<crate::db::AppState> {
    Router::new()
        // --- Routes spécifiques (sans paramètres) ---
        .route("/volumes/prepare", post(prepare_volume))
        
        // ─────────────────────────────────────────
        // POST /volumes/verify
        // Vérifie si un nom de volume existe déjà pour l'utilisateur
        // ─────────────────────────────────────────
        .route("/volumes/verify", post(verify_volume))

        // ─────────────────────────────────────────
        // POST /volumes
        // Création d’un nouveau volume chiffré
        // ─────────────────────────────────────────
        .route("/volumes", post(create_volume))

        // --- Routes avec paramètres (:id) ---
        
        // ─────────────────────────────────────────
        // GET /volumes/:id
        // Récupération d’un volume par son identifiant
        // ─────────────────────────────────────────
        .route("/volumes/:id", get(get_volume))

        // ─────────────────────────────────────────
        // GET /users/:id/volumes
        // Liste des volumes dont l’utilisateur est propriétaire
        // ─────────────────────────────────────────
        .route("/users/:id/volumes", get(list_user_volumes))

        // ─────────────────────────────────────────
        // PATCH /volumes/:id
        // Modification d’un volume existant
        // ─────────────────────────────────────────
        .route("/volumes/:id", patch(update_volume))

        // ─────────────────────────────────────────
        // DELETE /volumes/:id
        // Suppression définitive d’un volume
        // ─────────────────────────────────────────
        .route("/volumes/:id", delete(delete_volume))
}
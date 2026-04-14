// -----------------------------------------------------------------------------
// volume_routes_module.rs
// Déclaration des routes HTTP liées aux volumes chiffrés
// -----------------------------------------------------------------------------

use axum::{
    Router,
    routing::{delete, get, patch, post},
};

// Import des handlers liés aux volumes chiffrés
use crate::api::handlers::volume_handler::{
    create_volume,     // POST   /volumes
    delete_volume,     // DELETE /volumes/:id
    get_volume,        // GET    /volumes/:id
    get_volume_key,    // GET    /volumes/:id/key <-- Ajouté ici
    list_user_volumes, // GET    /users/:id/volumes
    prepare_volume,    // POST   /volumes/prepare
    verify_volume,     // POST   /volumes/verify
    update_volume,     // PATCH  /volumes/:id
};

// ─────────────────────────────────────────────────────────────
// Déclaration des routes Volumes
// ─────────────────────────────────────────────────────────────

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
        // Récupérer les informations d’un volume (Métadonnées)
        // ─────────────────────────────────────────
        .route("/volumes/:id", get(get_volume))

        // ─────────────────────────────────────────
        // GET /volumes/:id/key
        // Récupérer la clé active d’un volume (si autorisé)
        // ─────────────────────────────────────────
        .route("/volumes/:id/key", get(get_volume_key))

        // ─────────────────────────────────────────
        // GET /users/:id/volumes
        // Lister les volumes appartenant à un utilisateur
        // ─────────────────────────────────────────
        .route("/users/:id/volumes", get(list_user_volumes))

        // ─────────────────────────────────────────
        // PATCH /volumes/:id
        // Modification d’un volume existant
        // ─────────────────────────────────────────
        .route("/volumes/:id", patch(update_volume))

        // ─────────────────────────────────────────
        // DELETE /volumes/:id
        // Supprimer définitivement un volume
        // ─────────────────────────────────────────
        .route("/volumes/:id", delete(delete_volume))
}
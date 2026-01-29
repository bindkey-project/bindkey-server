// Axum Router : permet de définir les routes HTTP
// post / get / patch / delete : méthodes HTTP utilisées pour gérer les volumes
use axum::{
    Router,
    routing::{delete, get, patch, post},
};

// Import des handlers liés aux volumes chiffrés
// Chaque handler implémente une action métier précise
use crate::api::handlers::volume_handler::{
    create_volume,     // POST   /volumes
    delete_volume,     // DELETE /volumes/:id
    get_volume,        // GET    /volumes/:id
    list_user_volumes, // GET    /users/:id/volumes
    update_volume,     // PATCH  /volumes/:id
};

//
// ─────────────────────────────────────────────────────────────
// Déclaration des routes Volumes
// ─────────────────────────────────────────────────────────────
//
// Ces routes permettent la gestion complète du cycle de vie
// des volumes chiffrés BindKey :
// - création
// - consultation
// - modification
// - suppression
//

pub fn volume_routes() -> Router<crate::db::AppState> {
    Router::new()
        // ─────────────────────────────────────────
        // POST /volumes
        // Création d’un nouveau volume chiffré
        // ─────────────────────────────────────────
        .route("/volumes", post(create_volume))
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
        // (renommage et/ou redimensionnement)
        // ─────────────────────────────────────────
        .route("/volumes/:id", patch(update_volume))
        // ─────────────────────────────────────────
        // DELETE /volumes/:id
        // Suppression définitive d’un volume
        // ─────────────────────────────────────────
        .route("/volumes/:id", delete(delete_volume))
}

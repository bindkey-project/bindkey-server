// -----------------------------------------------------------------------------
// volume_routes_module.rs
// Déclaration des routes HTTP liées aux volumes chiffrés
// -----------------------------------------------------------------------------

// Axum Router : permet de définir les routes HTTP
// get / post / patch / delete : méthodes HTTP pour manipuler les volumes
use axum::{
    Router,
    routing::{delete, get, patch, post},
};

// Import des handlers qui contiennent la logique métier
// Chaque handler correspond à une action sur les volumes
use crate::api::handlers::volume_handler::{
    create_volume,      // création d’un volume
    delete_volume,      // suppression d’un volume
    get_volume,         // récupérer un volume
    get_volume_key,     // récupérer la clé active d’un volume
    list_user_volumes,  // lister les volumes d’un utilisateur
    prepare_volume,     // préparer la création d’un volume (générer UUID)
    update_volume,      // modifier un volume
};

// -----------------------------------------------------------------------------
// Fonction qui enregistre toutes les routes liées aux volumes
// Appelée dans api/mod.rs via .merge(volume_routes())
// -----------------------------------------------------------------------------

pub fn volume_routes() -> Router<crate::db::AppState> {
    Router::new()

        // POST /volumes/prepare
        // Génère un volume_id avant la création du volume
        .route("/volumes/prepare", post(prepare_volume))

        // POST /volumes
        // Création d’un nouveau volume chiffré
        .route("/volumes", post(create_volume))

        // GET /volumes/:id
        // Récupérer les informations d’un volume
        .route("/volumes/:id", get(get_volume))

        // GET /volumes/:id/key
        // Récupérer la clé active d’un volume (si autorisé)
        .route("/volumes/:id/key", get(get_volume_key))

        // GET /users/:id/volumes
        // Lister les volumes appartenant à un utilisateur
        .route("/users/:id/volumes", get(list_user_volumes))

        // PATCH /volumes/:id
        // Modifier un volume (nom ou taille)
        .route("/volumes/:id", patch(update_volume))

        // DELETE /volumes/:id
        // Supprimer définitivement un volume
        .route("/volumes/:id", delete(delete_volume))
}
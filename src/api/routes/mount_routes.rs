// Axum Router : permet de définir les routes HTTP
// post : méthode HTTP utilisée ici pour déclencher des actions
use axum::{
    Router,
    routing::post,
};

// Import des handlers de montage / démontage
// Ces handlers assurent la traçabilité des accès aux volumes
use crate::api::handlers::mount_handler::{
    mount_volume,     // POST /mount
    unmount_volume,   // POST /unmount/:id
};

//
// ─────────────────────────────────────────────────────────────
// Déclaration des routes Mount / Unmount
// ─────────────────────────────────────────────────────────────
//
// Ces routes sont critiques pour la sécurité :
// - elles enregistrent qui monte quel volume
// - elles tracent quand l’accès commence et se termine
// - elles permettent l’audit et la détection d’abus
//

pub fn mount_routes() -> Router<crate::db::AppState> {
    Router::new()

        // ─────────────────────────────────────────
        // POST /mount
        // Monte un volume chiffré pour un utilisateur
        // → création d’un événement de montage
        // ─────────────────────────────────────────
        .route("/mount", post(mount_volume))

        // ─────────────────────────────────────────
        // POST /unmount/:id
        // Démontage explicite d’un volume monté
        // → fermeture de l’accès + traçabilité
        // ─────────────────────────────────────────
        .route("/unmount/:id", post(unmount_volume))
}

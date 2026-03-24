// Axum Router : permet de définir les routes HTTP
// post / get / delete : méthodes HTTP utilisées pour la gestion des permissions
use axum::{
    Router,
    routing::{delete, get, post},
};

// Import des handlers liés au partage et aux permissions
// Ces handlers contiennent la logique métier de contrôle d’accès
use crate::api::handlers::permission_handler::{
    get_my_grants,
    list_volume_permissions, // GET  /volumes/:id/permissions
    revoke_permission,       // DELETE /permissions/:id
    share_volume,            // POST /volumes/:id/share
};

//
// ─────────────────────────────────────────────────────────────
// Déclaration des routes Permissions / Sharing
// ─────────────────────────────────────────────────────────────
//
// Ces routes sont critiques pour la sécurité BindKey :
// - elles contrôlent qui peut accéder à quel volume
// - elles préviennent les fuites de clés (risque #9)
// - elles assurent une traçabilité claire des partages
//

pub fn permission_routes() -> Router<crate::db::AppState> {
    Router::new()
        // ─────────────────────────────────────────
        // POST /volumes/:id/share
        // Partage un volume avec un autre utilisateur
        // (READ ou READ_WRITE, avec expiration optionnelle)
        // ─────────────────────────────────────────
        .route("/volumes/:id/share", post(share_volume))
        // ─────────────────────────────────────────
        // GET /volumes/:id/permissions
        // Liste tous les droits d’accès associés à un volume
        // → visibilité complète pour audit et gestion
        // ─────────────────────────────────────────
        .route("/volumes/:id/permissions", get(list_volume_permissions))
        // ─────────────────────────────────────────
        // DELETE /permissions/:id
        // Révoque explicitement un droit d’accès
        // → coupure immédiate de l’accès
        // ─────────────────────────────────────────
        .route("/permissions/:id", delete(revoke_permission))

        .route("/me/grants", get(get_my_grants))
}

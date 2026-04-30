// Axum Router : permet de définir les routes HTTP
// post / get / delete : méthodes HTTP utilisées pour la gestion des permissions
use axum::{
    Router,
    routing::{delete, get, post},
};

// Import des handlers liés au partage et aux permissions
// Ces handlers contiennent la logique métier de contrôle d’accès
use crate::api::handlers::permission_handler::{
    accept_permission, // POST /permissions/:id/accept → accepter un partage
    deny_permission,   // POST /permissions/:id/deny → refuser un partage
    get_my_grants,
    get_my_shared_invitations, // GET /me/shared-invitations → invitations reçues
    list_volume_permissions,   // GET  /volumes/:id/permissions
    revoke_permission,         // DELETE /permissions/:id
    share_volume,              // POST /volumes/:id/share
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
        // ─────────────────────────────────────────
        // GET /me/shared-invitations
        //
        // → Côté destinataire
        // → Liste les invitations reçues (status = PENDING)
        // → Permet à l’utilisateur de voir :
        //    - qui partage
        //    - quel volume
        //    - avec quels droits
        // ─────────────────────────────────────────
        .route("/me/shared-invitations", get(get_my_shared_invitations))
        // ─────────────────────────────────────────
        // POST /permissions/:id/accept
        //
        // → Le destinataire accepte le partage
        // → status passe de PENDING → ACTIVE
        // → Le volume devient visible dans /me/grants
        // ─────────────────────────────────────────
        .route("/permissions/:id/accept", post(accept_permission))
        // ─────────────────────────────────────────
        // POST /permissions/:id/deny
        //
        // → Le destinataire refuse le partage
        // → status passe de PENDING → DENIED
        // → Le volume ne sera jamais accessible
        // ─────────────────────────────────────────
        .route("/permissions/:id/deny", post(deny_permission))
}

// ─────────────────────────────────────────────────────────────
// Routes — Volume Sharing (cf. share_server.md §4)
// ─────────────────────────────────────────────────────────────
//
// Ce module expose toutes les routes liées au partage sécurisé
// de volumes entre BindKeys.
//
// Contrairement à l'ancien système (permissions),
// ici le partage est basé sur un échange cryptographique (ECDH)
// entre devices (ATECC608), le serveur ne voit jamais la clé.
//
// Flux global :
//   1. /share_request   → préparation du partage
//   2. /share_complete  → stockage du wrapped blob
//   3. /shares/received → récupération côté destinataire
//   4. /accept / deny   → décision utilisateur
//

use crate::db::AppState;

use axum::{
    Router,
    routing::{delete, get, post},
};

// Import des handlers liés au sharing
// Chaque handler correspond à une étape du protocole
use crate::api::handlers::share_handler::{
    accept_share, // accepter un partage
    acknowledge_share,
    complete_share, // finaliser le partage (wrapped blob)
    deny_share,     // refuser un partage
    get_pending_shares,
    list_received_shares,   // voir les partages reçus
    remove_received_share,  // retirer un partage côté cible (libère le slot)
    request_share,          // initier un partage
};

pub fn share_routes() -> Router<AppState> {
    Router::new()
        // ─────────────────────────────────────────
        // POST /share_request
        //
        // → Étape B du protocole
        // → Côté source (utilisateur qui partage)
        //
        // Input :
        //   - volume_name
        //   - target_user_email
        //
        // Action :
        //   - résout le volume
        //   - trouve la BindKey cible
        //   - alloue un slot sécurisé [10..14]
        //   - pré-crée une entrée en base (PENDING)
        //
        // Output :
        //   - target_sn
        //   - target_pubkey_ecdh
        //   - target_slot
        //   - volume_id
        //
        // → utilisé ensuite par la BindKey pour chiffrer la clé
        // ─────────────────────────────────────────
        .route("/share_request", post(request_share))
        // ─────────────────────────────────────────
        // POST /share_complete
        //
        // → Étape C du protocole
        // → Côté source après interaction avec la BindKey
        //
        // Input :
        //   - source_sn
        //   - target_sn
        //   - volume_id
        //   - wrapped (clé chiffrée en hex)
        //
        // Action :
        //   - vérifie que la source appartient à l'utilisateur
        //   - convertit le wrapped (60 bytes)
        //   - met à jour la ligne en base
        //
        // Résultat :
        //   - partage prêt à être récupéré côté cible
        //   - status reste PENDING (en attente de récupération)
        // ─────────────────────────────────────────
        .route("/share_complete", post(complete_share))
        // ─────────────────────────────────────────
        // GET /shares/received
        //
        // → Côté destinataire
        //
        // Retourne :
        //   - les partages reçus
        //   - uniquement ceux prêts (wrapped_blob != NULL)
        //   - status = PENDING
        //
        // Permet à l’utilisateur de voir :
        //   - qui a partagé (source_sn)
        //   - quel volume
        //   - sur quel slot
        //
        // → équivalent du "invitations list" dans l'ancien système
        // ─────────────────────────────────────────
        .route("/shares/received", get(list_received_shares))
        // ─────────────────────────────────────────
        // POST /shares/:id/accept
        //
        // → Côté destinataire
        //
        // Action :
        //   - marque le partage comme DELIVERED
        //   - enregistre delivered_at
        //
        // Effet :
        //   - la BindKey cible peut utiliser la clé
        //   - le partage est considéré comme accepté
        // ─────────────────────────────────────────
        .route("/shares/:id/accept", post(accept_share))
        // ─────────────────────────────────────────
        // POST /shares/:id/deny
        //
        // → Côté destinataire
        //
        // Action :
        //   - supprime ou ignore le partage
        //
        // Effet :
        //   - le slot reste occupé (design v1)
        //   - le partage est refusé définitivement
        //
        // → équivalent du DENIED dans l'ancien système
        // ─────────────────────────────────────────
        .route("/shares/:id/deny", post(deny_share))
        // ─────────────────────────────────────────
        // DELETE /shares/received/:id
        //
        // → Côté destinataire
        //
        // Action :
        //   - supprime la ligne volume_shares (PENDING ou DELIVERED)
        //   - libère le slot [10..14] sur la BindKey cible
        //
        // Effet :
        //   - le partage disparaît côté destinataire uniquement
        //   - le volume du propriétaire n'est pas affecté
        // ─────────────────────────────────────────
        .route("/shares/received/:id", delete(remove_received_share))
        .route("/shares/pending", get(get_pending_shares))
        .route("/share_acknowledged", post(acknowledge_share))
}

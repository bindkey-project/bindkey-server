// ─────────────────────────────────────────────────────────────
// Routes — Volume Sharing (cf. share_server.md §4)
// ─────────────────────────────────────────────────────────────
use axum::{Router, routing::post};

use crate::api::handlers::share_handler::{complete_share, request_share};
use crate::db::AppState;

pub fn share_routes() -> Router<AppState> {
    Router::new()
        // POST /share_request — opération B (Demande de partage)
        // Body: { volume_name, target_user_email }
        // Renvoie (target_sn, target_pubkey_ecdh, target_slot, volume_id).
        .route("/share_request", post(request_share))

        // POST /share_complete — opération C (Stockage du wrapped)
        // Body: { source_sn, target_sn, volume_id, wrapped (hex 120 chars) }
        .route("/share_complete", post(complete_share))
}

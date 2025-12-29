use axum::{
    Router,
    routing::{post, get, patch},
};

use crate::api::handlers::bindkey_handler::{
    enroll_bindkey,
    get_bindkey,
    get_user_bindkeys,
    update_bindkey_status,
    reset_bindkey,
};


pub fn bindkey_routes() -> Router<crate::db::AppState> {
    Router::new()
        .route("/bindkeys/enroll", post(enroll_bindkey))
        .route("/bindkeys/:id", get(get_bindkey))
        .route("/users/:id/bindkeys", get(get_user_bindkeys))
        .route("/bindkeys/:id/status", patch(update_bindkey_status))
        .route("/bindkeys/:id/reset", post(reset_bindkey))
}

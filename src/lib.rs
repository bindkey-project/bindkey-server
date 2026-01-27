pub mod api;
pub mod config;
pub mod db;

use crate::db::AppState;
use axum::Router;
use dotenvy::dotenv;

/// Cette fonction est maintenant dans la LIB, donc accessible par les tests et le main
pub async fn create_app_instance() -> Router {
    dotenv().ok();

    let cfg = config::Config::from_env();

    let pool = db::create_pool(&cfg.database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    sqlx::migrate!().run(&pool).await.expect("Migration failed");

    // On définit is_test à true uniquement si on est en mode compilation de test
    let state = AppState { db: pool };

    api::create_app(state)
}

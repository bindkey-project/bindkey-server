use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use axum::Router;

mod api;
mod config;
mod db;

use db::AppState; // ⬅️ on importe AppState depuis db.rs

#[tokio::main]
async fn main() {
    // 1) Logs
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // 2) Config (port + DATABASE_URL)
    let cfg = config::Config::from_env();

    // 3) Connexion BDD
    let pool = db::create_pool(&cfg.database_url)
        .await
        .expect("❌ Failed to connect to PostgreSQL");
    tracing::info!("✅ Successfully connected to PostgreSQL");

    tracing::info!("📦 Running database migrations...");
    sqlx::migrate!().run(&pool).await.expect("❌ Migration failed");
    tracing::info!("✅ Migrations applied");

    // 4) Création du state global
    let state = AppState { db: pool };

    // 5) Créer le router en lui passant le state
    let app: Router = api::create_app(state);

    // 6) Adresse et listener
    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    let actual_addr = listener.local_addr().expect("failed to read local addr");
    tracing::info!("Bindkey server running on http://{}/", actual_addr);

    // 7) Lancement du serveur Axum
    axum::serve(listener, app)
        .await
        .expect("server failed");
}

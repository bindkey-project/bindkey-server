use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use dotenvy::dotenv;
use axum::Router;

mod api;
mod config;
mod db;

use db::AppState;

/// 1. FONCTION DE CRÉATION DE L'APP
/// On extrait toute la logique de construction ici pour qu'elle soit réutilisable.
pub async fn create_app_instance() -> Router {
    // On charge le .env pour récupérer DATABASE_URL
    dotenv().ok();

    // Configuration (port + DATABASE_URL) via ton module config
    let cfg = config::Config::from_env();

    // Connexion BDD via ton module db
    let pool = db::create_pool(&cfg.database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    // Exécution des migrations pour garantir que les tables (users, bindkeys) existent
    sqlx::migrate!().run(&pool).await.expect("Migration failed");

    // Création du state global pour les handlers
    let state = AppState { db: pool };

    // On retourne le router final créé par ton module api
    api::create_app(state)
}

/// 2. POINT D'ENTRÉE DU SERVEUR
#[tokio::main]
async fn main() {
    // Initialisation des logs (uniquement ici pour ne pas polluer les tests)
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("Starting BindKey server logic...");

    // On appelle notre fonction pour obtenir le router
    let app = create_app_instance().await;

    // Configuration de l'adresse (Logique d'origine conservée)
    let cfg = config::Config::from_env();
    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    let actual_addr = listener.local_addr().expect("failed to read local addr");
    tracing::info!("BindKey server running on http://{}/", actual_addr);

    // Lancement du serveur Axum
    axum::serve(listener, app)
        .await
        .expect("server failed");
}

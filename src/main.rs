
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use axum::Router;

mod api;
mod config;
mod db;


#[tokio::main]
async fn main(){

    // 1) Initialisation des logs
    tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::from_default_env())
    .init();

    // 2) Chargement de la configuration
    let cfg= config::Config::from_env();

    //3) Connexion à la base PostgreSQL
    let pool = db::create_pool(&cfg.database_url)
    .await
    .expect("❌ Failed to connect to PostgreSQL");

    tracing::info!("✅ Successfully connected to PostgreSQL");

     // 4) Création de l'application (routes)
    let app : Router = api::create_app();

    // 5) Adresse IP + port venant du fichier .env
    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));

     // 6) Listener TCP
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");


    let actual_addr = listener.local_addr().expect("failed to read local addr");
    tracing::info!("Bindkey server running on http://{}/", actual_addr);

    // 7) Lancement du serveur Axum
    axum::serve(listener,app)
        .await
        .expect("server failed");

}


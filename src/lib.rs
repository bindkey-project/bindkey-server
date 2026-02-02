pub mod api;
pub mod config;
pub mod db;

use crate::db::AppState;
use axum::Router;
use dotenvy::dotenv;
use std::env;
// Ajout des imports manquants pour sqlx et tokio
use sqlx::postgres::PgPoolOptions;
use tokio::time::{sleep, Duration};

/// Cette fonction est maintenant dans la LIB, donc accessible par les tests et le main
pub async fn create_app_instance() -> Router {
    dotenv().ok();

    // On récupère l'URL de la base de données
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Boucle de connexion pour éviter le CrashLoop sur Kubernetes
    let pool = loop {
        eprintln!("🚀 Tentative de connexion à la base de données...");
        match PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(2))
            .connect(&db_url)
            .await 
        {
            Ok(p) => {
                eprintln!("✅ Connexion PostgreSQL réussie !");
                break p;
            },
            Err(e) => {
                eprintln!("⏳ PostgreSQL n'est pas encore prêt ({}), nouvelle tentative dans 2s...", e);
                sleep(Duration::from_secs(2)).await;
            }
        }
    };

    // Exécution des migrations pour recréer les tables si le PVC était vide
    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Migration failed");

    let state = AppState { db: pool };

    api::create_app(state)
}
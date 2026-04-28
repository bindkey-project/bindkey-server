pub mod api;
pub mod config;
pub mod db;

use crate::db::AppState;
use axum::Router;
use dotenvy::dotenv;
use std::env;
use sqlx::postgres::PgPoolOptions;
use tokio::time::{sleep, Duration};

/// Charge la Root CA depuis les variables d'environnement.
///
/// Les variables `ROOT_CA_CERT_PEM` et `ROOT_CA_KEY_PEM` sont injectées par
/// Kubernetes depuis le Secret `bindkey-rootca`. Le serveur refuse de démarrer
/// si elles sont absentes (la signature des certificats BindKey est impossible sans).
fn load_root_ca_from_env() -> (String, String) {
    let cert_pem = env::var("ROOT_CA_CERT_PEM")
        .expect("ROOT_CA_CERT_PEM est requis (Secret K8s 'bindkey-rootca')");
    let key_pem = env::var("ROOT_CA_KEY_PEM")
        .expect("ROOT_CA_KEY_PEM est requis (Secret K8s 'bindkey-rootca')");

    if cert_pem.trim().is_empty() || key_pem.trim().is_empty() {
        panic!("ROOT_CA_CERT_PEM / ROOT_CA_KEY_PEM ne peuvent pas être vides");
    }

    eprintln!("🔑 Root CA chargée depuis les variables d'environnement.");
    (cert_pem, key_pem)
}

/// Point d'entrée principal de l'application, accessible par les tests et le main.
pub async fn create_app_instance() -> Router {
    dotenv().ok();

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
            }
            Err(e) => {
                eprintln!("⏳ PostgreSQL n'est pas encore prêt ({}), nouvelle tentative dans 2s...", e);
                sleep(Duration::from_secs(2)).await;
            }
        }
    };

    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Migration failed");

    let (ca_cert_pem, ca_key_pem) = load_root_ca_from_env();

    let state = AppState { db: pool, ca_cert_pem, ca_key_pem };

    api::create_app(state)
}
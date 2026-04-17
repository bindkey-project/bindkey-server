use dotenvy::dotenv;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

// On importe tout depuis la lib
use bindkey_server::config;
use bindkey_server::create_app_instance;

use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok(); // pour la clé publique du test
    // Initialisation du provider TLS (important !)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("Starting BindKey SERVER logic with TLS...");

    // On utilise la fonction qui est maintenant dans la lib
    let app = create_app_instance().await;

    let cfg = config::Config::from_env();
    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));

    // Configuration TLS
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();
    let config = RustlsConfig::from_der(
        vec![cert.cert.der().to_vec()],
        cert.key_pair.serialize_der(),
    )
    .await
    .unwrap();

    tracing::info!(
        "🛡️ BindKey SERVER ARGOCDv2 running on https://localhost:{}/",
        cfg.port
    );

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

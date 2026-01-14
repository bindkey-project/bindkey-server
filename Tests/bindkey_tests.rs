use axum::{
    body,
    body::Body,
    http::{Request, StatusCode}, // J'ajoute StatusCode ici pour mes comparaisons
};
use tower::util::ServiceExt; 
use serde_json::{json, Value};
use uuid::Uuid;

use bindkey_server::create_app_instance;

#[tokio::test]
async fn test_full_security_and_enrollment_flow() {
    let app = create_app_instance().await;

    // --- ÉTAPE 1 : CRÉATION DE L'UTILISATEUR ---
    let user_email = format!("dev_{}@bindkey.io", Uuid::new_v4());
    let create_user_json = json!({
        "first_name": "Marwa",
        "last_name": "Dev",
        "email": user_email
    });

    let user_res = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&create_user_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(user_res.status().is_success());
    let body_bytes = body::to_bytes(user_res.into_body(), usize::MAX).await.unwrap();
    let user_data: Value = serde_json::from_slice(&body_bytes).unwrap();
    let user_id = Uuid::parse_str(user_data["id"].as_str().expect("Pas d'ID")).unwrap();
    
    println!("\n--- ÉTAPE 1 : USER CRÉÉ ({}) ---", user_id);

    // --- ÉTAPE 2 : PREMIER ENRÔLEMENT (SUCCÈS) ---
    let shared_bindkey_uid = format!("BK-STORY1-{}", Uuid::new_v4());
    let enroll_payload = json!({
        "user_id": user_id,
        "bindkey_uid": shared_bindkey_uid,
        "public_key": "pub_key_secure_2026",
        "fingerprint_template": "biometric_template_hash"
    });

    let enroll_res = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/bindkeys/enroll")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&enroll_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    println!("--- ÉTAPE 2 : PREMIER ENRÔLEMENT ---");
    println!("Statut reçu : {} ({:?})", enroll_res.status().as_u16(), enroll_res.status().canonical_reason());
    assert!(enroll_res.status().is_success());

    // --- ÉTAPE 3 : TEST DE SÉCURITÉ (DOUBLON) ---
    let duplicate_res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/bindkeys/enroll")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&enroll_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let dup_status = duplicate_res.status();
    println!("\n--- ÉTAPE 3 : TEST SÉCURITÉ (DOUBLON) ---");
    println!("Tentative d'enrôler la même clé une seconde fois...");
    println!("Statut reçu : {} ({:?})", dup_status.as_u16(), dup_status.canonical_reason().unwrap_or("Inconnu"));

    // MODIFICATION ICI : Je vérifie que j'ai bien un 409 CONFLICT
    // Si j'ai encore un 500, le test échouera, me disant que mon handler n'est pas encore parfait.
    assert_eq!(
        dup_status, 
        StatusCode::CONFLICT, 
        "ERREUR : Le serveur devrait renvoyer 409 Conflict pour un doublon, mais il a renvoyé {:?}", 
        dup_status
    );
    
    println!("Résultat : La sécurité a bien bloqué le doublon avec un code 409 propre.");
}
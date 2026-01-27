use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::util::ServiceExt;
use uuid::Uuid;

// On importe body proprement pour les conversions
use axum::body as ax_body;

use bindkey_server::create_app_instance;

#[tokio::test]
async fn test_full_security_and_enrollment_flow() {
    let app = create_app_instance().await;

    // --- ÉTAPE 1 : CRÉATION DE L'UTILISATEUR ---
    let user_email = format!("dev_{}@bindkey.io", Uuid::new_v4());
    let create_user_json = json!({
        "first_name": "Marwa",
        "last_name": "Dev",
        "email": user_email,
        "role": "USER",
        "password_hash": "hash123"
    });

    let user_res = app
        .clone()
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

    assert!(
        user_res.status().is_success(),
        "Erreur création user: {:?}",
        user_res.status()
    );

    let body_bytes = ax_body::to_bytes(user_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let user_data: Value = serde_json::from_slice(&body_bytes).unwrap();
    let user_id = user_data["id"]
        .as_str()
        .expect("Pas d'ID dans la réponse JSON");

    println!("\n--- ÉTAPE 1 : USER CRÉÉ ({}) ---", user_id);

    // --- ÉTAPE 2 : PREMIER ENRÔLEMENT ---
    let shared_bindkey_uid = format!("BK-STORY1-{}", Uuid::new_v4());
    let enroll_payload = json!({
        "user_id": user_id,
        "bindkey_uid": shared_bindkey_uid,
        "public_key": "pub_key_secure_2026",
        "fingerprint_template": "biometric_template_hash"
    });

    let enroll_res = app
        .clone()
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

    // --- AJOUT DE LOGS POUR VOIR L'ERREUR REELLE ---
    let status = enroll_res.status();
    let body_bytes = ax_body::to_bytes(enroll_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);

    println!("--- ÉTAPE 2 : STATUT ENRÔLEMENT : {} ---", status);
    println!("--- RÉPONSE SERVEUR : {} ---", body_str);

    assert!(
        status.is_success(),
        "L'enrôlement a échoué avec le message : {}",
        body_str
    );

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

    assert_eq!(dup_status, StatusCode::CONFLICT);
    println!("Résultat : La sécurité a bien bloqué le doublon avec un code 409.");
}

#[tokio::test]
async fn test_get_user_bindkeys_list() {
    let app = create_app_instance().await;

    let user_email = format!("test_list_{}@bindkey.io", Uuid::new_v4());
    let create_user_json = json!({
        "first_name": "Test",
        "last_name": "List",
        "email": user_email,
        "role": "USER",
        "password_hash": "hash123"
    });

    let user_res = app
        .clone()
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

    let body_bytes = ax_body::to_bytes(user_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let user_data: Value = serde_json::from_slice(&body_bytes).unwrap();
    let user_id = user_data["id"].as_str().expect("L'ID user est manquant");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/users/{}/bindkeys", user_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    println!("\n--- TEST : LISTE DES CLÉS ---");
    assert!(response.status().is_success());
}

#[tokio::test]
async fn test_get_bindkey_not_found() {
    let app = create_app_instance().await;
    let fake_id = Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/bindkeys/{}", fake_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    println!("\n--- TEST : BINDKEY INCONNUE ---");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_user_bindkeys_list_content() {
    let app = create_app_instance().await;

    let user_email = format!("list_test_{}@test.com", Uuid::new_v4());
    let user_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "first_name": "List",
                        "last_name": "Tester",
                        "email": user_email,
                        "role": "USER",
                        "password_hash": "hash123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body_bytes = ax_body::to_bytes(user_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let user_data: Value = serde_json::from_slice(&body_bytes).unwrap();
    let user_id_str = user_data["id"].as_str().expect("Pas d'ID");

    let bindkey_uid = format!("BK-LIST-{}", Uuid::new_v4());
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/bindkeys/enroll")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "user_id": user_id_str,
                        "bindkey_uid": bindkey_uid,
                        "public_key": "key_list_test",
                        "fingerprint_template": "template_list_test"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/users/{}/bindkeys", user_id_str))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    println!("\n--- TEST : CONTENU DE LA LISTE ---");
    let status = response.status();
    let body_bytes = ax_body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list: Vec<Value> =
        serde_json::from_slice(&body_bytes).expect("Body n'est pas une liste JSON");

    assert!(status.is_success());
    assert!(!list.is_empty(), "La liste ne devrait pas être vide !");
    assert_eq!(list[0]["bindkey_uid"], bindkey_uid);
}

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

#[tokio::test]
async fn test_get_user_bindkeys_list() {
    let app = create_app_instance().await;
    
    // 1. Création d'un user
    let user_id = Uuid::new_v4();
    // (Note: Dans un vrai test, on créerait l'user en DB d'abord, 
    // mais ici on teste la réponse de la route GET)

    // 2. Appel de la route GET /users/:id/bindkeys
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
    println!("Statut reçu : {} ({:?})", response.status().as_u16(), response.status().canonical_reason());

    // On s'attend à un 200 OK (même si la liste est vide [])
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
    println!("Statut reçu : {} ({:?})", response.status().as_u16(), response.status().canonical_reason());

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_user_bindkeys_list_content() {
    let app = create_app_instance().await;
    
    // 1. On crée d'abord un utilisateur (nécessaire pour la FK)
    let user_email = format!("list_test_{}@test.com", Uuid::new_v4());
    let user_res = app.clone().oneshot(
        Request::builder().method("POST").uri("/users")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({"first_name": "List", "last_name": "Tester", "email": user_email})).unwrap())).unwrap()
    ).await.unwrap();
    
    let body_bytes = body::to_bytes(user_res.into_body(), usize::MAX).await.unwrap();
    let user_id: Value = serde_json::from_slice(&body_bytes).unwrap();
    let user_id_uuid = user_id["id"].as_str().unwrap();

    // 2. On enrôle une clé pour cet utilisateur
    let bindkey_uid = format!("BK-LIST-{}", Uuid::new_v4());
    app.clone().oneshot(
        Request::builder().method("POST").uri("/bindkeys/enroll")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({
                "user_id": user_id_uuid,
                "bindkey_uid": bindkey_uid,
                "public_key": "key_list_test",
                "fingerprint_template": "template_list_test"
            })).unwrap())).unwrap()
    ).await.unwrap();

    // 3. On demande la liste des clés de cet utilisateur
    let response = app.oneshot(
        Request::builder().method("GET").uri(format!("/users/{}/bindkeys", user_id_uuid))
            .body(Body::empty()).unwrap()
    ).await.unwrap();

    println!("\n--- TEST : CONTENU DE LA LISTE ---");
    let status = response.status();
    let body_bytes = body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let list: Vec<Value> = serde_json::from_slice(&body_bytes).unwrap();

    println!("Statut : {}, Nombre de clés trouvées : {}", status, list.len());

    assert!(status.is_success());
    assert!(!list.is_empty(), "La liste ne devrait pas être vide après un enrôlement !");
    assert_eq!(list[0]["bindkey_uid"], bindkey_uid, "Le bindkey_uid reçu ne correspond pas à celui créé");
}
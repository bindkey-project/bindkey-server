use bindkey_server::api::middleware::hasher_mot_de_passe;

use axum::body as ax_body;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::util::ServiceExt;
use uuid::Uuid;

use bindkey_server::create_app_instance;

// ─────────────────────────────────────────────────────────────
// Test 1 : flow enrollement + doublon
// ─────────────────────────────────────────────────────────────use bindkey_server::api::middleware::hasher_mot_de_passe;
use bindkey_server::api::middleware::chiffrer_aes;

#[tokio::test]
async fn test_full_security_and_enrollment_flow() {
    let app = create_app_instance().await;

    // ÉTAPE 1 : CRÉATION DE L'UTILISATEUR
    // NOTE : le handler create_user attend "password" (clair) optionnel
    let user_email = format!("dev_{}@bindkey.io", Uuid::new_v4());
    let create_user_json = json!({
        "first_name": "Marwa",
        "last_name": "Dev",
        "email": user_email,
        "password": "password123"
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

    // ÉTAPE 2 : ENRÔLEMENT DE LA BINDKEY
    let shared_bindkey_uid = format!("BK-STORY1-{}", Uuid::new_v4());
    let enroll_payload = json!({
        "user_id": user_id,
        "bindkey_uid": shared_bindkey_uid,
        // ⚠️ à adapter si votre endpoint attend une vraie clé base64
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

    // ÉTAPE 3 : TEST DOUBLON (doit être bloqué)
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
    println!("✅ Doublon bloqué avec 409 CONFLICT");
}

// ─────────────────────────────────────────────────────────────
// Test 2 : GET /users/:id/bindkeys (liste)
// ─────────────────────────────────────────────────────────────
#[tokio::test]
async fn test_get_user_bindkeys_list() {
    let app = create_app_instance().await;

    let user_email = format!("test_list_{}@bindkey.io", Uuid::new_v4());
    let create_user_json = json!({
        "first_name": "Test",
        "last_name": "List",
        "email": user_email,
        "password": "password123"
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

// ─────────────────────────────────────────────────────────────
// Test 3 : GET /bindkeys/:id (not found)
// ─────────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────────
// Test 4 : contenu liste bindkeys non vide
// ─────────────────────────────────────────────────────────────
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
                        "password": "password123"
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


/*async fn setup_test_user_with_key(pool: &sqlx::PgPool, email: &str, public_key_b64: &str) {
    // 1. Configuration de l'environnement de sécurité (AES)
    unsafe {
        std::env::set_var("PWD_ENCRYPTION_KEY", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    }
    
    let key_hex = std::env::var("PWD_ENCRYPTION_KEY").unwrap();
    let key_bytes = hex::decode(&key_hex).expect("Clé AES invalide");
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(b"unique_nonce"); 

    // 2. Génération d'un hash Argon2 valide pour "password123"
    // On utilise un sel statique pour éviter les conflits entre rand 0.8 et 0.9
    let salt = SaltString::from_b64("c29tZXN0YXRpY19zYWx0").unwrap(); 
    let argon2 = Argon2::default();
    let argon2_hash = argon2
        .hash_password("password123".as_bytes(), &salt)
        .expect("Échec génération hash argon2")
        .to_string();

    // 3. Chiffrement AES du hash pour le stockage (Middleware-friendly)
    let encrypted_bytes = cipher
        .encrypt(nonce, argon2_hash.as_bytes())
        .expect("Chiffrement de test échoué");
    
    let encrypted_b64 = general_purpose::STANDARD.encode(encrypted_bytes);

    // 4. Insertion ou mise à jour de l'utilisateur
    let row = sqlx::query(
        r#"
        INSERT INTO users (
            id, first_name, last_name, email, role, status, 
            password_hash, recovery_code_hash, created_at, updated_at
        ) 
        VALUES ($1, $2, $3, $4, $5::user_role, $6::user_status, $7, $8, NOW(), NOW()) 
        ON CONFLICT (email) DO UPDATE SET 
            password_hash = EXCLUDED.password_hash,
            recovery_code_hash = EXCLUDED.recovery_code_hash,
            status = EXCLUDED.status
        RETURNING id
        "#
    )
    .bind(Uuid::new_v4())
    .bind("Test")
    .bind("User")
    .bind(email)
    .bind("USER")
    .bind("ACTIVE")
    .bind(&encrypted_b64)
    .bind(&encrypted_b64)
    .fetch_one(pool)
    .await
    .expect("Échec insertion/update utilisateur");

    let user_id: Uuid = row.get("id");

    // 5. Nettoyage des anciennes BindKeys
    sqlx::query("DELETE FROM bindkeys WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .ok();

    // 6. Insertion de la BindKey de test
    sqlx::query(
        r#"
        INSERT INTO bindkeys (
            id, user_id, bindkey_uid, fingerprint_template, public_key, status
        ) 
        VALUES ($1, $2, $3, $4, $5, $6::bindkey_status)
        "#
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(format!("BK-{}", Uuid::new_v4()))
    .bind(&encrypted_b64) // Utilise le format chiffré pour le template
    .bind(public_key_b64)
    .bind("ACTIVE")
    .execute(pool)
    .await
    .expect("Erreur lors de l'insertion de la bindkey");
}
#[tokio::test]*/
/*async fn test_full_authentication_flow() {
    // 1. Initialisation du serveur de test (In-Memory)
    // On récupère ton Router via create_app_instance
    let app = create_app_instance().await; 
    let server = TestServer::new(app).expect("Failed to create test server");

    // 2. Connexion à la BDD pour préparer les données
    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();

    // 3. Préparation des clés ECC (Simulation BindKey)
    let signing_key = SigningKey::from_bytes(&[0u8; 32]); 
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let public_key_b64 = general_purpose::STANDARD.encode(public_key_bytes);

    let test_email = "ci_test@bindkey.io";
    setup_test_user_with_key(&pool, test_email, &public_key_b64).await;

    // 4. ÉTAPE LOGIN : Appel via le serveur de test
    let login_payload = json!({
        "email": test_email,
        "password_hash": "password123" 
    });

    let res_login = server.post("/sessions/login")
        .json(&login_payload)
        .await;

    res_login.assert_status_ok();
    let login_data: LoginResponse = res_login.json();
    
    // 5. ÉTAPE SIGNATURE (Logique locale au test)
    let signature = signing_key.sign(login_data.auth_challenge.as_bytes());
    let signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

    // 6. ÉTAPE VERIFY : Envoi de la signature
    let verify_payload = VerifyRequest {
        session_id: login_data.session_id,
        signature: signature_b64,
    };

    let res_verify = server.post("/sessions/verify")
        .json(&verify_payload)
        .await;

    // 7. ASSERTIONS FINALES
    res_verify.assert_status_ok();
    let final_data: VerifyResponse = res_verify.json();
    
    assert!(!final_data.server_token.is_empty(), "Le server_token ne doit pas être vide");
    assert_eq!(final_data.role, "USER");
    
    println!("✅ Flow d'authentification validé en mémoire pour : {}", final_data.first_name);
}*/

#[tokio::test]
async fn generate_real_admin_hash() {
    // 1. On utilise DIRECTEMENT la valeur que ton logiciel envoie
    // On ne recalcule pas le SHA-256 ici pour éviter les erreurs de concaténation
    let software_hash = "ac78c60dfa03149112f62d063d4cd20c5b3b4d4f6c8f977efc6628d54c0cb65c";

    // 2. Ton hachage Argon2 (Utilise ta fonction avec sel aléatoire)
    let argon_hash = hasher_mot_de_passe(software_hash);

    // 3. Ton chiffrement AES (Utilise ta fonction avec Nonce aléatoire + préfixe)
    // Assure-toi que export PWD_ENCRYPTION_KEY=... est fait dans le terminal
    let final_db_string = chiffrer_aes(&argon_hash);

    println!("\n\n🚀 VALEUR À COPIER EN BDD (password_hash) :\n{}\n", final_db_string);
}
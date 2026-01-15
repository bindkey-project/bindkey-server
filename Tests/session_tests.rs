use axum::{body::Body, http::{Request, StatusCode}, body};
use tower::util::ServiceExt;
use serde_json::{json, Value};
use uuid::Uuid;
use bindkey_server::create_app_instance;


#[tokio::test]
async fn test_session_full_lifecycle() {
    let app = create_app_instance().await;

    println!("\n🔑 DÉMARRAGE DU TEST : SESSIONS (LOGIN -> REFRESH -> LOGOUT)");

    // --- PRÉPARATION : Création User et BindKey ---
    let user_res = app.clone().oneshot(
        Request::builder().method("POST").uri("/users")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({
                "first_name": "Sess", "last_name": "Tester", "email": format!("s_{}@test.com", Uuid::new_v4())
            })).unwrap())).unwrap()
    ).await.unwrap();
    let user_id = serde_json::from_slice::<Value>(&body::to_bytes(user_res.into_body(), usize::MAX).await.unwrap()).unwrap()["id"].as_str().unwrap().to_string();

    let bk_res = app.clone().oneshot(
        Request::builder().method("POST").uri("/bindkeys/enroll")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({
                "user_id": user_id, "bindkey_uid": format!("BK-{}", Uuid::new_v4()),
                "public_key": "key", "fingerprint_template": "temp"
            })).unwrap())).unwrap()
    ).await.unwrap();
    let bindkey_id = serde_json::from_slice::<Value>(&body::to_bytes(bk_res.into_body(), usize::MAX).await.unwrap()).unwrap()["bindkey_id"].as_str().unwrap().to_string();

    // --- 1. LOGIN ---
    let login_payload = json!({ "user_id": user_id, "bindkey_id": bindkey_id });
    let res = app.clone().oneshot(
        Request::builder().method("POST").uri("/sessions/login")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&login_payload).unwrap())).unwrap()
    ).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body_login = body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let login_data: Value = serde_json::from_slice(&body_login).unwrap();
    let server_token = login_data["server_token"].as_str().unwrap().to_string();
    println!("--- ÉTAPE 1 : LOGIN RÉUSSI (Token: {}) ---", server_token);

    // --- 2. REFRESH (UN SEUL APPEL ICI) ---
    let refresh_res = app.clone().oneshot(
        Request::builder().method("POST").uri("/sessions/refresh")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({ "server_token": server_token })).unwrap())).unwrap()
    ).await.unwrap();

    let refresh_status = refresh_res.status();
    println!("\n--- ÉTAPE 2 : REFRESH ---");
    println!("Statut : {} ({:?})", refresh_status.as_u16(), refresh_status.canonical_reason());
    
    assert_eq!(refresh_status, StatusCode::OK);
    
    let body_refresh = body::to_bytes(refresh_res.into_body(), usize::MAX).await.unwrap();
    let refresh_data: Value = serde_json::from_slice(&body_refresh).unwrap();
    let new_server_token = refresh_data["server_token"].as_str().unwrap();
    println!("DEBUG TEST: Nouveau token après refresh = {}", new_server_token);

   // --- 3. LOGOUT ---
    let logout_res = app.oneshot(
        Request::builder().method("POST").uri("/sessions/logout")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({ "server_token": new_server_token })).unwrap())).unwrap()
    ).await.unwrap();

    let logout_status = logout_res.status();
    println!("\n--- ÉTAPE 3 : LOGOUT ---");
    println!("Statut : {} ({:?})", logout_status.as_u16(), logout_status.canonical_reason());
    
    assert_eq!(logout_status, StatusCode::NO_CONTENT); 
    println!("\n✅ TOUT LE CYCLE DE SESSION EST VALIDÉ");
}
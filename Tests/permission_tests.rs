use axum::{body::Body, http::{Request, StatusCode}, body};
use tower::util::ServiceExt;
use serde_json::{json, Value};
use uuid::Uuid;
use bindkey_server::create_app_instance;

#[tokio::test]
async fn test_permission_lifecycle_and_security() {
    let app = create_app_instance().await;

    println!("\n🔐 TEST : PARTAGE ET SÉCURITÉ DES VOLUMES");

    // --- PRÉPARATION : Créer deux utilisateurs et un volume ---
    // User A (Propriétaire)
    let u_res = app.clone().oneshot(Request::builder().method("POST").uri("/users").header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({"first_name":"Owner","last_name":"A","email":format!("a_{}@t.com", Uuid::new_v4())})).unwrap())).unwrap()).await.unwrap();
    let owner_id = serde_json::from_slice::<Value>(&body::to_bytes(u_res.into_body(), usize::MAX).await.unwrap()).unwrap()["id"].as_str().unwrap().to_string();

    // User B (Invité)
    let u_res_b = app.clone().oneshot(Request::builder().method("POST").uri("/users").header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({"first_name":"Guest","last_name":"B","email":format!("b_{}@t.com", Uuid::new_v4())})).unwrap())).unwrap()).await.unwrap();
    let guest_id = serde_json::from_slice::<Value>(&body::to_bytes(u_res_b.into_body(), usize::MAX).await.unwrap()).unwrap()["id"].as_str().unwrap().to_string();

    // Disque et Volume pour Owner A
    let d_res = app.clone().oneshot(Request::builder().method("POST").uri("/disks/register").header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({"serial_number":format!("SN-{}", Uuid::new_v4()),"capacity_bytes":1000})).unwrap())).unwrap()).await.unwrap();
    let disk_id = serde_json::from_slice::<Value>(&body::to_bytes(d_res.into_body(), usize::MAX).await.unwrap()).unwrap()["disk_id"].as_str().unwrap().to_string();

    let v_res = app.clone().oneshot(Request::builder().method("POST").uri("/volumes").header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({"owner_id":owner_id,"disk_id":disk_id,"name":"SharedVol","size_bytes":100,"encrypted_key":"key"})).unwrap())).unwrap()).await.unwrap();
    let volume_id = serde_json::from_slice::<Value>(&body::to_bytes(v_res.into_body(), usize::MAX).await.unwrap()).unwrap()["volume_id"].as_str().unwrap().to_string();

    // --- 1. TEST SÉCURITÉ : Un usurpateur essaie de partager ---
    println!("--- ÉTAPE 1 : TEST TENTATIVE FRAUDULEUSE ---");
    let fraud_payload = json!({
        "grantee_id": guest_id,
        "permission": "READ",
        "created_by": guest_id // L'utilisateur B essaie de se donner des droits lui-même
    });
    let fraud_res = app.clone().oneshot(
        Request::builder().method("POST").uri(format!("/volumes/{}/share", volume_id))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&fraud_payload).unwrap())).unwrap()
    ).await.unwrap();

    println!("Statut usurpateur : {} (Attendu: 403 Forbidden)", fraud_res.status().as_u16());
    assert_eq!(fraud_res.status(), StatusCode::FORBIDDEN);

    // --- 2. PARTAGE NOMINAL : Owner A partage avec Guest B ---
    println!("\n--- ÉTAPE 2 : PARTAGE LÉGITIME ---");
    let share_payload = json!({
        "grantee_id": guest_id,
        "permission": "READ",
        "created_by": owner_id
    });
    let share_res = app.clone().oneshot(
        Request::builder().method("POST").uri(format!("/volumes/{}/share", volume_id))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&share_payload).unwrap())).unwrap()
    ).await.unwrap();

    assert_eq!(share_res.status(), StatusCode::OK);
    let perm_id = serde_json::from_slice::<Value>(&body::to_bytes(share_res.into_body(), usize::MAX).await.unwrap()).unwrap()["permission_id"].as_str().unwrap().to_string();
    println!("Volume partagé avec succès. ID Permission : {}", perm_id);

    // --- 3. RÉVOCATION ---
    println!("\n--- ÉTAPE 3 : RÉVOCATION DU DROIT ---");
    let revoke_res = app.oneshot(
        Request::builder().method("DELETE").uri(format!("/permissions/{}", perm_id))
            .body(Body::empty()).unwrap()
    ).await.unwrap();

    assert_eq!(revoke_res.status(), StatusCode::NO_CONTENT);
    println!("Accès révoqué.");

    println!("\n✅ TEST DES PERMISSIONS TERMINÉ AVEC SUCCÈS");
}
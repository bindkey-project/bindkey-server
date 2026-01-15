use axum::{body::Body, http::{Request, StatusCode}, body};
use tower::util::ServiceExt;
use serde_json::{json, Value};
use uuid::Uuid;
use bindkey_server::create_app_instance;

#[tokio::test]
async fn test_volume_lifecycle_full() {
    let app = create_app_instance().await;

    println!("\n🚀 DÉMARRAGE DU TEST : CYCLE DE VIE DES VOLUMES");

    // --- 1. PRÉPARATION : CRÉATION DU OWNER (USER) ---
    let user_res = app.clone().oneshot(
        Request::builder().method("POST").uri("/users")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({
                "first_name": "Vol", "last_name": "Owner", "email": format!("owner_{}@test.com", Uuid::new_v4())
            })).unwrap())).unwrap()
    ).await.unwrap();
    
    let user_status = user_res.status();
    let body_user = body::to_bytes(user_res.into_body(), usize::MAX).await.unwrap();
    let user_data: Value = serde_json::from_slice(&body_user).unwrap();
    let user_id = user_data["id"].as_str().unwrap().to_string();
    
    println!("--- ÉTAPE 1 : CRÉATION USER ---");
    println!("Statut : {} ({:?}) | ID : {}", user_status.as_u16(), user_status.canonical_reason(), user_id);

    // --- 2. PRÉPARATION : CRÉATION DU DISQUE ---
    let disk_res = app.clone().oneshot(
        Request::builder().method("POST").uri("/disks/register")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({
                "serial_number": format!("SN-VOL-{}", Uuid::new_v4()),
                "capacity_bytes": 1000000
            })).unwrap())).unwrap()
    ).await.unwrap();
    
    let disk_status = disk_res.status();
    let body_disk = body::to_bytes(disk_res.into_body(), usize::MAX).await.unwrap();
    let disk_data: Value = serde_json::from_slice(&body_disk).unwrap();
    let disk_id = disk_data["disk_id"].as_str().unwrap().to_string();
    
    println!("\n--- ÉTAPE 2 : ENREGISTREMENT DISQUE ---");
    println!("Statut : {} ({:?}) | ID : {}", disk_status.as_u16(), disk_status.canonical_reason(), disk_id);

    // --- 3. CRÉATION DU VOLUME (POST /volumes) ---
    let volume_name = "Coffre-Fort-Alpha";
    let create_vol_payload = json!({
        "owner_id": user_id,
        "disk_id": disk_id,
        "name": volume_name,
        "size_bytes": 500000,
        "encrypted_key": "AES256-SECRET-KEY-ENCRYPTED"
    });

    let res = app.clone().oneshot(
        Request::builder().method("POST").uri("/volumes")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_vol_payload).unwrap())).unwrap()
    ).await.unwrap();

    let create_status = res.status();
    println!("\n--- ÉTAPE 3 : CRÉATION DU VOLUME ---");
    println!("Statut : {} ({:?})", create_status.as_u16(), create_status.canonical_reason());
    
    assert_eq!(create_status, StatusCode::OK);
    
    let body_vol = body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let volume_id = serde_json::from_slice::<Value>(&body_vol).unwrap()["volume_id"].as_str().unwrap().to_string();

    // --- 4. MISE À JOUR (PATCH /volumes/:id) ---
    let new_name = "Coffre-Fort-Final";
    let patch_res = app.clone().oneshot(
        Request::builder().method("PATCH").uri(format!("/volumes/{}", volume_id))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({ "name": new_name })).unwrap())).unwrap()
    ).await.unwrap();

    let patch_status = patch_res.status();
    println!("\n--- ÉTAPE 4 : MISE À JOUR (PATCH) ---");
    println!("Statut : {} ({:?}) | Nouveau nom : {}", patch_status.as_u16(), patch_status.canonical_reason(), new_name);
    assert_eq!(patch_status, StatusCode::NO_CONTENT);

    // --- 5. VÉRIFICATION LISTE (GET /users/:id/volumes) ---
    let list_res = app.clone().oneshot(
        Request::builder().method("GET").uri(format!("/users/{}/volumes", user_id))
            .body(Body::empty()).unwrap()
    ).await.unwrap();

    let list_status = list_res.status();
    let body_list = body::to_bytes(list_res.into_body(), usize::MAX).await.unwrap();
    let volumes: Vec<Value> = serde_json::from_slice(&body_list).unwrap();
    
    println!("\n--- ÉTAPE 5 : RÉCUPÉRATION LISTE USER ---");
    println!("Statut : {} ({:?}) | Volumes trouvés : {}", list_status.as_u16(), list_status.canonical_reason(), volumes.len());
    
    assert!(!volumes.is_empty());
    assert_eq!(volumes[0]["name"], new_name);

    // --- 6. SUPPRESSION (DELETE /volumes/:id) ---
    let del_res = app.oneshot(
        Request::builder().method("DELETE").uri(format!("/volumes/{}", volume_id))
            .body(Body::empty()).unwrap()
    ).await.unwrap();

    let del_status = del_res.status();
    println!("\n--- ÉTAPE 6 : SUPPRESSION DU VOLUME ---");
    println!("Statut : {} ({:?})", del_status.as_u16(), del_status.canonical_reason());
    assert_eq!(del_status, StatusCode::NO_CONTENT);
    
    println!("\n✅ TEST TERMINÉ AVEC SUCCÈS");
}
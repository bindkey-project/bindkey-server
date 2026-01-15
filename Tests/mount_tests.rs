use axum::{body::Body, http::{Request, StatusCode}, body};
use tower::util::ServiceExt;
use serde_json::{json, Value};
use uuid::Uuid;
use bindkey_server::create_app_instance;

#[tokio::test]
async fn test_mount_unmount_cycle() {
    let app = create_app_instance().await;

    println!("\n📂 TEST : MONTAGE & DÉMONTAGE DE VOLUMES");

    // --- PRÉPARATION : Création des entités parentes ---
    
    // 1. Création User
    let u_res = app.clone().oneshot(
        Request::builder().method("POST").uri("/users")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({
                "first_name": "Mount", 
                "last_name": "Tester", 
                "email": format!("m_{}@t.com", Uuid::new_v4())
            })).unwrap())).unwrap()
    ).await.unwrap();
    let u_id = serde_json::from_slice::<Value>(&body::to_bytes(u_res.into_body(), usize::MAX).await.unwrap()).unwrap()["id"].as_str().unwrap().to_string();

    // 2. Création Disque
    let d_res = app.clone().oneshot(
        Request::builder().method("POST").uri("/disks/register")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({
                "serial_number": format!("SN-{}", Uuid::new_v4()),
                "capacity_bytes": 1000000
            })).unwrap())).unwrap()
    ).await.unwrap();
    let d_id = serde_json::from_slice::<Value>(&body::to_bytes(d_res.into_body(), usize::MAX).await.unwrap()).unwrap()["disk_id"].as_str().unwrap().to_string();

    // 3. Création Volume
    let v_res = app.clone().oneshot(
        Request::builder().method("POST").uri("/volumes")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({
                "owner_id": u_id,
                "disk_id": d_id,
                "name": "TestMount",
                "size_bytes": 100000,
                "encrypted_key": "secret_key"
            })).unwrap())).unwrap()
    ).await.unwrap();
    let v_id = serde_json::from_slice::<Value>(&body::to_bytes(v_res.into_body(), usize::MAX).await.unwrap()).unwrap()["volume_id"].as_str().unwrap().to_string();

    // --- ÉTAPE 1 : MOUNT ---
    let mount_payload = json!({
        "volume_id": v_id,
        "user_id": u_id,
        "expires_at": null
    });

    let res = app.clone().oneshot(
        Request::builder().method("POST").uri("/mount")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&mount_payload).unwrap())).unwrap()
    ).await.unwrap();

    println!("--- ÉTAPE 1 : MOUNT ---");
    println!("Statut : {} ({:?})", res.status().as_u16(), res.status().canonical_reason());
    assert_eq!(res.status(), StatusCode::OK);

    let body_mount = body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let mount_id = serde_json::from_slice::<Value>(&body_mount).unwrap()["mount_id"].as_str().unwrap().to_string();

    // --- ÉTAPE 2 : UNMOUNT ---
    let unmount_res = app.oneshot(
        Request::builder().method("POST").uri(format!("/unmount/{}", mount_id))
            .body(Body::empty()).unwrap()
    ).await.unwrap();

    println!("\n--- ÉTAPE 2 : UNMOUNT ---");
    println!("Statut : {} ({:?})", unmount_res.status().as_u16(), unmount_res.status().canonical_reason());
    assert_eq!(unmount_res.status(), StatusCode::NO_CONTENT);

    println!("\n✅ CYCLE DE MONTAGE VALIDÉ AVEC SUCCÈS");
}
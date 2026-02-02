use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::util::ServiceExt;
use uuid::Uuid;

// On utilise toujours notre fonction pour instancier l'app réelle
use bindkey_server::create_app_instance;

#[tokio::test]
async fn test_disk_lifecycle_full() {
    let app = create_app_instance().await;

    // --- 1. ENREGISTREMENT DU DISQUE (POST) ---
    let serial = format!("SN-{}", Uuid::new_v4());
    let register_payload = json!({
        "serial_number": serial,
        "capacity_bytes": 1_000_000_000_i64 // 1 GB
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/disks/register")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&register_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    println!("\n--- ÉTAPE 1 : ENREGISTREMENT DISQUE ---");
    println!(
        "Statut : {} ({:?})",
        res.status().as_u16(),
        res.status().canonical_reason()
    );
    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: Value = serde_json::from_slice(&body).unwrap();
    let disk_id = resp_json["disk_id"].as_str().unwrap();
    println!("Succès : Disque enregistré avec l'ID {}", disk_id);

    // --- 2. RÉCUPÉRATION PAR ID (GET /disks/:id) ---
    // on fait le GET
    let res = app
    .clone()
    .oneshot(
        Request::builder()
            .method("GET")
            .uri(format!("/disks/{}", disk_id))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    // récupérer status avant de consommer le body
    let status = res.status();

    // lire le body (ça consomme res)
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
    .await
    .unwrap();
    let body_str = String::from_utf8_lossy(&body);

    println!("Statut : {} ({:?})", status.as_u16(), status.canonical_reason());
    println!("Body : {}", body_str);

    // puis assert
    assert_eq!(status, StatusCode::OK);



    // --- 3. RECHERCHE PAR NUMÉRO DE SÉRIE (GET /disks?serial=...) ---
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/disks?serial={}", serial))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    println!("\n--- ÉTAPE 3 : RECHERCHE PAR SÉRIE ---");
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let disk_data: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(disk_data["serial_number"], serial);
    println!("Succès : Le numéro de série correspond bien !");
}

#[tokio::test]
async fn test_get_disk_not_found() {
    let app = create_app_instance().await;
    let fake_id = Uuid::new_v4();

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/disks/{}", fake_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    println!("\n--- TEST : DISQUE INEXISTANT ---");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    println!("Statut : 404 (Correct)");
}

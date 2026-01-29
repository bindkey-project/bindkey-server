// Import des composants Axum nécessaires pour construire des handlers HTTP
// - Json : sérialisation / désérialisation JSON
// - State : accès à l’état partagé (connexion DB)
// - Path / Query : récupération des paramètres d’URL
// - StatusCode : codes HTTP explicites
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};

// UUID pour identifier de manière unique chaque disque
use uuid::Uuid;

// Accès à l’état global de l’application (contient la connexion PostgreSQL)
use crate::db::AppState;

// Modèle Disk correspondant à la table `disks`
use crate::api::models::disk::Disk;

// ─────────────────────────────────────────────────────────────
// POST /disks/register
// ─────────────────────────────────────────────────────────────
// 🎯 Objectif :
// Enregistrer un disque physique (USB, SSD, etc.) dans le système BindKey.
//
// Cas d’usage :
// - Lorsqu’un nouveau support est branché
// - Éviter les doublons via le numéro de série
// - Associer plus tard des volumes chiffrés à ce disque
// ─────────────────────────────────────────────────────────────

// Données reçues depuis le client pour enregistrer un disque
#[derive(serde::Deserialize)]
pub struct RegisterDiskRequest {
    pub serial_number: String, // Numéro de série matériel du disque
    pub capacity_bytes: i64,   // Capacité totale du disque en octets
}

// Réponse envoyée après enregistrement
#[derive(serde::Serialize)]
pub struct RegisterDiskResponse {
    pub disk_id: Uuid,   // UUID généré côté serveur
    pub message: String, // Message informatif
}

// Handler principal : POST /disks/register
pub async fn register_disk(
    State(state): State<AppState>,            // Connexion DB partagée
    Json(payload): Json<RegisterDiskRequest>, // JSON reçu depuis le client
) -> Result<Json<RegisterDiskResponse>, (StatusCode, String)> {
    // Génération d’un identifiant unique pour le disque
    let disk_id = Uuid::new_v4();

    // Insertion du disque dans la base PostgreSQL
    sqlx::query(
        r#"
        INSERT INTO disks (id, serial_number, capacity_bytes)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(disk_id) // $1 : UUID du disque
    .bind(&payload.serial_number) // $2 : numéro de série
    .bind(payload.capacity_bytes) // $3 : capacité
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // Réponse retournée au client
    Ok(Json(RegisterDiskResponse {
        disk_id,
        message: "Disk registered".into(),
    }))
}

// ─────────────────────────────────────────────────────────────
// GET /disks/:id
// ─────────────────────────────────────────────────────────────
// 🎯 Objectif :
// Récupérer les informations complètes d’un disque via son UUID
// ─────────────────────────────────────────────────────────────

pub async fn get_disk(
    State(state): State<AppState>, // Connexion DB
    Path(id): Path<Uuid>,          // UUID extrait depuis l’URL
) -> Result<Json<Disk>, (StatusCode, String)> {
    // Recherche du disque en base
    let disk = sqlx::query_as::<_, Disk>("SELECT * FROM disks WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Disk not found".into()))?;

    // Retourne le disque trouvé
    Ok(Json(disk))
}

// ─────────────────────────────────────────────────────────────
// GET /disks?serial=...
// ─────────────────────────────────────────────────────────────
// 🎯 Objectif :
// Retrouver un disque à partir de son numéro de série.
//
// Cas critique sécurité / logique :
// - Empêcher l’enregistrement multiple du même disque
// - Vérifier l’existence avant création
// ─────────────────────────────────────────────────────────────

// Paramètre de requête : ?serial=XXXX
#[derive(serde::Deserialize)]
pub struct DiskSerialQuery {
    pub serial: String,
}

// Handler : GET /disks?serial=...
pub async fn get_disk_by_serial(
    State(state): State<AppState>,    // Connexion DB
    Query(q): Query<DiskSerialQuery>, // Paramètre ?serial=
) -> Result<Json<Disk>, (StatusCode, String)> {
    // Recherche du disque par numéro de série
    let disk = sqlx::query_as::<_, Disk>("SELECT * FROM disks WHERE serial_number = $1")
        .bind(&q.serial)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Disk not found".into()))?;

    // Retourne le disque trouvé
    Ok(Json(disk))
}

// src/api/handlers/disk_handler.rs
//
// Objectif :
// - Ajouter des logs d’audit (écriture dans la table audit_logs) pour les actions disque
// - Garder le handler identique côté API, mais tracer en base ce qui se passe
//
//  Points importants :
// - On appelle write_audit_log() APRÈS les opérations DB réussies
// - On ne cache pas les erreurs d’audit : si l’audit échoue, on l’affiche avec eprintln!
// - Ici il n’y a pas AuthUser dans les endpoints disque -> user_id = None (sauf si tu ajoutes l’auth)

// Import des composants Axum nécessaires pour construire des handlers HTTP
// - Json : sérialisation / désérialisation JSON
// - State : accès à l’état partagé (connexion DB)
// - Path / Query : récupération des paramètres d’URL
// - StatusCode : codes HTTP explicites
use axum::{
    Json,
    extract::{State, Path, Query},
    http::StatusCode,
};

// UUID pour identifier de manière unique chaque disque
use uuid::Uuid;

// Accès à l’état global de l’application (contient la connexion PostgreSQL)
use crate::db::AppState;

// Modèle Disk correspondant à la table `disks`
use crate::api::models::disk::Disk;

// Audit : helper qui insère dans la table audit_logs
use crate::api::audit::{write_audit_log, AuditSeverity};

// ─────────────────────────────────────────────────────────────
// POST /disks/register
// ─────────────────────────────────────────────────────────────
// Objectif :
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
    pub disk_id: Uuid,    // UUID généré côté serveur
    pub message: String,  // Message informatif
}

// Handler principal : POST /disks/register
pub async fn register_disk(
    State(state): State<AppState>,             // Connexion DB partagée
    Json(payload): Json<RegisterDiskRequest>,  // JSON reçu depuis le client
) -> Result<Json<RegisterDiskResponse>, (StatusCode, String)> {
    // 1) Génération d’un identifiant unique pour le disque
    let disk_id = Uuid::new_v4();

    // 2) Insertion du disque dans la base PostgreSQL
    sqlx::query(
        r#"
        INSERT INTO disks (id, serial_number, capacity_bytes)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(disk_id)                 // $1 : UUID du disque
    .bind(&payload.serial_number)  // $2 : numéro de série
    .bind(payload.capacity_bytes)  // $3 : capacité
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("SQL error: {e}")
    ))?;

    // 3) Audit après INSERT OK
    // Ici on n’a pas d'utilisateur (pas d’AuthUser), donc user_id = None.
    // bindkey_id n’est pas concerné -> None.
    if let Err(e) = write_audit_log(
        &state,
        None,
        None,
        "DISK_REGISTER",
        Some(format!(
            "disk_id={disk_id} serial_number={} capacity_bytes={}",
            payload.serial_number, payload.capacity_bytes
        )),
        AuditSeverity::INFO,
    )
    .await
    {
        // Si tu vois ça dans kubectl logs / terminal, alors l’INSERT audit a échoué
        eprintln!("❌ AUDIT LOG FAILED (DISK_REGISTER): {e}");
    }

    // 4) Réponse retournée au client
    Ok(Json(RegisterDiskResponse {
        disk_id,
        message: "Disk registered".into(),
    }))
}

// ─────────────────────────────────────────────────────────────
// GET /disks/:id
// ─────────────────────────────────────────────────────────────
// Objectif :
// Récupérer les informations complètes d’un disque via son UUID
// ─────────────────────────────────────────────────────────────

pub async fn get_disk(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Disk>, (StatusCode, String)> {
    let disk = sqlx::query_as::<_, Disk>("SELECT * FROM disks WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| match e {
            // 404 : disque introuvable
            sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "Disk not found".into()),
            // autre : erreur DB
            other => (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {other}")),
        })?;

    // Audit (optionnel) : lecture réussie
    // Tu peux le garder ou l’enlever selon si tu veux auditer les lectures.
    if let Err(e) = write_audit_log(
        &state,
        None,
        None,
        "DISK_GET",
        Some(format!("disk_id={id}")),
        AuditSeverity::INFO,
    )
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED (DISK_GET): {e}");
    }

    Ok(Json(disk))
}

// ─────────────────────────────────────────────────────────────
// GET /disks?serial=...
// ─────────────────────────────────────────────────────────────
// Objectif :
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
    State(state): State<AppState>,
    Query(q): Query<DiskSerialQuery>,
) -> Result<Json<Disk>, (StatusCode, String)> {
    let disk = sqlx::query_as::<_, Disk>("SELECT * FROM disks WHERE serial_number = $1")
        .bind(&q.serial)
        .fetch_one(&state.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "Disk not found".into()),
            other => (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {other}")),
        })?;

    // Audit (optionnel) : recherche réussie par serial
    if let Err(e) = write_audit_log(
        &state,
        None,
        None,
        "DISK_GET_BY_SERIAL",
        Some(format!("serial_number={} disk_id={}", q.serial, disk.id)),
        AuditSeverity::INFO,
    )
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED (DISK_GET_BY_SERIAL): {e}");
    }

    Ok(Json(disk))
}

// Axum Router : permet de définir les routes HTTP
// post / get : méthodes HTTP utilisées pour l’API REST
use axum::{
    Router,
    routing::{get, post},
};

// Import des handlers liés aux disques physiques
// Chaque handler contient la logique métier associée
use crate::api::handlers::disk_handler::{
    get_disk,           // GET  /disks/:id
    get_disk_by_serial, // GET  /disks?serial=...
    register_disk,      // POST /disks/register
};

//
// ─────────────────────────────────────────────────────────────
// Déclaration des routes Disks
// ─────────────────────────────────────────────────────────────
//
// Ces routes permettent de gérer les disques physiques (USB, SSD, etc.)
// utilisés par BindKey pour héberger des volumes chiffrés.
//

pub fn disk_routes() -> Router<crate::db::AppState> {
    Router::new()
        // ─────────────────────────────────────────
        // POST /disks/register
        // Enregistre un disque physique dans le système
        // (numéro de série + capacité)
        // ─────────────────────────────────────────
        .route("/disks/register", post(register_disk))
        // ─────────────────────────────────────────
        // GET /disks/:id
        // Récupère les informations d’un disque via son UUID
        // ─────────────────────────────────────────
        .route("/disks/:id", get(get_disk))
        // ─────────────────────────────────────────
        // GET /disks?serial=...
        // Recherche d’un disque par numéro de série
        // → évite les doublons lors de l’enregistrement
        // ─────────────────────────────────────────
        .route("/disks", get(get_disk_by_serial))
}

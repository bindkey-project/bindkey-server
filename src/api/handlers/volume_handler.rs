// Axum :
// - Json : gestion des corps JSON
// - State : accès à l’état global (pool DB)
// - Path : paramètres d’URL (/volumes/:id)
// - StatusCode : codes HTTP explicites
use axum::{Json, extract::{State, Path}, http::StatusCode};

// UUID pour identifier volumes, users, disques
use uuid::Uuid;

// Accès à la base de données
use crate::db::AppState;

// Modèle Volume (correspond à la table PostgreSQL volumes)
use crate::api::models::volume::Volume;

//
// ─────────────────────────────────────────────────────────────
// POST /volumes
// Objectif : créer un volume chiffré BindKey
// ─────────────────────────────────────────────────────────────
//

/// Données nécessaires à la création d’un volume
#[derive(serde::Deserialize)]
pub struct CreateVolumeRequest {
    pub owner_id: Uuid,        // Propriétaire du volume
    pub disk_id: Uuid,         // Disque physique associé
    pub name: String,          // Nom lisible du volume
    pub size_bytes: i64,       // Taille allouée
    pub encrypted_key: String, // Clé de chiffrement (jamais en clair)
}

/// Réponse envoyée après création
#[derive(serde::Serialize)]
pub struct CreateVolumeResponse {
    pub volume_id: Uuid,
    pub message: String,
}

pub async fn create_volume(
    State(state): State<AppState>,              // Accès DB
    Json(payload): Json<CreateVolumeRequest>,   // Données envoyées par le client
) -> Result<Json<CreateVolumeResponse>, (StatusCode, String)> {

    // 1️⃣ Génération d’un identifiant unique pour le volume
    let volume_id = Uuid::new_v4();

    // 2️⃣ Insertion en base
    sqlx::query(
        r#"
        INSERT INTO volumes (
            id,
            owner_id,
            disk_id,
            name,
            size_bytes,
            encrypted_key
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        "#
    )
    .bind(volume_id)
    .bind(payload.owner_id)
    .bind(payload.disk_id)
    .bind(&payload.name)
    .bind(payload.size_bytes)
    .bind(&payload.encrypted_key)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("SQL error: {e}")
    ))?;

    // 3️⃣ Réponse au client
    Ok(Json(CreateVolumeResponse {
        volume_id,
        message: "Volume created".into(),
    }))
}

//
// ─────────────────────────────────────────────────────────────
// GET /volumes/:id
// Objectif : récupérer un volume précis
// ─────────────────────────────────────────────────────────────
//

pub async fn get_volume(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,      // ID du volume depuis l’URL
) -> Result<Json<Volume>, (StatusCode, String)> {

    let v = sqlx::query_as::<_, Volume>(
        "SELECT * FROM volumes WHERE id = $1"
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (
        StatusCode::NOT_FOUND,
        "Volume not found".into()
    ))?;

    Ok(Json(v))
}

//
// ─────────────────────────────────────────────────────────────
// GET /users/:id/volumes
// Objectif : lister les volumes dont l’utilisateur est propriétaire
// ─────────────────────────────────────────────────────────────
//

pub async fn list_user_volumes(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,     // ID de l’utilisateur
) -> Result<Json<Vec<Volume>>, (StatusCode, String)> {

    let list = sqlx::query_as::<_, Volume>(
        r#"
        SELECT *
        FROM volumes
        WHERE owner_id = $1
        ORDER BY created_at DESC
        "#
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("SQL error: {e}")
    ))?;

    Ok(Json(list))
}

//
// ─────────────────────────────────────────────────────────────
// PATCH /volumes/:id
// Objectif : renommer ou redimensionner un volume
// ─────────────────────────────────────────────────────────────
//

/// Champs optionnels : seuls ceux fournis seront modifiés
#[derive(serde::Deserialize)]
pub struct UpdateVolumeRequest {
    pub name: Option<String>,        // Nouveau nom (optionnel)
    pub size_bytes: Option<i64>,     // Nouvelle taille (optionnelle)
}

pub async fn update_volume(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,                 // ID du volume
    Json(payload): Json<UpdateVolumeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {

    // COALESCE permet de garder l’ancienne valeur si le champ est NULL
    let res = sqlx::query(
        r#"
        UPDATE volumes
        SET
            name = COALESCE($1, name),
            size_bytes = COALESCE($2, size_bytes),
            updated_at = now()
        WHERE id = $3
        "#
    )
    .bind(payload.name)
    .bind(payload.size_bytes)
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("SQL error: {e}")
    ))?;

    // Aucun volume modifié → ID invalide
    if res.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Volume not found".into()
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

//
// ─────────────────────────────────────────────────────────────
// DELETE /volumes/:id
// Objectif : supprimer définitivement un volume
// ─────────────────────────────────────────────────────────────
//

pub async fn delete_volume(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,     // ID du volume
) -> Result<StatusCode, (StatusCode, String)> {

    let res = sqlx::query(
        "DELETE FROM volumes WHERE id = $1"
    )
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("SQL error: {e}")
    ))?;

    if res.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Volume not found".into()
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

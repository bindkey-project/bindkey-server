// Import des composants Axum nécessaires
// - Json : gestion des payloads JSON
// - State : accès à l’état global (DB)
// - Path : lecture des paramètres dans l’URL
// - StatusCode : codes HTTP clairs
use axum::{
    Json,
    extract::{State, Path},
    http::StatusCode
};

// UUID pour identifier permissions, users, volumes
use uuid::Uuid;

// Accès à la base de données
use crate::db::AppState;

// Modèle VolumePermission + enum PermissionLevel (READ / READ_WRITE)
use crate::api::models::volume_permission::{
    VolumePermission,
    PermissionLevel
};

//
// ─────────────────────────────────────────────────────────────
// STRUCTURES DE DONNÉES
// ─────────────────────────────────────────────────────────────
//

// Données reçues lors du partage d’un volume
#[derive(serde::Deserialize)]
pub struct ShareVolumeRequest {
    pub grantee_id: Uuid,                 // Utilisateur qui reçoit l’accès
    pub permission: PermissionLevel,      // Niveau d’accès (READ / READ_WRITE)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>, 
    // Date d’expiration optionnelle du droit
    pub created_by: Uuid,                 
    // Utilisateur qui partage (en attendant l’auth, transmis dans le body)
}

// Réponse envoyée après un partage réussi
#[derive(serde::Serialize)]
pub struct ShareVolumeResponse {
    pub permission_id: Uuid,               // ID de la permission créée
    pub message: String,
}

//
// ─────────────────────────────────────────────────────────────
// POST /volumes/:id/share
// Objectif : partager un volume à un autre utilisateur
// ⚠️ RÈGLE DE SÉCURITÉ CRITIQUE (Risque #9)
// Seul le propriétaire du volume peut le partager
// ─────────────────────────────────────────────────────────────
//

pub async fn share_volume(
    State(state): State<AppState>,          // Accès DB
    Path(volume_id): Path<Uuid>,            // ID du volume à partager
    Json(payload): Json<ShareVolumeRequest> // Données de partage
) -> Result<Json<ShareVolumeResponse>, (StatusCode, String)> {

    // 1️⃣ Vérification du propriétaire du volume
    // On récupère l’owner_id depuis la table volumes
    let owner_id: Uuid = sqlx::query_scalar(
        "SELECT owner_id FROM volumes WHERE id = $1"
    )
    .bind(volume_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (
        StatusCode::NOT_FOUND,
        "Volume not found".into()
    ))?;

    // Si l’utilisateur qui tente de partager n’est pas le propriétaire → refus
    if owner_id != payload.created_by {
        return Err((
            StatusCode::FORBIDDEN,
            "Only owner can share this volume".into()
        ));
    }

    // 2️⃣ Création de la permission
    let perm_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO volume_permissions (
            id,
            volume_id,
            grantee_id,
            permission,
            expires_at,
            created_by
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        "#
    )
    .bind(perm_id)
    .bind(volume_id)
    .bind(payload.grantee_id)
    .bind(payload.permission)
    .bind(payload.expires_at)
    .bind(payload.created_by)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("SQL error: {e}")
    ))?;

    // Réponse de succès
    Ok(Json(ShareVolumeResponse {
        permission_id: perm_id,
        message: "Volume shared".into(),
    }))
}

//
// ─────────────────────────────────────────────────────────────
// GET /volumes/:id/permissions
// Objectif : lister tous les accès à un volume
// ─────────────────────────────────────────────────────────────
//

pub async fn list_volume_permissions(
    State(state): State<AppState>,     // Accès DB
    Path(volume_id): Path<Uuid>,       // Volume concerné
) -> Result<Json<Vec<VolumePermission>>, (StatusCode, String)> {

    // Récupération de toutes les permissions associées au volume
    let list = sqlx::query_as::<_, VolumePermission>(
        "SELECT * FROM volume_permissions
         WHERE volume_id = $1
         ORDER BY created_at DESC"
    )
    .bind(volume_id)
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
// DELETE /permissions/:id
// Objectif : révoquer un accès à un volume
// ─────────────────────────────────────────────────────────────
//

pub async fn revoke_permission(
    State(state): State<AppState>,    // Accès DB
    Path(permission_id): Path<Uuid>,  // ID de la permission à supprimer
) -> Result<StatusCode, (StatusCode, String)> {

    let res = sqlx::query(
        "DELETE FROM volume_permissions WHERE id = $1"
    )
    .bind(permission_id)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("SQL error: {e}")
    ))?;

    // Si aucune ligne supprimée → permission inexistante
    if res.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Permission not found".into()
        ));
    }

    // Succès sans contenu
    Ok(StatusCode::NO_CONTENT)
}

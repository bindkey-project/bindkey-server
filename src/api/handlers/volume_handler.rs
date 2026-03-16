// src/api/handlers/volume_handler.rs
// -----------------------------------------------------------------------------
// Handlers HTTP liés aux volumes chiffrés.
//
// Endpoints gérés :
//   - POST   /volumes
//   - POST   /volumes/prepare
//   - GET    /volumes/:id
//   - GET    /volumes/:id/key
//   - GET    /users/:id/volumes
//   - PATCH  /volumes/:id
//   - DELETE /volumes/:id
//
// Idée générale du modèle actuel :
//   - la table `volumes` stocke les métadonnées du volume
//   - la table `volume_keys` stocke la clé active chiffrée du volume
//   - la table `volume_permissions` stocke les droits d’accès
//
// Important :
//   - un volume appartient à un user 
//   - un volume n’est PLUS lié directement à une BindKey
//   - la BindKey sert à authentifier / déverrouiller, pas à "posséder" le volume
//
// Audit :
//   - VOLUME_CREATE
//   - VOLUME_UPDATE
//   - VOLUME_DELETE
//   - VOLUME_FORBIDDEN
//   - VOLUME_KEY_READ
//
// Sécurité :
//   - ne jamais logger `encrypted_key`
// -----------------------------------------------------------------------------

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;

use crate::api::audit::{write_audit_log, AuditSeverity};
use crate::api::auth::{require_role, AuthUser};
use crate::api::models::user::UserRole;
use crate::api::models::volume::Volume;
use crate::db::AppState;

// -----------------------------------------------------------------------------
// POST /volumes/prepare
// -----------------------------------------------------------------------------
// Ce endpoint est volontairement minimal pour le moment !!!!
//
// Avant, il essayait de retrouver un volume via la BindKey.
// Ce n’est plus cohérent avec l’architecture actuelle.
//
// Maintenant, il sert simplement à générer un `volume_id` côté serveur,
// que le client peut ensuite réutiliser lors du vrai POST /volumes.
// -----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct PrepareVolumeRequest {}

#[derive(serde::Serialize)]
pub struct PrepareVolumeResponse {
    /// Indique si un volume existait déjà.
    /// Dans cette version simplifiée, on retourne toujours false.
    pub exists: bool,

    /// UUID réservé pour le futur volume.
    pub volume_id: Uuid,
}

pub async fn prepare_volume(
    Extension(_auth): Extension<AuthUser>,
    State(_state): State<AppState>,
    Json(_payload): Json<PrepareVolumeRequest>,
) -> Result<Json<PrepareVolumeResponse>, (StatusCode, String)> {
    Ok(Json(PrepareVolumeResponse {
        exists: false,
        volume_id: Uuid::new_v4(),
    }))
}

// -----------------------------------------------------------------------------
// POST /volumes
// -----------------------------------------------------------------------------
// Création complète d’un volume.
//
// La logique est maintenant en 2 étapes atomiques (transaction SQL) :
//   1) créer l’entrée dans `volumes`
//   2) créer la clé active dans `volume_keys`
//
// Pourquoi une transaction ?
//   - pour éviter d’avoir un volume créé sans clé associée
//   - si une étape échoue, tout est annulé
// -----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct CreateVolumeRequest {
    /// UUID du volume, fourni après /volumes/prepare ou généré côté client.
    pub volume_id: Uuid,

    /// Disque physique cible.
    pub disk_id: Uuid,

    /// Nom lisible du volume.
    pub name: String,

    /// Taille allouée au volume.
    pub size_bytes: i64,

    /// Clé de volume CHIFFRÉE est stockée dans `volume_keys`
    pub encrypted_key: String,
}

#[derive(serde::Serialize)]
pub struct CreateVolumeResponse {
    pub volume_id: Uuid,
    pub message: String,
}

// -----------------------------------------------------------------------------
// GET /volumes/:id/key
// -----------------------------------------------------------------------------
// Réponse renvoyée lorsqu’un utilisateur autorisé demande la clé active d’un volume.
// -----------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct GetVolumeKeyResponse {
    pub volume_id: Uuid,
    pub encrypted_key: String,
    pub key_version: i32,
}

pub async fn create_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<CreateVolumeRequest>,
) -> Result<Json<CreateVolumeResponse>, (StatusCode, String)> {
    // 1) Démarrer une transaction :
    // si l’insertion du volume réussit mais pas celle de la clé,
    // on rollback pour garder une base cohérente.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // 2) Insérer les métadonnées du volume dans `volumes`
    sqlx::query(
        r#"
        INSERT INTO volumes (id, owner_id, disk_id, name, size_bytes)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(payload.volume_id)
    .bind(auth.user_id)
    .bind(payload.disk_id)
    .bind(&payload.name)
    .bind(payload.size_bytes)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // 3) Créer la première clé active de ce volume dans `volume_keys`
    let volume_key_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO volume_keys (id, volume_id, encrypted_key, key_version, is_active)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(volume_key_id)
    .bind(payload.volume_id)
    .bind(&payload.encrypted_key)
    .bind(1_i32) // première version de clé
    .bind(true)  // la clé créée ici devient la clé active
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // 4) Valider définitivement la transaction
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // 5) Audit de succès
    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_CREATE",
        Some(format!("volume_id={}", payload.volume_id)),
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(CreateVolumeResponse {
        volume_id: payload.volume_id,
        message: "Volume created".into(),
    }))
}

// -----------------------------------------------------------------------------
// GET /volumes/:id
// -----------------------------------------------------------------------------
// Retourne les métadonnées du volume.
//
// Règle d’accès :
//   - owner du volume
//   - ou ADMIN
// -----------------------------------------------------------------------------

pub async fn get_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Volume>, (StatusCode, String)> {
    // 1) Charger le volume
    let v = sqlx::query_as::<_, Volume>("SELECT * FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    // 2) Vérification owner/admin
    let is_owner = v.owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("get denied volume_id={}", id)),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    Ok(Json(v))
}

// -----------------------------------------------------------------------------
// GET /users/:id/volumes
// -----------------------------------------------------------------------------
// Retourne la liste des volumes appartenant à un user.
//
// Règle d’accès :
//   - l’utilisateur lui-même
//   - ou ADMIN
// -----------------------------------------------------------------------------

pub async fn list_user_volumes(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Volume>>, (StatusCode, String)> {
    let is_self = auth.user_id == user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_self && !is_admin {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("list denied target_user_id={}", user_id)),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    let list = sqlx::query_as::<_, Volume>(
        "SELECT * FROM volumes WHERE owner_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(list))
}

// -----------------------------------------------------------------------------
// PATCH /volumes/:id
// -----------------------------------------------------------------------------
// Met à jour certaines métadonnées du volume.
//
// Champs modifiables actuellement :
//   - name
//   - size_bytes
//
// Règle d’accès :
//   - owner
//   - ou ADMIN
// -----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct UpdateVolumeRequest {
    pub name: Option<String>,
    pub size_bytes: Option<i64>,
}

pub async fn update_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateVolumeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1) Charger owner_id pour vérifier les droits
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("update denied volume_id={}", id)),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    // 2) Sauvegarder les valeurs avant move, uniquement pour l’audit
    let new_name = payload.name.clone();
    let new_size = payload.size_bytes;

    // 3) Mise à jour partielle
    let res = sqlx::query(
        r#"
        UPDATE volumes
        SET name = COALESCE($1, name),
            size_bytes = COALESCE($2, size_bytes),
            updated_at = now()
        WHERE id = $3
        "#,
    )
    .bind(payload.name)
    .bind(payload.size_bytes)
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Volume not found".into()));
    }

    // 4) Audit de succès
    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_UPDATE",
        Some(format!(
            "volume_id={} name={:?} size_bytes={:?}",
            id, new_name, new_size
        )),
        AuditSeverity::INFO,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// -----------------------------------------------------------------------------
// DELETE /volumes/:id
// -----------------------------------------------------------------------------
// Supprime un volume.
//
// Règle d’accès :
//   - owner
//   - ou ADMIN
//
// Grâce aux clés étrangères avec ON DELETE CASCADE,
// les `volume_keys` associés seront supprimés automatiquement.
// -----------------------------------------------------------------------------

pub async fn delete_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1) Vérifier le propriétaire du volume
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("delete denied volume_id={}", id)),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    // 2) Suppression du volume
    let res = sqlx::query("DELETE FROM volumes WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Volume not found".into()));
    }

    // 3) Audit de succès
    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_DELETE",
        Some(format!("volume_id={} deleted", id)),
        AuditSeverity::WARNING,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// -----------------------------------------------------------------------------
// GET /volumes/:id/key
// -----------------------------------------------------------------------------
// Retourne la clé ACTIVE d’un volume si l’utilisateur est autorisé.
//
// Règle d’accès :
//   - owner
//   - ou ADMIN
//   - ou permission ACTIVE non expirée dans `volume_permissions`
//
// La clé est lue dans `volume_keys` avec `is_active = TRUE`.
// -----------------------------------------------------------------------------

pub async fn get_volume_key(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(volume_id): Path<Uuid>,
) -> Result<Json<GetVolumeKeyResponse>, (StatusCode, String)> {
    // 1) Vérifier que le volume existe et récupérer son owner
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(volume_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);
    let mut has_permission = false;

    // 2) Si l’utilisateur n’est ni owner ni admin,
    // vérifier s’il a une permission ACTIVE et non expirée
    if !is_owner && !is_admin {
        let perm = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT 1
            FROM volume_permissions
            WHERE volume_id = $1
              AND grantee_id = $2
              AND status = 'ACTIVE'
              AND (expires_at IS NULL OR expires_at > now())
            LIMIT 1
            "#,
        )
        .bind(volume_id)
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

        if perm.is_some() {
            has_permission = true;
        }
    }

    if !is_owner && !is_admin && !has_permission {
        write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_FORBIDDEN",
            Some(format!("key access denied volume_id={}", volume_id)),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    // 3) Charger la clé active
    let row = sqlx::query_as::<_, (String, i32)>(
        r#"
        SELECT encrypted_key, key_version
        FROM volume_keys
        WHERE volume_id = $1
          AND is_active = TRUE
        LIMIT 1
        "#,
    )
    .bind(volume_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "Active volume key not found".into()))?;

    let (encrypted_key, key_version) = row;

    // 4) Audit de succès
    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_KEY_READ",
        Some(format!("volume_id={}", volume_id)),
        AuditSeverity::INFO,
    )
    .await;

    // 5) Réponse JSON
    Ok(Json(GetVolumeKeyResponse {
        volume_id,
        encrypted_key,
        key_version,
    }))
}
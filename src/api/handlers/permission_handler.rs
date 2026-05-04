// src/api/handlers/permission_handler.rs
//
// Ce fichier gère toute la logique liée aux permissions et au partage de volumes.
//
// Endpoints principaux :
// - POST   /volumes/:id/share              → créer une invitation de partage
// - GET    /volumes/:id/permissions        → lister les permissions d’un volume
// - DELETE /permissions/:id                → révoquer une permission
// - GET    /me/grants                      → voir les volumes accessibles
// - GET    /me/shared-invitations          → voir les invitations reçues
// - POST   /permissions/:id/accept         → accepter une invitation
// - POST   /permissions/:id/deny           → refuser une invitation
//
// Sécurité :
// - seul le propriétaire ou un ADMIN peut partager / lister / révoquer
// - le destinataire voit uniquement ses propres invitations
// - un volume partagé n’apparaît dans /me/grants qu’après acceptation
//
// Audit :
// - VOLUME_PERMISSION_GRANT
// - VOLUME_PERMISSION_REVOKE
// - VOLUME_PERMISSION_FORBIDDEN
// - MY_GRANTS_READ

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};

use uuid::Uuid;

use crate::api::audit::{AuditSeverity, write_audit_log};
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;
use crate::api::models::volume_permission::{PermissionLevel, VolumePermission};
use crate::db::AppState;

// ─────────────────────────────────────────────────────────────
// Structures JSON
// ─────────────────────────────────────────────────────────────

/// Body reçu quand un propriétaire partage un volume.
#[derive(serde::Deserialize)]
pub struct ShareVolumeRequest {
    /// Utilisateur qui reçoit l’invitation.
    pub grantee_id: Uuid,

    /// Niveau d’accès accordé : READ ou READ_WRITE.
    pub permission: PermissionLevel,

    /// Date d’expiration optionnelle du partage.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Réponse après création d’une invitation de partage.
#[derive(serde::Serialize)]
pub struct ShareVolumeResponse {
    /// Identifiant de la permission créée.
    pub permission_id: Uuid,

    /// Message de confirmation.
    pub message: String,
}

/// Réponse utilisée par /me/grants.
/// Elle représente un volume réellement accessible par l’utilisateur.
#[derive(serde::Serialize, sqlx::FromRow)]
pub struct MyGrantResponse {
    pub volume_id: Uuid,
    pub disk_id: Uuid,
    pub name: String,
    pub permission: PermissionLevel,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Clé chiffrée du volume.
    /// Attention : elle ne doit jamais être une clé en clair.
    pub encrypted_key: String,

    /// Version de la clé, utile pour rotation / renouvellement.
    pub key_version: i32,
}

// ─────────────────────────────────────────────────────────────
// POST /volumes/:id/share
//
// Crée une invitation de partage.
// Le volume n’est PAS directement accessible : status = PENDING.
// Le destinataire devra accepter pour passer en ACTIVE.
// ─────────────────────────────────────────────────────────────

pub async fn share_volume(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(volume_id): Path<Uuid>,
    Json(payload): Json<ShareVolumeRequest>,
) -> Result<Json<ShareVolumeResponse>, (StatusCode, String)> {
    // 1) Vérifier que le volume existe et récupérer son propriétaire.
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(volume_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    // 2) Vérifier les droits : seul le propriétaire ou un ADMIN peut partager.
    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        // Audit d’une tentative non autorisée.
        let _ = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_PERMISSION_FORBIDDEN",
            Some(format!(
                "share denied volume_id={volume_id} grantee_id={}",
                payload.grantee_id
            )),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((
            StatusCode::FORBIDDEN,
            "Only owner (or ADMIN) can share this volume".into(),
        ));
    }

    // 3) Préparer les valeurs avant insertion.
    let grantee_id = payload.grantee_id;
    let expires_at = payload.expires_at;
    let permission_str = format!("{:?}", payload.permission);

    // 4) Créer une permission en attente.
    // PENDING = invitation envoyée, pas encore acceptée.
    let perm_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO volume_permissions (
            id, volume_id, grantee_id, permission, expires_at, created_by, status
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'PENDING')
        "#,
    )
    .bind(perm_id)
    .bind(volume_id)
    .bind(grantee_id)
    .bind(payload.permission)
    .bind(expires_at)
    .bind(auth.user_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // 5) Audit après création de l’invitation.
    let _ = write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_PERMISSION_GRANT",
        Some(format!(
            "permission_id={perm_id} volume_id={volume_id} grantee_id={grantee_id} permission={permission_str} expires_at={expires_at:?}"
        )),
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(ShareVolumeResponse {
        permission_id: perm_id,
        message: "Volume shared invitation created".into(),
    }))
}

// ─────────────────────────────────────────────────────────────
// GET /volumes/:id/permissions
//
// Liste les permissions d’un volume.
// Accessible uniquement au propriétaire ou à un ADMIN.
// ─────────────────────────────────────────────────────────────

pub async fn list_volume_permissions(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(volume_id): Path<Uuid>,
) -> Result<Json<Vec<VolumePermission>>, (StatusCode, String)> {
    // 1) Vérifier que le volume existe et récupérer son propriétaire.
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(volume_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    // 2) Autorisation owner/admin.
    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        let _ = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_PERMISSION_FORBIDDEN",
            Some(format!("list permissions denied volume_id={volume_id}")),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    // 3) Récupérer toutes les permissions du volume.
    // Le propriétaire peut ainsi voir ACTIVE, PENDING, DENIED, REVOKED.
    let list = sqlx::query_as::<_, VolumePermission>(
        "SELECT * FROM volume_permissions WHERE volume_id = $1 ORDER BY created_at DESC",
    )
    .bind(volume_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(list))
}

// ─────────────────────────────────────────────────────────────
// DELETE /permissions/:id
//
// Révoque une permission existante.
// On ne supprime pas physiquement la ligne : status = REVOKED.
// Cela garde une trace exploitable pour l’audit.
// ─────────────────────────────────────────────────────────────

pub async fn revoke_permission(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(permission_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1) Retrouver la permission ciblée.
    let row = sqlx::query_as::<_, (Uuid, Uuid)>(
        r#"
        SELECT volume_id, grantee_id
        FROM volume_permissions
        WHERE id = $1
        "#,
    )
    .bind(permission_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    let Some((volume_id, grantee_id)) = row else {
        return Err((StatusCode::NOT_FOUND, "Permission not found".into()));
    };

    // 2) Vérifier que celui qui révoque est owner ou ADMIN.
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM volumes WHERE id = $1")
        .bind(volume_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Volume not found".into()))?;

    let is_owner = owner_id == auth.user_id;
    let is_admin = require_role(&auth.role, &UserRole::ADMIN);

    if !is_owner && !is_admin {
        let _ = write_audit_log(
            &state,
            Some(auth.user_id),
            None,
            "VOLUME_PERMISSION_FORBIDDEN",
            Some(format!(
                "revoke denied permission_id={permission_id} volume_id={volume_id}"
            )),
            AuditSeverity::WARNING,
        )
        .await;

        return Err((StatusCode::FORBIDDEN, "Not allowed".into()));
    }

    // 3) Révocation logique.
    sqlx::query(
        r#"
        UPDATE volume_permissions
        SET status = 'REVOKED', revoked_at = now()
        WHERE id = $1
        "#,
    )
    .bind(permission_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    // 4) Audit de la révocation.
    let _ = write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "VOLUME_PERMISSION_REVOKE",
        Some(format!(
            "permission_id={permission_id} volume_id={volume_id} grantee_id={grantee_id} revoked"
        )),
        AuditSeverity::WARNING,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// GET /me/grants
//
// Retourne les volumes réellement accessibles par l’utilisateur connecté.
// Inclut :
// - ses propres volumes
// - les volumes partagés acceptés seulement : status = ACTIVE
//
// Exclut :
// - invitations PENDING
// - invitations DENIED
// - permissions REVOKED
// ─────────────────────────────────────────────────────────────

pub async fn get_my_grants(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
) -> Result<Json<Vec<MyGrantResponse>>, (StatusCode, String)> {
    // 1) Volumes possédés par l’utilisateur.
    let mut grants = sqlx::query_as::<_, MyGrantResponse>(
        r#"
        SELECT
            v.id AS volume_id,
            v.disk_id,
            v.name,
            'READ_WRITE'::text::permission_level AS permission,
            NULL AS expires_at,
            vk.encrypted_key,
            vk.key_version
        FROM volumes v
        JOIN volume_keys vk
            ON vk.volume_id = v.id
        WHERE v.owner_id = $1
          AND vk.is_active = TRUE
        "#,
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("SQL error (owner): {e}"),
        )
    })?;

    // 2) Volumes partagés déjà acceptés.
    let mut shared = sqlx::query_as::<_, MyGrantResponse>(
        r#"
        SELECT
            v.id AS volume_id,
            v.disk_id,
            v.name,
            vp.permission,
            vp.expires_at,
            vk.encrypted_key,
            vk.key_version
        FROM volume_permissions vp
        JOIN volumes v
            ON v.id = vp.volume_id
        JOIN volume_keys vk
            ON vk.volume_id = v.id
        WHERE vp.grantee_id = $1
          AND vp.status = 'ACTIVE'
          AND (vp.expires_at IS NULL OR vp.expires_at > now())
          AND vk.is_active = TRUE
        ORDER BY vp.created_at DESC
        "#,
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("SQL error (shared): {e}"),
        )
    })?;

    // 3) Fusionner owned + shared.
    grants.append(&mut shared);

    // 4) Audit de consultation des droits.
    write_audit_log(
        &state,
        Some(auth.user_id),
        None,
        "MY_GRANTS_READ",
        Some(format!("grants_count={}", grants.len())),
        AuditSeverity::INFO,
    )
    .await;

    Ok(Json(grants))
}

// ─────────────────────────────────────────────────────────────
// GET /me/shared-invitations
//
// Côté destinataire : liste les invitations de partage reçues.
// Seules les permissions PENDING sont retournées.
// ─────────────────────────────────────────────────────────────

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct SharedInvitationResponse {
    pub permission_id: Uuid,
    pub volume_id: Uuid,
    pub disk_id: Uuid,
    pub volume_name: String,
    pub permission: PermissionLevel,
    pub owner_id: Uuid,
    pub owner_email: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn get_my_shared_invitations(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
) -> Result<Json<Vec<SharedInvitationResponse>>, (StatusCode, String)> {
    let invitations = sqlx::query_as::<_, SharedInvitationResponse>(
        r#"
        SELECT
            vp.id AS permission_id,
            v.id AS volume_id,
            v.disk_id,
            v.name AS volume_name,
            vp.permission,
            v.owner_id,
            u.email AS owner_email,
            vp.created_at,
            vp.expires_at
        FROM volume_permissions vp
        JOIN volumes v ON v.id = vp.volume_id
        JOIN users u ON u.id = v.owner_id
        WHERE vp.grantee_id = $1
          AND vp.status = 'PENDING'
          AND (vp.expires_at IS NULL OR vp.expires_at > now())
        ORDER BY vp.created_at DESC
        "#,
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    Ok(Json(invitations))
}

// ─────────────────────────────────────────────────────────────
// POST /permissions/:id/accept
//
// Le destinataire accepte une invitation.
// status : PENDING → ACTIVE
// Après ça, le volume apparaît dans /me/grants.
// ─────────────────────────────────────────────────────────────

pub async fn accept_permission(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(permission_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let res = sqlx::query(
        r#"
        UPDATE volume_permissions
        SET status = 'ACTIVE'
        WHERE id = $1
          AND grantee_id = $2
          AND status = 'PENDING'
          AND (expires_at IS NULL OR expires_at > now())
        "#,
    )
    .bind(permission_id)
    .bind(auth.user_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Invitation not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// POST /permissions/:id/deny
//
// Le destinataire refuse une invitation.
// status : PENDING → DENIED
// Le volume ne sera pas visible dans /me/grants.
// Le propriétaire verra le refus via la liste des permissions.
// ─────────────────────────────────────────────────────────────

pub async fn deny_permission(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(permission_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let res = sqlx::query(
        r#"
        UPDATE volume_permissions
        SET status = 'DENIED'
        WHERE id = $1
          AND grantee_id = $2
          AND status = 'PENDING'
        "#,
    )
    .bind(permission_id)
    .bind(auth.user_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SQL error: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Invitation not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

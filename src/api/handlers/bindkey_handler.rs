// src/api/handlers/bindkey_handler.rs
//
// Endpoints :
//   - POST  /bindkeys/enroll
//   - GET   /bindkeys/:id
//   - GET   /users/:id/bindkeys
//   - PATCH /bindkeys/:id/status
//   - POST  /bindkeys/:id/reset
//
// Audit (table audit_logs) :
//   - BINDKEY_CREATE
//   - BINDKEY_STATUS_UPDATE
//   - BINDKEY_REVOKE (LOST/BROKEN/RESET selon ton enum)
//   - BINDKEY_RESET
//
// Modif principale : ne jamais faire `let _ = write_audit_log(...).await;`
//    car ça cache les erreurs DB.
//    On affiche l’erreur si l’insertion audit échoue.
//
// Fix Rust important : `payload.status` n’est pas Copy,
//    donc on le clone AVANT de le binder à SQLx.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension,
    Json,
};

use uuid::Uuid;

use crate::db::AppState;
use crate::api::models::bindkey::{Bindkey, BindkeyStatus};
use crate::api::auth::{AuthUser, require_role};
use crate::api::models::user::UserRole;

// Audit : helper qui insère dans la table audit_logs
use crate::api::audit::{write_audit_log, AuditSeverity};

//
// ─────────────────────────────────────────────────────────────
// POST /bindkeys/enroll
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct EnrollBindkeyRequest {
    pub user_id: Uuid,
    pub bindkey_uid: String,
    pub public_key: String,
    pub fingerprint_template: String,
}

#[derive(serde::Serialize)]
pub struct EnrollBindkeyResponse {
    pub bindkey_id: Uuid,
    pub message: String,
}

pub async fn enroll_bindkey(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Json(payload): Json<EnrollBindkeyRequest>,
) -> Result<Json<EnrollBindkeyResponse>, (StatusCode, String)> {
    // 1) RBAC : seul ENROLLER (ou ADMIN si ton require_role le permet) peut enrôler
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    // 2) Génération de l’ID BindKey
    let bindkey_id = Uuid::new_v4();

    // 3) INSERT bindkey en DB
    let query = r#"
        INSERT INTO bindkeys (
            id, user_id, bindkey_uid, fingerprint_template, public_key, status
        )
        VALUES ($1, $2, $3, $4, $5, 'ACTIVE')
    "#;

    // On exécute l’INSERT mais on garde le Result pour gérer le cas "doublon" proprement
    let insert_res = sqlx::query(query)
        .bind(bindkey_id)
        .bind(payload.user_id)
        .bind(&payload.bindkey_uid)
        .bind(&payload.fingerprint_template)
        .bind(&payload.public_key)
        .execute(&state.db)
        .await;

    match insert_res {
        Ok(_) => {
            // ✅ INSERT OK -> on continue
        }
        Err(e) => {
            // ✅ Si Postgres renvoie une violation de contrainte UNIQUE
            //    SQLSTATE = 23505 => on doit répondre 409 CONFLICT (doublon)
            if let sqlx::Error::Database(db_err) = &e {
                if db_err.code().as_deref() == Some("23505") {
                    return Err((StatusCode::CONFLICT, "BindKey already exists".into()));
                }
            }

            // ❌ Toute autre erreur -> 500
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Enroll BindKey failed: {e}"),
            ));
        }
    }

    // 4)  Audit après succès
    // IMPORTANT : si l’audit échoue, on l’affiche.
    if let Err(e) = write_audit_log(
        &state,
        Some(auth.user_id), // utilisateur qui a déclenché l’action (enroller/admin)
        Some(bindkey_id),   // bindkey concernée
        "BINDKEY_CREATE",
        Some(format!(
            "enrolled bindkey_id={bindkey_id} for user_id={}",
            payload.user_id
        )),
        AuditSeverity::INFO,
    )
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED (BINDKEY_CREATE): {e}");
    }

    Ok(Json(EnrollBindkeyResponse {
        bindkey_id,
        message: "BindKey enrolled successfully".into(),
    }))
}

//
// ─────────────────────────────────────────────────────────────
// GET /bindkeys/:id
// ─────────────────────────────────────────────────────────────

pub async fn get_bindkey(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Bindkey>, (StatusCode, String)> {
    // Simple lecture : pas forcément une action sensible -> audit optionnel
    let bindkey = sqlx::query_as::<_, Bindkey>("SELECT * FROM bindkeys WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "BindKey not found".into()))?;

    Ok(Json(bindkey))
}

//
// ─────────────────────────────────────────────────────────────
// GET /users/:id/bindkeys
// ─────────────────────────────────────────────────────────────

pub async fn get_user_bindkeys(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Bindkey>>, (StatusCode, String)> {
    let bindkeys = sqlx::query_as::<_, Bindkey>("SELECT * FROM bindkeys WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to fetch bindkeys: {e}")))?;

    Ok(Json(bindkeys))
}

//
// ─────────────────────────────────────────────────────────────
// PATCH /bindkeys/:id/status
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct UpdateBindkeyStatusRequest {
    pub status: BindkeyStatus,
}

pub async fn update_bindkey_status(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateBindkeyStatusRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1) RBAC
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    // FIX MOVE :
    // payload.status n’est pas Copy, donc on clone AVANT de l’utiliser dans .bind()
    // et aussi pour pouvoir le réutiliser dans le match + log.
    let new_status = payload.status.clone();

    // 2) Update status en DB
    let res = sqlx::query("UPDATE bindkeys SET status = $1 WHERE id = $2")
        .bind(new_status.clone()) // SQLx consomme la valeur -> on clone
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update status: {e}")))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "BindKey not found".into()));
    }

    // 3) Déterminer l’action audit selon le nouveau status
    let action = match new_status {
        // LOST/BROKEN/RESET = révocation (plus sensible)
        BindkeyStatus::LOST | BindkeyStatus::BROKEN | BindkeyStatus::RESET => "BINDKEY_REVOKE",
        // sinon simple update
        _ => "BINDKEY_STATUS_UPDATE",
    };

    // 4) Déterminer la sévérité (WARNING si révocation)
    let severity = match new_status {
        BindkeyStatus::LOST | BindkeyStatus::BROKEN | BindkeyStatus::RESET => AuditSeverity::WARNING,
        _ => AuditSeverity::INFO,
    };

    // 5) Audit après succès (avec erreur visible si ça échoue)
    if let Err(e) = write_audit_log(
        &state,
        Some(auth.user_id),
        Some(id),
        action,
        Some(format!("bindkey_id={id} new_status={new_status:?}")),
        severity,
    )
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED ({action}): {e}");
    }

    Ok(StatusCode::NO_CONTENT)
}

//
// ─────────────────────────────────────────────────────────────
// POST /bindkeys/:id/reset
// ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ResetBindkeyRequest {
    pub reset_type: String,
}

pub async fn reset_bindkey(
    Extension(auth): Extension<AuthUser>,
    State(state): State<AppState>,
    Path(bindkey_id): Path<Uuid>,
    Json(payload): Json<ResetBindkeyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1) RBAC
    if !require_role(&auth.role, &UserRole::ENROLLER) {
        return Err((StatusCode::FORBIDDEN, "ENROLLER/ADMIN required".into()));
    }

    // 2) Enregistrer l’opération de reset
    let reset_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO bindkey_resets (id, bindkey_id, reset_type, performed_by)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(reset_id)
    .bind(bindkey_id)
    .bind(&payload.reset_type)
    .bind(auth.user_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to reset bindkey: {e}")))?;

    // 3) Audit après succès (WARNING car reset = action sensible)
    if let Err(e) = write_audit_log(
        &state,
        Some(auth.user_id),
        Some(bindkey_id),
        "BINDKEY_RESET",
        Some(format!("reset_id={reset_id} reset_type={}", payload.reset_type)),
        AuditSeverity::WARNING,
    )
    .await
    {
        eprintln!("❌ AUDIT LOG FAILED (BINDKEY_RESET): {e}");
    }

    Ok(StatusCode::NO_CONTENT)
}

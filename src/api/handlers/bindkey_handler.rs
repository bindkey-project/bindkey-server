use axum::{
    Json,
    extract::{State, Path},
    http::StatusCode,
};

use uuid::Uuid;

use crate::db::AppState;
use crate::api::models::bindkey::{Bindkey, BindkeyStatus};

// -------------------------------
// 1) ENROLL: POST /bindkeys/enroll
// -------------------------------

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
    State(state): State<AppState>,
    Json(payload): Json<EnrollBindkeyRequest>,
) -> Result<Json<EnrollBindkeyResponse>, (StatusCode, String)> {

    let bindkey_id = Uuid::new_v4();

    let query = r#"
        INSERT INTO bindkeys (
            id,
            user_id,
            bindkey_uid,
            fingerprint_template,
            public_key,
            status
        )
        VALUES ($1, $2, $3, $4, $5, 'ACTIVE')
    "#;

    sqlx::query(query)
        .bind(bindkey_id)
        .bind(payload.user_id)
        .bind(&payload.bindkey_uid)
        .bind(&payload.fingerprint_template)
        .bind(&payload.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Enroll BindKey failed: {}", e)
        ))?;

    Ok(Json(EnrollBindkeyResponse {
        bindkey_id,
        message: "BindKey enrolled successfully".into(),
    }))
}

// -------------------------------
// 2) GET: GET /bindkeys/:id
// -------------------------------

pub async fn get_bindkey(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Bindkey>, (StatusCode, String)> {

    let bindkey = sqlx::query_as::<_, Bindkey>(
        "SELECT * FROM bindkeys WHERE id = $1"
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (
        StatusCode::NOT_FOUND,
        "BindKey not found".into()
    ))?;

    Ok(Json(bindkey))
}

// -------------------------------
// 3) GET: GET /users/:id/bindkeys
// -------------------------------

pub async fn get_user_bindkeys(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Bindkey>>, (StatusCode, String)> {

    let bindkeys = sqlx::query_as::<_, Bindkey>(
        "SELECT * FROM bindkeys WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Failed to fetch bindkeys: {}", e)
    ))?;

    Ok(Json(bindkeys))
}

// -------------------------------
// 4) PATCH: PATCH /bindkeys/:id/status
// -------------------------------

#[derive(serde::Deserialize)]
pub struct UpdateBindkeyStatusRequest {
    pub status: BindkeyStatus,
}

pub async fn update_bindkey_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateBindkeyStatusRequest>,
) -> Result<StatusCode, (StatusCode, String)> {

    let res = sqlx::query(
        "UPDATE bindkeys SET status = $1 WHERE id = $2"
    )
    .bind(payload.status)
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Failed to update status: {}", e)
    ))?;

    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "BindKey not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

// -------------------------------
// 5) RESET: POST /bindkeys/:id/reset
// -------------------------------

#[derive(serde::Deserialize)]
pub struct ResetBindkeyRequest {
    pub reset_type: String,
    pub performed_by: Uuid,
}

pub async fn reset_bindkey(
    State(state): State<AppState>,
    Path(bindkey_id): Path<Uuid>,
    Json(payload): Json<ResetBindkeyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {

    let reset_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO bindkey_resets (
            id,
            bindkey_id,
            reset_type,
            performed_by
        )
        VALUES ($1, $2, $3, $4)
        "#
    )
    .bind(reset_id)
    .bind(bindkey_id)
    .bind(&payload.reset_type)
    .bind(payload.performed_by)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Failed to reset bindkey: {}", e)
    ))?;

    Ok(StatusCode::NO_CONTENT)
}

use axum::{
    extract::{Request, State}, // Request ici (alias axum::extract::Request)
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};

use chrono::Utc;
use uuid::Uuid;

use crate::api::auth::AuthUser;
use crate::api::models::user::{UserRole, UserStatus};
use crate::db::AppState;

/// Middleware global : valide "Authorization: Bearer <server_token>"
/// et injecte `AuthUser` dans `req.extensions()`.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    // --- BLOC CORRIGÉ POUR LES TESTS ---
    if cfg!(feature = "skip-auth") {
        // En mode test, on injecte un vrai utilisateur existant en base
        // pour éviter les erreurs de clé étrangère sur owner_id, created_by, etc.
        let maybe_user = sqlx::query_as::<_, (Uuid,)>(
            r#"
        SELECT id
        FROM users
        ORDER BY created_at ASC
        LIMIT 1
        "#,
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Test auth SQL error: {e}"),
            )
        })?;

        let user_id = maybe_user.map(|row| row.0).unwrap_or(Uuid::nil());

        req.extensions_mut().insert(AuthUser {
            user_id,
            role: UserRole::ADMIN,
        });

        return Ok(next.run(req).await);
    }
    // ------------------------------------
    // 1) Lire le header Authorization
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // 2) Extraire "Bearer <token>"
    let token = auth_header.strip_prefix("Bearer ").ok_or((
        StatusCode::UNAUTHORIZED,
        "Missing/invalid Bearer token".into(),
    ))?;

    // 3) Charger la session et vérifier expiration
    let (_session_id, user_id, expires_at) =
        sqlx::query_as::<_, (Uuid, Uuid, chrono::DateTime<Utc>)>(
            r#"
            SELECT id, user_id, expires_at
            FROM sessions
            WHERE server_token = $1
            "#,
        )
        .bind(token)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid session token".into()))?;

    if expires_at < Utc::now() {
        return Err((StatusCode::UNAUTHORIZED, "Session expired".into()));
    }

    // 4) Charger role + status du user
    let (role, status) = sqlx::query_as::<_, (UserRole, UserStatus)>(
        r#"
        SELECT role, status
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::UNAUTHORIZED, "User not found".into()))?;

    if status != UserStatus::ACTIVE {
        return Err((StatusCode::FORBIDDEN, "User disabled".into()));
    }

    // 5) Injecter AuthUser pour les handlers (Extension<AuthUser>)
    req.extensions_mut().insert(AuthUser { user_id, role });

    // 6) Continuer vers le handler
    Ok(next.run(req).await)
}

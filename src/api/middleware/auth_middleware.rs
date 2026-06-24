use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};

use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::api::auth::AuthUser;
use crate::api::models::user::{UserRole, UserStatus};
use crate::db::AppState;

// SHA-256 utilisé pour comparer le token reçu avec le hash stocké en base.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Middleware global :
/// - lit `Authorization: Bearer <server_token>`
/// - hash le token reçu avec SHA-256
/// - compare ce hash avec `sessions.server_token` en base
/// - vérifie expiration + statut utilisateur
/// - injecte `AuthUser` dans la requête
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    // En mode test, on bypass l’auth réelle.
    if cfg!(feature = "skip-auth") {
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

    // 1) Lire le header Authorization.
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // 2) Extraire le token brut depuis "Bearer <token>".
    let token = auth_header.strip_prefix("Bearer ").ok_or((
        StatusCode::UNAUTHORIZED,
        "Missing/invalid Bearer token".into(),
    ))?;

    // 3) Hasher le token reçu.
    // La base ne contient jamais le token en clair, seulement son hash SHA-256.
    let token_hash = hash_token(token);

    // [DEBUG] À retirer après diagnostic du 401 admin.
    tracing::warn!(
        target: "auth_debug",
        path = %req.uri().path(),
        token_recv = %token,
        token_hash = %token_hash,
        "auth_middleware: token reçu"
    );

    // 4) Charger la session correspondant au hash.
    let (_session_id, user_id, expires_at) =
        sqlx::query_as::<_, (Uuid, Uuid, chrono::DateTime<Utc>)>(
            r#"
            SELECT id, user_id, expires_at
            FROM sessions
            WHERE server_token = $1
            "#,
        )
        .bind(&token_hash)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            tracing::warn!(
                target: "auth_debug",
                token_hash = %token_hash,
                "auth_middleware: aucune session ne matche ce hash"
            );
            (StatusCode::UNAUTHORIZED, "Invalid session token".into())
        })?;

    // 5) Vérifier expiration.
    if expires_at < Utc::now() {
        return Err((StatusCode::UNAUTHORIZED, "Session expired".into()));
    }

    // 6) Charger rôle + statut utilisateur.
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

    // 7) Refuser un utilisateur désactivé.
    if status != UserStatus::ACTIVE {
        return Err((StatusCode::FORBIDDEN, "User disabled".into()));
    }

    // 8) Injecter AuthUser pour les handlers.
    req.extensions_mut().insert(AuthUser { user_id, role });

    // 9) Continuer vers la route demandée.
    Ok(next.run(req).await)
}

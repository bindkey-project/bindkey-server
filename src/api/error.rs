use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Notre type de résultat personnalisé
pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Erreur de base de données : {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Utilisateur non autorisé : {0}")]
    AuthError(String),

    #[error("Ressource non trouvée : {0}")]
    NotFound(String),

    #[error("Erreur de validation : {0}")]
    ValidationError(String),

    #[error("Erreur cryptographique : {0}")]
    CryptoError(String),

    #[error("Erreur interne du serveur")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            AppError::DatabaseError(e) => {
                // On logue l'erreur réelle en interne mais on cache les détails SQL au client
                eprintln!("DB Error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DATABASE_ERROR",
                    "Une erreur est survenue avec la base de données.".to_string(),
                )
            }
            AppError::AuthError(msg) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg),
            AppError::CryptoError(msg) => {
                eprintln!("Crypto Error: {:?}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "CRYPTO_ERROR", "Erreur lors du traitement sécurisé.".to_string())
            }
            AppError::Internal(msg) => {
                eprintln!("Internal Error: {:?}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", msg)
            }
        };

        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": message
            }
        }));

        (status, body).into_response()
    }
}

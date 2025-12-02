use sqlx::{Pool, Postgres};

/// Alias de type : Pool<Postgres> → PgPool
pub type PgPool = Pool<Postgres>;

/// State global de l'application BindKey.
/// Il contiendra tout ce dont les handlers ont besoin (DB, config, etc.).
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
}

/// Crée un pool de connexion PostgreSQL à partir d'une URL.
/// Vérifie la connexion en faisant un `SELECT 1`.
pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    // Création du pool
    let pool = PgPool::connect(database_url).await?;

    // Test simple : la base répond bien
    sqlx::query("SELECT 1")
        .execute(&pool)
        .await?;

    Ok(pool)
}

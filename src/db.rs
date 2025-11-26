use sqlx::{Pool, Postgres};


/// Type alias pour un pool PostgreSQL.
/// Ça permet d'écrire `PgPool` au lieu de `Pool<Postgres>`.
pub type PgPool = Pool<Postgres>;

/// Crée un pool de connexion PostgreSQL à partir d'une URL.
/// Vérifie la connexion en faisant un `SELECT 1`.

pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {

    //Creation du pool asynchrone
    let pool = PgPool::connect(database_url).await?;

    //Petit Test , on envoie une requete "SELECT 1" pour verifier que la DB Repond
    sqlx::query("SELECT 1")
    .execute(&pool)
    .await?;

    Ok(pool)



}
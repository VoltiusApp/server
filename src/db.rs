use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing::{error, info};

pub async fn create_pool() -> PgPool {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    info!("Initializing PostgreSQL connection pool");

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await
        .unwrap_or_else(|err| {
            error!(error = %err, "Failed to connect to database");
            panic!("Failed to connect to database");
        });

    info!("PostgreSQL connection pool is ready");
    pool
}

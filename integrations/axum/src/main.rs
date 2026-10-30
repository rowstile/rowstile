//! The conformance app's server: ROWSTILE_APP_URL is the app role's connection, ADDR where it listens. It refuses
//! to start on a connection that skips row-level security (check 13).

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt::init(); // what the app logs: the errors it answers 500
    let url = std::env::var("ROWSTILE_APP_URL").unwrap_or_default();
    let pool = match sqlx::PgPool::connect(&url).await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    // a superuser, BYPASSRLS or the tables' owner: the database would filter nothing
    if let Err(e) = rowstile::sqlx::check(&pool).await {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    let listener = tokio::net::TcpListener::bind(std::env::var("ADDR").unwrap_or_default()).await.expect("ADDR");
    axum::serve(listener, conformance::router(pool)).await.expect("serve");
    ExitCode::SUCCESS
}

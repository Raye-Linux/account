use std::net::SocketAddr;

use raye_account_server::{router, AppState, Config, MIGRATOR};
use sqlx::postgres::PgPoolOptions;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RAYE_ACCOUNT_LOG").unwrap_or_else(|_| "info".into()),
        )
        .init();
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("raye-account-server: {e}");
            std::process::exit(2);
        }
    };
    let db = PgPoolOptions::new()
        .max_connections(8)
        .min_connections(0)
        .idle_timeout(std::time::Duration::from_secs(300))
        .connect(&config.database_url)
        .await
        .unwrap_or_else(|e| {
            eprintln!("raye-account-server: database: {e}");
            std::process::exit(1);
        });
    MIGRATOR.run(&db).await.unwrap_or_else(|e| {
        eprintln!("raye-account-server: migrations: {e}");
        std::process::exit(1);
    });
    let listen = config.listen;
    let app = router(AppState::new(db, config));
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap_or_else(|e| {
        eprintln!("raye-account-server: {listen}: {e}");
        std::process::exit(1);
    });
    tracing::info!(%listen, "listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server error");
}

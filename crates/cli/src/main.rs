use std::sync::Arc;

use fishnet_server::{
    create_router,
    password::FilePasswordStore,
    rate_limit::LoginRateLimiter,
    session::SessionStore,
    state::AppState,
};

#[tokio::main]
async fn main() {
    let state = AppState {
        password_store: Arc::new(FilePasswordStore::new(FilePasswordStore::default_path())),
        session_store: Arc::new(SessionStore::new()),
        rate_limiter: Arc::new(LoginRateLimiter::new()),
    };

    let app = create_router(state);

    let host = std::env::var("FISHNET_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let addr = format!("{host}:8473");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("fishnet dashboard API listening on http://{addr}");
    axum::serve(listener, app).await.unwrap();
}

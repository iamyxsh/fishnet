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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8473")
        .await
        .unwrap();
    println!("fishnet dashboard API listening on http://127.0.0.1:8473");
    axum::serve(listener, app).await.unwrap();
}

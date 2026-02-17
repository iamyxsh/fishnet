pub mod auth;
pub mod middleware;
pub mod password;
pub mod rate_limit;
pub mod session;
pub mod state;

use axum::{middleware as axum_middleware, routing::{get, post}, Router};
use tower_http::cors::CorsLayer;

use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    let public_routes = Router::new()
        .route("/api/auth/status", get(auth::status))
        .route("/api/auth/setup", post(auth::setup))
        .route("/api/auth/login", post(auth::login));

    let protected_routes = Router::new()
        .route("/api/auth/logout", post(auth::logout))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::require_auth,
        ));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(CorsLayer::permissive())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use password::FilePasswordStore;
    use rate_limit::LoginRateLimiter;
    use session::SessionStore;

    fn test_state(dir: &std::path::Path) -> AppState {
        AppState {
            password_store: Arc::new(FilePasswordStore::new(dir.join("auth.json"))),
            session_store: Arc::new(SessionStore::new()),
            rate_limiter: Arc::new(LoginRateLimiter::new()),
        }
    }

    async fn body_json(body: Body) -> serde_json::Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn status_request() -> Request<Body> {
        Request::builder()
            .uri("/api/auth/status")
            .body(Body::empty())
            .unwrap()
    }

    fn setup_request(password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/auth/setup")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"password":"{password}","confirm":"{password}"}}"#
            )))
            .unwrap()
    }

    fn login_request(password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"password":"{password}"}}"#)))
            .unwrap()
    }

    fn logout_request(token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/auth/logout")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_full_auth_flow() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        // 1. Status: not initialized
        let resp = app.clone().oneshot(status_request()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["initialized"], false);
        assert_eq!(body["authenticated"], false);

        // 2. Setup password
        let resp = app.clone().oneshot(setup_request("test1234")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);

        // 3. Status: initialized
        let resp = app.clone().oneshot(status_request()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["initialized"], true);

        // 4. Login
        let resp = app.clone().oneshot(login_request("test1234")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        let token = body["token"].as_str().unwrap().to_string();
        assert!(token.starts_with("fn_sess_"));
        assert!(body["expires_at"].is_string());

        // 5. Logout
        let resp = app.clone().oneshot(logout_request(&token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);

        // 6. Token rejected after logout
        let resp = app.clone().oneshot(logout_request(&token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_setup_only_once() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        let resp = app.clone().oneshot(setup_request("test1234")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app.clone().oneshot(setup_request("other123")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        app.clone().oneshot(setup_request("test1234")).await.unwrap();

        let resp = app.clone().oneshot(login_request("wrongpwd")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["error"], "invalid password");
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        app.clone().oneshot(setup_request("test1234")).await.unwrap();

        // 5 failed attempts
        for _ in 0..5 {
            let resp = app.clone().oneshot(login_request("wrongpwd")).await.unwrap();
            assert!(
                resp.status() == StatusCode::UNAUTHORIZED
                    || resp.status() == StatusCode::TOO_MANY_REQUESTS
            );
        }

        // 6th should be rate limited
        let resp = app.clone().oneshot(login_request("wrongpwd")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = body_json(resp.into_body()).await;
        assert!(body["retry_after_seconds"].is_number());
    }

    #[tokio::test]
    async fn test_protected_without_token() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/logout")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

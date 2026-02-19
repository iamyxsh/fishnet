pub mod alert;
pub mod auth;
pub mod config;
#[cfg(feature = "embed-dashboard")]
pub mod dashboard;
pub mod llm_guard;
pub mod middleware;
pub mod password;
pub mod proxy;
pub mod rate_limit;
#[cfg(feature = "dev-seed")]
pub mod seed;
pub mod session;
pub mod state;
pub mod watch;

use axum::{extract::DefaultBodyLimit, middleware as axum_middleware, routing::{any, get, post}, Router};
use tower_http::cors::CorsLayer;

use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    let public_routes = Router::new()
        .route("/api/auth/status", get(auth::status))
        .route("/api/auth/setup", post(auth::setup))
        .route("/api/auth/login", post(auth::login));

    let protected_routes = Router::new()
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/alerts", get(alert::list_alerts))
        .route("/api/alerts/dismiss", post(alert::dismiss_alert))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::require_auth,
        ));

    let proxy_routes = Router::new()
        .route("/proxy/{provider}/{*rest}", any(proxy::handler))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024));

    let router = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(proxy_routes)
        .layer(CorsLayer::permissive())
        .with_state(state);

    #[cfg(feature = "embed-dashboard")]
    let router = router.fallback(dashboard::static_handler);

    router
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use alert::AlertStore;
    use llm_guard::BaselineStore;
    use password::FilePasswordStore;
    use rate_limit::LoginRateLimiter;
    use session::SessionStore;

    fn test_state(dir: &std::path::Path) -> AppState {
        let (_tx, config_rx) = tokio::sync::watch::channel(
            Arc::new(fishnet_types::config::FishnetConfig::default()),
        );
        AppState {
            password_store: Arc::new(FilePasswordStore::new(dir.join("auth.json"))),
            session_store: Arc::new(SessionStore::new()),
            rate_limiter: Arc::new(LoginRateLimiter::new()),
            config_rx,
            alert_store: Arc::new(AlertStore::new()),
            baseline_store: Arc::new(BaselineStore::new()),
            http_client: reqwest::Client::new(),
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

    // --- Proxy + guard integration tests ---

    fn test_state_with_config(
        dir: &std::path::Path,
        config: fishnet_types::config::FishnetConfig,
    ) -> (AppState, tokio::sync::watch::Sender<Arc<fishnet_types::config::FishnetConfig>>) {
        let (tx, config_rx) = tokio::sync::watch::channel(Arc::new(config));
        let state = AppState {
            password_store: Arc::new(FilePasswordStore::new(dir.join("auth.json"))),
            session_store: Arc::new(SessionStore::new()),
            rate_limiter: Arc::new(LoginRateLimiter::new()),
            config_rx,
            alert_store: Arc::new(AlertStore::new()),
            baseline_store: Arc::new(BaselineStore::new()),
            http_client: reqwest::Client::new(),
        };
        (state, tx)
    }

    fn openai_proxy_request(system_prompt: &str, user_msg: &str) -> Request<Body> {
        let body = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg}
            ]
        });
        Request::builder()
            .method("POST")
            .uri("/proxy/openai/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn test_proxy_drift_deny_blocks_request() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.mode = fishnet_types::config::GuardMode::Deny;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        // First request: baseline captured — upstream will fail (no real API) but
        // the guard itself should pass. The upstream error means we get BAD_GATEWAY.
        let resp = app
            .clone()
            .oneshot(openai_proxy_request("You are helpful.", "Hi"))
            .await
            .unwrap();
        // Not 403 — guard passed, upstream failed
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);

        // Second request with different prompt: drift → DENIED
        let resp = app
            .clone()
            .oneshot(openai_proxy_request("You are evil.", "Hi"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp.into_body()).await;
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("System prompt drift detected"));

        // Verify alert was created
        let alerts = state.alert_store.list().await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, alert::AlertType::PromptDrift);
    }

    #[tokio::test]
    async fn test_proxy_size_guard_deny_blocks_oversized() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.enabled = false; // disable drift for this test
        config.llm.prompt_size_guard.max_prompt_tokens = 100; // very low limit: 400 chars
        config.llm.prompt_size_guard.action = fishnet_types::config::GuardAction::Deny;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        // Send a prompt with > 400 chars
        let big_content = "x".repeat(500);
        let resp = app
            .clone()
            .oneshot(openai_proxy_request(&big_content, "Hi"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp.into_body()).await;
        assert!(body["error"].as_str().unwrap().contains("exceeds limit"));
    }

    #[tokio::test]
    async fn test_proxy_size_guard_alert_allows_but_creates_alert() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.max_prompt_tokens = 100;
        config.llm.prompt_size_guard.action = fishnet_types::config::GuardAction::Alert;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let big_content = "x".repeat(500);
        let resp = app
            .clone()
            .oneshot(openai_proxy_request(&big_content, "Hi"))
            .await
            .unwrap();
        // Should NOT be 403 — alert mode allows the request
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);

        // But alert should have been created
        let alerts = state.alert_store.list().await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, alert::AlertType::PromptSize);
    }

    #[tokio::test]
    async fn test_proxy_guards_disabled_passes_through() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.enabled = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let big_content = "x".repeat(10000);
        let resp = app
            .clone()
            .oneshot(openai_proxy_request(&big_content, "Hi"))
            .await
            .unwrap();
        // Guards disabled: no 403, goes through to upstream (which fails with BAD_GATEWAY)
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
        assert!(state.alert_store.list().await.is_empty());
        assert!(state.baseline_store.is_empty().await);
    }

    #[tokio::test]
    async fn test_proxy_hot_reload_toggle_off() {
        let dir = tempfile::tempdir().unwrap();
        let config = fishnet_types::config::FishnetConfig::default();
        let (state, tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        // First request: baseline captured
        let resp = app
            .clone()
            .oneshot(openai_proxy_request("hello", "Hi"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);

        // Hot-reload: disable prompt drift
        let mut new_config = fishnet_types::config::FishnetConfig::default();
        new_config.llm.prompt_drift.enabled = false;
        tx.send(Arc::new(new_config)).unwrap();

        // Different prompt: should NOT trigger drift since disabled
        let resp = app
            .clone()
            .oneshot(openai_proxy_request("totally different", "Hi"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
        assert!(state.alert_store.list().await.is_empty());
    }

    #[tokio::test]
    async fn test_proxy_unknown_provider() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/proxy/unknown/v1/chat")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_proxy_invalid_json_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/proxy/openai/v1/chat/completions")
                    .header("content-type", "application/json")
                    .body(Body::from("not valid json {{{"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp.into_body()).await;
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("not valid JSON"));
    }

    #[tokio::test]
    async fn test_proxy_non_json_body_passes_through() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state);

        // Non-JSON content-type should not be rejected as invalid JSON —
        // it bypasses guard checks and forwards to upstream (which fails
        // with BAD_GATEWAY since there's no real server).
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/proxy/openai/v1/files")
                    .header("content-type", "multipart/form-data; boundary=abc")
                    .body(Body::from("--abc\r\ncontent\r\n--abc--"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Not 400 — non-JSON bodies are forwarded, not rejected
        assert_ne!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

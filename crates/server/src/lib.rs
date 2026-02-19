pub mod alert;
pub mod auth;
pub mod config;
pub mod constants;
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
pub mod spend;
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
        .route("/api/alerts/config", get(alert::get_alert_config).put(alert::update_alert_config))
        .route("/api/spend", get(spend::get_spend))
        .route("/api/spend/budgets", get(spend::get_budgets).put(spend::set_budget))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::require_auth,
        ));

    let proxy_routes = Router::new()
        .route("/proxy/{provider}/{*rest}", any(proxy::handler))
        .layer(DefaultBodyLimit::max(constants::MAX_BODY_SIZE));

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
    use rate_limit::{LoginRateLimiter, ProxyRateLimiter};
    use session::SessionStore;
    use spend::SpendStore;

    fn test_state(dir: &std::path::Path) -> AppState {
        let (_tx, config_rx) = tokio::sync::watch::channel(
            Arc::new(fishnet_types::config::FishnetConfig::default()),
        );
        AppState {
            password_store: Arc::new(FilePasswordStore::new(dir.join("auth.json"))),
            session_store: Arc::new(SessionStore::new()),
            rate_limiter: Arc::new(LoginRateLimiter::new()),
            proxy_rate_limiter: Arc::new(ProxyRateLimiter::new()),
            config_rx,
            config_path: Some(dir.join("fishnet.toml")),
            alert_store: Arc::new(AlertStore::new()),
            baseline_store: Arc::new(BaselineStore::new()),
            spend_store: Arc::new(SpendStore::open_in_memory().unwrap()),
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

        let resp = app.clone().oneshot(status_request()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["initialized"], false);
        assert_eq!(body["authenticated"], false);

        let resp = app.clone().oneshot(setup_request("test1234")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);

        let resp = app.clone().oneshot(status_request()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["initialized"], true);

        let resp = app.clone().oneshot(login_request("test1234")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        let token = body["token"].as_str().unwrap().to_string();
        assert!(token.starts_with("fn_sess_"));
        assert!(body["expires_at"].is_string());

        let resp = app.clone().oneshot(logout_request(&token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);

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

        for _ in 0..5 {
            let resp = app.clone().oneshot(login_request("wrongpwd")).await.unwrap();
            assert!(
                resp.status() == StatusCode::UNAUTHORIZED
                    || resp.status() == StatusCode::TOO_MANY_REQUESTS
            );
        }

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

    fn test_state_with_config(
        dir: &std::path::Path,
        config: fishnet_types::config::FishnetConfig,
    ) -> (AppState, tokio::sync::watch::Sender<Arc<fishnet_types::config::FishnetConfig>>) {
        let (tx, config_rx) = tokio::sync::watch::channel(Arc::new(config));
        let state = AppState {
            password_store: Arc::new(FilePasswordStore::new(dir.join("auth.json"))),
            session_store: Arc::new(SessionStore::new()),
            rate_limiter: Arc::new(LoginRateLimiter::new()),
            proxy_rate_limiter: Arc::new(ProxyRateLimiter::new()),
            config_rx,
            config_path: Some(dir.join("fishnet.toml")),
            alert_store: Arc::new(AlertStore::new()),
            baseline_store: Arc::new(BaselineStore::new()),
            spend_store: Arc::new(SpendStore::open_in_memory().unwrap()),
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

        let resp = app
            .clone()
            .oneshot(openai_proxy_request("You are helpful.", "Hi"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);

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

        let alerts = state.alert_store.list().await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, alert::AlertType::PromptDrift);
    }

    #[tokio::test]
    async fn test_proxy_size_guard_deny_blocks_oversized() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.max_prompt_tokens = 100;
        config.llm.prompt_size_guard.action = fishnet_types::config::GuardAction::Deny;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

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
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);

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

        let resp = app
            .clone()
            .oneshot(openai_proxy_request("hello", "Hi"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);

        let mut new_config = fishnet_types::config::FishnetConfig::default();
        new_config.llm.prompt_drift.enabled = false;
        tx.send(Arc::new(new_config)).unwrap();

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
        assert_ne!(resp.status(), StatusCode::BAD_REQUEST);
    }

    async fn setup_and_login(app: &Router) -> String {
        app.clone().oneshot(setup_request("test1234")).await.unwrap();
        let resp = app.clone().oneshot(login_request("test1234")).await.unwrap();
        let body = body_json(resp.into_body()).await;
        body["token"].as_str().unwrap().to_string()
    }

    fn authed_get(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn authed_put(uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn authed_post(uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn test_alerts_require_auth() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/api/alerts").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_alerts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app.clone().oneshot(authed_get("/api/alerts", &token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_list_alerts_with_data_and_dismiss() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        state.alert_store.create(
            alert::AlertType::PromptDrift, alert::AlertSeverity::Critical,
            "openai", "drift detected".to_string(),
        ).await;
        state.alert_store.create(
            alert::AlertType::PromptSize, alert::AlertSeverity::Warning,
            "anthropic", "too big".to_string(),
        ).await;

        let resp = app.clone().oneshot(authed_get("/api/alerts", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 2);

        assert_eq!(body["alerts"][0]["service"], "openai");
        assert_eq!(body["alerts"][0]["type"], "prompt_drift");
        assert_eq!(body["alerts"][1]["service"], "anthropic");
        assert_eq!(body["alerts"][1]["type"], "prompt_size");

        let resp = app.clone().oneshot(authed_get("/api/alerts?type=prompt_drift", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        let alerts = body["alerts"].as_array().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["type"], "prompt_drift");

        let resp = app.clone().oneshot(authed_get("/api/alerts?dismissed=false", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 2);

        let alert_id = "alert_001";
        let resp = app.clone().oneshot(authed_post(
            "/api/alerts/dismiss", &token,
            serde_json::json!({"id": alert_id}),
        )).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);

        let resp = app.clone().oneshot(authed_get("/api/alerts?dismissed=true", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        let alerts = body["alerts"].as_array().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["dismissed"], true);

        let resp = app.clone().oneshot(authed_get("/api/alerts?dismissed=false", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_list_alerts_pagination() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        for i in 0..5 {
            state.alert_store.create(
                alert::AlertType::PromptDrift, alert::AlertSeverity::Warning,
                "openai", format!("alert {i}"),
            ).await;
        }

        let resp = app.clone().oneshot(authed_get("/api/alerts?limit=2", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 2);

        let resp = app.clone().oneshot(authed_get("/api/alerts?skip=3", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 2);

        let resp = app.clone().oneshot(authed_get("/api/alerts?skip=2&limit=2", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 2);

        let resp = app.clone().oneshot(authed_get("/api/alerts?skip=100", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_dismiss_nonexistent_alert() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app.clone().oneshot(authed_post(
            "/api/alerts/dismiss", &token,
            serde_json::json!({"id": "alert_999"}),
        )).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_alert_config() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app.clone().oneshot(authed_get("/api/alerts/config", &token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;

        assert_eq!(body["toggles"]["prompt_drift"], true);
        assert_eq!(body["toggles"]["prompt_size"], true);
        assert_eq!(body["toggles"]["budget_warning"], true);
        assert_eq!(body["toggles"]["budget_exceeded"], true);
        assert_eq!(body["toggles"]["onchain_denied"], true);
        assert_eq!(body["toggles"]["rate_limit_hit"], true);
        assert_eq!(body["retention_days"], 30);
    }

    #[tokio::test]
    async fn test_update_alert_config_partial() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        let config_path = dir.path().join("fishnet.toml");
        std::fs::write(&config_path, "").unwrap();

        let resp = app.clone().oneshot(authed_put(
            "/api/alerts/config", &token,
            serde_json::json!({"prompt_drift": false}),
        )).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);
        assert_eq!(body["toggles"]["prompt_drift"], false);
        assert_eq!(body["toggles"]["prompt_size"], true);
        assert_eq!(body["toggles"]["budget_warning"], true);

        let content = std::fs::read_to_string(&config_path).unwrap();
        let reloaded: fishnet_types::config::FishnetConfig = toml::from_str(&content).unwrap();
        assert!(!reloaded.alerts.prompt_drift);
        assert!(reloaded.alerts.prompt_size);
    }

    #[tokio::test]
    async fn test_spend_requires_auth() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/api/spend").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_spend_track_spend_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.track_spend = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app.clone().oneshot(authed_get("/api/spend", &token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["enabled"], false);
        assert!(body.get("daily").is_none());
    }

    #[tokio::test]
    async fn test_spend_empty_data() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app.clone().oneshot(authed_get("/api/spend", &token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["enabled"], true);
        assert_eq!(body["daily"].as_array().unwrap().len(), 0);
        assert_eq!(body["config"]["track_spend"], true);
        assert_eq!(body["config"]["spend_history_days"], 30);
    }

    #[tokio::test]
    async fn test_spend_with_data() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        let today = chrono::Utc::now().date_naive().format("%Y-%m-%d").to_string();
        state.spend_store.record_spend("openai", &today, 4.20).unwrap();
        state.spend_store.record_spend("anthropic", &today, 1.80).unwrap();

        let resp = app.clone().oneshot(authed_get("/api/spend", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["enabled"], true);
        assert_eq!(body["daily"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_spend_days_param_capped() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.dashboard.spend_history_days = 7;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        let resp = app.clone().oneshot(authed_get("/api/spend?days=365", &token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_spend_budgets_crud() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app.clone().oneshot(authed_get("/api/spend/budgets", &token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["budgets"].as_array().unwrap().len(), 0);

        let resp = app.clone().oneshot(authed_put(
            "/api/spend/budgets", &token,
            serde_json::json!({
                "service": "openai",
                "daily_budget_usd": 20.0,
                "monthly_budget_usd": 500.0
            }),
        )).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);
        assert_eq!(body["budget"]["service"], "openai");
        assert_eq!(body["budget"]["daily_budget_usd"], 20.0);

        let resp = app.clone().oneshot(authed_get("/api/spend/budgets", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        let budgets = body["budgets"].as_array().unwrap();
        assert_eq!(budgets.len(), 1);
        assert_eq!(budgets[0]["service"], "openai");

        let resp = app.clone().oneshot(authed_put(
            "/api/spend/budgets", &token,
            serde_json::json!({
                "service": "openai",
                "daily_budget_usd": 30.0
            }),
        )).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app.clone().oneshot(authed_get("/api/spend/budgets", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["budgets"][0]["daily_budget_usd"], 30.0);
    }

    #[tokio::test]
    async fn test_spend_budget_warning_active() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.budget_warning_pct = 80;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        state.spend_store.set_budget(&spend::ServiceBudget {
            service: "openai".to_string(),
            daily_budget_usd: 10.0,
            monthly_budget_usd: None,
            updated_at: 0,
        }).unwrap();

        let today = chrono::Utc::now().date_naive().format("%Y-%m-%d").to_string();
        state.spend_store.record_spend("openai", &today, 9.0).unwrap();

        let resp = app.clone().oneshot(authed_get("/api/spend", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["budgets"]["openai"]["warning_active"], true);
        assert_eq!(body["budgets"]["openai"]["daily_limit"], 10.0);
        assert_eq!(body["budgets"]["openai"]["spent_today"], 9.0);
    }

    #[tokio::test]
    async fn test_spend_budget_warning_inactive_when_pct_zero() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.budget_warning_pct = 0;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        state.spend_store.set_budget(&spend::ServiceBudget {
            service: "openai".to_string(),
            daily_budget_usd: 10.0,
            monthly_budget_usd: None,
            updated_at: 0,
        }).unwrap();

        let today = chrono::Utc::now().date_naive().format("%Y-%m-%d").to_string();
        state.spend_store.record_spend("openai", &today, 9.0).unwrap();

        let resp = app.clone().oneshot(authed_get("/api/spend", &token)).await.unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["budgets"]["openai"]["warning_active"], false);
    }

    #[tokio::test]
    async fn test_proxy_rate_limit_returns_429() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.rate_limit_per_minute = 2;
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.enabled = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        for _ in 0..2 {
            let resp = app
                .clone()
                .oneshot(openai_proxy_request("hello", "Hi"))
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        let resp = app
            .clone()
            .oneshot(openai_proxy_request("hello", "Hi"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = body_json(resp.into_body()).await;
        assert!(body["retry_after_seconds"].is_number());
        assert!(body["error"].as_str().unwrap().contains("rate limit"));

        let alerts = state.alert_store.list().await;
        assert!(alerts.iter().any(|a| a.alert_type == alert::AlertType::RateLimitHit));
    }

    #[tokio::test]
    async fn test_proxy_rate_limit_zero_disables() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.rate_limit_per_minute = 0;
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.enabled = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        for _ in 0..10 {
            let resp = app
                .clone()
                .oneshot(openai_proxy_request("hello", "Hi"))
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    #[tokio::test]
    async fn test_proxy_rate_limit_alert_toggle_off() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.rate_limit_per_minute = 1;
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.enabled = false;
        config.alerts.rate_limit_hit = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        app.clone().oneshot(openai_proxy_request("hello", "Hi")).await.unwrap();

        let resp = app.clone().oneshot(openai_proxy_request("hello", "Hi")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        assert!(state.alert_store.list().await.is_empty());
    }

    #[tokio::test]
    async fn test_proxy_drift_alert_toggle_off_still_denies() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.mode = fishnet_types::config::GuardMode::Deny;
        config.alerts.prompt_drift = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        app.clone().oneshot(openai_proxy_request("You are helpful.", "Hi")).await.unwrap();

        let resp = app.clone().oneshot(openai_proxy_request("You are evil.", "Hi")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        assert!(state.alert_store.list().await.is_empty());
    }

    #[tokio::test]
    async fn test_proxy_size_alert_toggle_off_still_denies() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.max_prompt_tokens = 100;
        config.llm.prompt_size_guard.action = fishnet_types::config::GuardAction::Deny;
        config.alerts.prompt_size = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let big_content = "x".repeat(500);
        let resp = app.clone().oneshot(openai_proxy_request(&big_content, "Hi")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        assert!(state.alert_store.list().await.is_empty());
    }
}

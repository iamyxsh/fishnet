use std::sync::Arc;

use fishnet_types::config::FishnetConfig;
use tokio::sync::watch;

use crate::alert::AlertStore;
use crate::llm_guard::BaselineStore;
use crate::password::PasswordVerifier;
use crate::rate_limit::LoginRateLimiter;
use crate::session::SessionStore;

#[derive(Clone)]
pub struct AppState {
    pub password_store: Arc<dyn PasswordVerifier>,
    pub session_store: Arc<SessionStore>,
    pub rate_limiter: Arc<LoginRateLimiter>,
    pub config_rx: watch::Receiver<Arc<FishnetConfig>>,
    pub alert_store: Arc<AlertStore>,
    pub baseline_store: Arc<BaselineStore>,
    pub http_client: reqwest::Client,
}

impl AppState {
    /// Get a snapshot of the current configuration.
    /// Cheap to call — just clones an Arc.
    pub fn config(&self) -> Arc<FishnetConfig> {
        self.config_rx.borrow().clone()
    }
}

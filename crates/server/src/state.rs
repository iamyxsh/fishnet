use std::path::PathBuf;
use std::sync::Arc;

use fishnet_types::config::FishnetConfig;
use tokio::sync::watch;

use crate::alert::AlertStore;
use crate::llm_guard::BaselineStore;
use crate::onchain::OnchainStore;
use crate::password::PasswordVerifier;
use crate::rate_limit::{LoginRateLimiter, ProxyRateLimiter};
use crate::session::SessionStore;
use crate::signer::SignerTrait;
use crate::spend::SpendStore;

#[derive(Clone)]
pub struct AppState {
    pub password_store: Arc<dyn PasswordVerifier>,
    pub session_store: Arc<SessionStore>,
    pub rate_limiter: Arc<LoginRateLimiter>,
    pub proxy_rate_limiter: Arc<ProxyRateLimiter>,
    pub config_rx: watch::Receiver<Arc<FishnetConfig>>,
    pub config_path: PathBuf,
    pub alert_store: Arc<AlertStore>,
    pub baseline_store: Arc<BaselineStore>,
    pub spend_store: Arc<SpendStore>,
    pub http_client: reqwest::Client,
    pub onchain_store: Arc<OnchainStore>,
    pub signer: Arc<dyn SignerTrait>,
}

impl AppState {
    pub fn config(&self) -> Arc<FishnetConfig> {
        self.config_rx.borrow().clone()
    }
}

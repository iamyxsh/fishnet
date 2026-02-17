use std::sync::Arc;

use crate::password::PasswordVerifier;
use crate::rate_limit::LoginRateLimiter;
use crate::session::SessionStore;

#[derive(Clone)]
pub struct AppState {
    pub password_store: Arc<dyn PasswordVerifier>,
    pub session_store: Arc<SessionStore>,
    pub rate_limiter: Arc<LoginRateLimiter>,
}

use std::collections::HashMap;

use chrono::{DateTime, TimeDelta, Utc};
use tokio::sync::Mutex;

use crate::constants;

pub struct LoginRateLimiter {
    failures: Mutex<Vec<DateTime<Utc>>>,
    window: TimeDelta,
    max_failures: usize,
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            failures: Mutex::new(Vec::new()),
            window: TimeDelta::seconds(constants::RATE_LIMIT_WINDOW_SECS),
            max_failures: constants::LOGIN_MAX_FAILURES,
        }
    }

    pub async fn check_rate_limit(&self) -> Result<(), u64> {
        let mut failures = self.failures.lock().await;
        let now = Utc::now();
        let cutoff = now - self.window;

        failures.retain(|t| *t > cutoff);

        if failures.len() >= self.max_failures {
            let oldest = failures.first().unwrap();
            let retry_after = (*oldest + self.window - now).num_seconds().max(1) as u64;
            return Err(retry_after);
        }

        Ok(())
    }

    pub async fn record_failure(&self) {
        let mut failures = self.failures.lock().await;
        failures.push(Utc::now());
    }

    async fn failure_count(&self) -> usize {
        let failures = self.failures.lock().await;
        let now = Utc::now();
        let cutoff = now - self.window;
        failures.iter().filter(|t| **t > cutoff).count()
    }

    pub async fn progressive_delay(&self) {
        let count = self.failure_count().await;
        let delay = match count {
            0..=2 => 0,
            3 => 1,
            4 => 2,
            _ => 5,
        };
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }
    }

    pub async fn reset(&self) {
        let mut failures = self.failures.lock().await;
        failures.clear();
    }
}

pub struct ProxyRateLimiter {
    windows: Mutex<HashMap<String, Vec<DateTime<Utc>>>>,
}

impl Default for ProxyRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyRateLimiter {
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    pub async fn check_and_record(&self, service: &str, max_per_minute: u32) -> Result<(), u64> {
        let mut windows = self.windows.lock().await;
        let now = Utc::now();
        let cutoff = now - TimeDelta::seconds(constants::RATE_LIMIT_WINDOW_SECS);

        let entries = windows.entry(service.to_string()).or_default();
        entries.retain(|t| *t > cutoff);

        if entries.len() >= max_per_minute as usize {
            let oldest = entries.first().unwrap();
            let retry_after = (*oldest + TimeDelta::seconds(constants::RATE_LIMIT_WINDOW_SECS) - now)
                .num_seconds()
                .max(1) as u64;
            return Err(retry_after);
        }

        entries.push(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proxy_rate_limiter_allows_within_limit() {
        let limiter = ProxyRateLimiter::new();
        for _ in 0..5 {
            assert!(limiter.check_and_record("openai", 10).await.is_ok());
        }
    }

    #[tokio::test]
    async fn proxy_rate_limiter_blocks_over_limit() {
        let limiter = ProxyRateLimiter::new();
        for _ in 0..3 {
            assert!(limiter.check_and_record("openai", 3).await.is_ok());
        }
        let result = limiter.check_and_record("openai", 3).await;
        assert!(result.is_err());
        let retry_after = result.unwrap_err();
        assert!(retry_after > 0);
    }

    #[tokio::test]
    async fn proxy_rate_limiter_services_are_independent() {
        let limiter = ProxyRateLimiter::new();
        for _ in 0..3 {
            assert!(limiter.check_and_record("openai", 3).await.is_ok());
        }
        assert!(limiter.check_and_record("openai", 3).await.is_err());
        assert!(limiter.check_and_record("anthropic", 3).await.is_ok());
    }
}

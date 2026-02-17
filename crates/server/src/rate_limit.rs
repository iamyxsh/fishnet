use chrono::{DateTime, TimeDelta, Utc};
use tokio::sync::Mutex;

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
            window: TimeDelta::seconds(60),
            max_failures: 5,
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

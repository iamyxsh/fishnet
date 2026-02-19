use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::state::AppState;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    PromptDrift,
    PromptSize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Critical,
    Warning,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub id: String,
    #[serde(rename = "type")]
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub service: String,
    pub message: String,
    pub timestamp: i64,
    pub dismissed: bool,
}

pub struct AlertStore {
    alerts: RwLock<VecDeque<Alert>>,
    counter: AtomicU64,
}

const MAX_ALERTS: usize = 1_000;

impl AlertStore {
    pub fn new() -> Self {
        Self {
            alerts: RwLock::new(VecDeque::new()),
            counter: AtomicU64::new(1),
        }
    }

    pub async fn create(
        &self,
        alert_type: AlertType,
        severity: AlertSeverity,
        service: &str,
        message: String,
    ) -> Alert {
        let id = format!(
            "alert_{:03}",
            self.counter.fetch_add(1, Ordering::Relaxed)
        );
        let alert = Alert {
            id,
            alert_type,
            severity,
            service: service.to_string(),
            message,
            timestamp: chrono::Utc::now().timestamp(),
            dismissed: false,
        };
        let cloned = alert.clone();
        let mut alerts = self.alerts.write().await;
        if alerts.len() >= MAX_ALERTS {
            alerts.pop_front();
        }
        alerts.push_back(alert);
        cloned
    }

    pub async fn list(&self) -> Vec<Alert> {
        Vec::from(self.alerts.read().await.clone())
    }

    pub async fn dismiss(&self, id: &str) -> bool {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.iter_mut().find(|a| a.id == id) {
            alert.dismissed = true;
            true
        } else {
            false
        }
    }
}

pub async fn list_alerts(State(state): State<AppState>) -> impl IntoResponse {
    let alerts = state.alert_store.list().await;
    Json(serde_json::json!({ "alerts": alerts }))
}

pub async fn dismiss_alert(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = match body.get("id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing alert id" })),
            )
                .into_response();
        }
    };

    if state.alert_store.dismiss(id).await {
        Json(serde_json::json!({ "success": true })).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "alert not found" })),
        )
            .into_response()
    }
}

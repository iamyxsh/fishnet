use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::state::AppState;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    PromptDrift,
    PromptSize,
    BudgetWarning,
    BudgetExceeded,
    OnchainDenied,
    RateLimitHit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Deserialize)]
pub struct AlertQuery {
    #[serde(rename = "type")]
    pub alert_type: Option<AlertType>,
    pub dismissed: Option<bool>,
    pub limit: Option<usize>,
    pub skip: Option<usize>,
}

pub async fn list_alerts(
    State(state): State<AppState>,
    Query(query): Query<AlertQuery>,
) -> impl IntoResponse {
    let mut alerts = state.alert_store.list().await;

    if let Some(ref t) = query.alert_type {
        alerts.retain(|a| &a.alert_type == t);
    }

    if let Some(dismissed) = query.dismissed {
        alerts.retain(|a| a.dismissed == dismissed);
    }

    let skip = query.skip.unwrap_or(0);
    let alerts: Vec<Alert> = match query.limit {
        Some(limit) => alerts.into_iter().skip(skip).take(limit).collect(),
        None => alerts.into_iter().skip(skip).collect(),
    };

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

pub async fn get_alert_config(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config();
    Json(serde_json::json!({
        "toggles": {
            "prompt_drift": config.alerts.prompt_drift,
            "prompt_size": config.alerts.prompt_size,
            "budget_warning": config.alerts.budget_warning,
            "budget_exceeded": config.alerts.budget_exceeded,
            "onchain_denied": config.alerts.onchain_denied,
            "rate_limit_hit": config.alerts.rate_limit_hit,
        },
        "retention_days": config.alerts.retention_days,
    }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateAlertConfigRequest {
    pub prompt_drift: Option<bool>,
    pub prompt_size: Option<bool>,
    pub budget_warning: Option<bool>,
    pub budget_exceeded: Option<bool>,
    pub onchain_denied: Option<bool>,
    pub rate_limit_hit: Option<bool>,
    pub retention_days: Option<u32>,
}

pub async fn update_alert_config(
    State(state): State<AppState>,
    Json(req): Json<UpdateAlertConfigRequest>,
) -> impl IntoResponse {
    let current = state.config();
    let mut updated = (*current).clone();

    if let Some(v) = req.prompt_drift {
        updated.alerts.prompt_drift = v;
    }
    if let Some(v) = req.prompt_size {
        updated.alerts.prompt_size = v;
    }
    if let Some(v) = req.budget_warning {
        updated.alerts.budget_warning = v;
    }
    if let Some(v) = req.budget_exceeded {
        updated.alerts.budget_exceeded = v;
    }
    if let Some(v) = req.onchain_denied {
        updated.alerts.onchain_denied = v;
    }
    if let Some(v) = req.rate_limit_hit {
        updated.alerts.rate_limit_hit = v;
    }
    if let Some(v) = req.retention_days {
        updated.alerts.retention_days = v;
    }

    let config_path = match &state.config_path {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "no config file path configured" })),
            )
                .into_response();
        }
    };

    match crate::config::save_config(&config_path, &updated) {
        Ok(()) => Json(serde_json::json!({
            "success": true,
            "toggles": {
                "prompt_drift": updated.alerts.prompt_drift,
                "prompt_size": updated.alerts.prompt_size,
                "budget_warning": updated.alerts.budget_warning,
                "budget_exceeded": updated.alerts.budget_exceeded,
                "onchain_denied": updated.alerts.onchain_denied,
                "rate_limit_hit": updated.alerts.rate_limit_hit,
            },
            "retention_days": updated.alerts.retention_days,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("failed to save config: {e}") })),
        )
            .into_response(),
    }
}

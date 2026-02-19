use crate::alert::{AlertSeverity, AlertStore, AlertType};
use crate::state::AppState;

pub async fn run(state: &AppState) {
    eprintln!("[fishnet] dev-seed: populating sample data");
    seed_alerts(&state.alert_store).await;
}

async fn seed_alerts(store: &AlertStore) {
    let alerts = [
        (
            AlertType::PromptDrift,
            AlertSeverity::Critical,
            "openai",
            "System prompt changed. Previous: 0x3a1f…c8e2 Current: 0x91b4…d7f0",
        ),
        (
            AlertType::PromptDrift,
            AlertSeverity::Critical,
            "anthropic",
            "System prompt changed. Previous: 0x7e2d…a1b3 Current: 0xf4c8…52e9",
        ),
        (
            AlertType::PromptSize,
            AlertSeverity::Warning,
            "openai",
            "Oversized prompt: ~62,500 tokens (limit: 50,000). Action: alert only.",
        ),
        (
            AlertType::PromptSize,
            AlertSeverity::Warning,
            "anthropic",
            "Prompt size 210,000 chars exceeds limit of 200,000. Action: denied.",
        ),
        (
            AlertType::PromptDrift,
            AlertSeverity::Critical,
            "openai",
            "System prompt changed. Previous: 0x3a1f…c8e2 Current: 0xbb07…19d3 (hashing first 500 chars)",
        ),
    ];

    for (alert_type, severity, service, message) in alerts {
        store
            .create(alert_type, severity, service, message.to_string())
            .await;
    }

    eprintln!("[fishnet] dev-seed: created {} sample alerts", alerts.len());
}

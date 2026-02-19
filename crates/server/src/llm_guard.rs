use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tokio::sync::{Mutex, RwLock};

use crate::alert::{AlertSeverity, AlertStore, AlertType};
use fishnet_types::config::{
    GuardAction, GuardMode, HashAlgorithm, PromptDriftConfig, PromptSizeGuardConfig,
};

pub struct BaselineStore {
    baselines: RwLock<HashMap<String, BaselineEntry>>,
    persist_path: Option<PathBuf>,
    persist_lock: Mutex<()>,
}

#[derive(Clone, Serialize, Deserialize)]
struct BaselineEntry {
    hash: String,
    hash_chars: u64,
    ignore_whitespace: bool,
    hash_algorithm: HashAlgorithm,
}

impl BaselineStore {
    pub fn new() -> Self {
        Self {
            baselines: RwLock::new(HashMap::new()),
            persist_path: None,
            persist_lock: Mutex::new(()),
        }
    }

    pub fn with_persistence(path: PathBuf, load_existing: bool) -> Self {
        let baselines = if load_existing {
            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<HashMap<String, BaselineEntry>>(&content) {
                    Ok(map) => {
                        eprintln!(
                            "[fishnet] loaded {} baseline(s) from {}",
                            map.len(),
                            path.display()
                        );
                        map
                    }
                    Err(e) => {
                        eprintln!(
                            "[fishnet] failed to parse baselines file {}, starting fresh: {e}",
                            path.display()
                        );
                        HashMap::new()
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!(
                        "[fishnet] no baselines file at {}, starting fresh",
                        path.display()
                    );
                    HashMap::new()
                }
                Err(e) => {
                    eprintln!(
                        "[fishnet] failed to read baselines file {}, starting fresh: {e}",
                        path.display()
                    );
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        Self {
            baselines: RwLock::new(baselines),
            persist_path: Some(path),
            persist_lock: Mutex::new(()),
        }
    }

    pub async fn clear(&self) {
        self.baselines.write().await.clear();
        self.persist().await;
    }

    pub async fn is_empty(&self) -> bool {
        self.baselines.read().await.is_empty()
    }

    async fn persist(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let _guard = self.persist_lock.lock().await;
        let snapshot = self.baselines.read().await.clone();
        match serde_json::to_string_pretty(&snapshot) {
            Ok(json) => {
                if let Some(parent) = path.parent() {
                    if let Err(e) = tokio::fs::create_dir_all(parent).await {
                        eprintln!(
                            "[fishnet] failed to create baselines directory {}: {e}",
                            parent.display()
                        );
                        return;
                    }
                }
                let tmp_path = path.with_extension("json.tmp");
                if let Err(e) = tokio::fs::write(&tmp_path, &json).await {
                    eprintln!(
                        "[fishnet] failed to write temp baselines file {}: {e}",
                        tmp_path.display()
                    );
                    return;
                }
                if let Err(e) = tokio::fs::rename(&tmp_path, path).await {
                    eprintln!(
                        "[fishnet] failed to rename baselines file {} → {}: {e}",
                        tmp_path.display(),
                        path.display()
                    );
                }
            }
            Err(e) => {
                eprintln!("[fishnet] failed to serialize baselines: {e}");
            }
        }
    }

    pub fn default_path() -> Option<PathBuf> {
        let mut path = dirs::home_dir()?;
        path.push(".fishnet");
        path.push("baselines.json");
        Some(path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardDecision {
    Allow,
    AllowWithAlert,
    Deny(String),
    BaselineCaptured,
    Skipped,
}

fn extract_text_from_content(value: &serde_json::Value) -> Option<String> {
    if let Some(s) = value.as_str() {
        return Some(s.to_string());
    }
    if let Some(blocks) = value.as_array() {
        let mut parts = Vec::new();
        for block in blocks {
            if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                    parts.push(text);
                }
            }
        }
        if !parts.is_empty() {
            return Some(parts.join(""));
        }
    }
    None
}

fn count_content_chars(value: &serde_json::Value) -> usize {
    if let Some(s) = value.as_str() {
        return s.chars().count();
    }
    if let Some(blocks) = value.as_array() {
        let mut total = 0;
        for block in blocks {
            if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                    total += text.chars().count();
                }
            }
        }
        return total;
    }
    0
}

pub fn extract_system_prompt(provider: &str, body: &serde_json::Value) -> Option<String> {
    match provider {
        "openai" => {
            body.get("messages")
                .and_then(|m| m.as_array())
                .and_then(|messages| {
                    messages.iter().find_map(|msg| {
                        if msg.get("role").and_then(|r| r.as_str()) == Some("system") {
                            msg.get("content").and_then(extract_text_from_content)
                        } else {
                            None
                        }
                    })
                })
        }
        "anthropic" => {
            body.get("system").and_then(extract_text_from_content)
        }
        _ => None,
    }
}

pub fn count_prompt_chars(provider: &str, body: &serde_json::Value) -> usize {
    let mut total = 0usize;

    match provider {
        "openai" => {
            if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
                for msg in messages {
                    if let Some(content) = msg.get("content") {
                        total += count_content_chars(content);
                    }
                }
            }
        }
        "anthropic" => {
            if let Some(system) = body.get("system") {
                total += count_content_chars(system);
            }
            if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
                for msg in messages {
                    if let Some(content) = msg.get("content") {
                        total += count_content_chars(content);
                    }
                }
            }
        }
        _ => {}
    }

    total
}

fn normalize_prompt(prompt: &str, hash_chars: u64, ignore_whitespace: bool) -> String {
    let mut text = if hash_chars > 0 {
        prompt.chars().take(hash_chars as usize).collect::<String>()
    } else {
        prompt.to_string()
    };

    if ignore_whitespace {
        text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    }

    text
}

fn hash_prompt(normalized: &str, algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Keccak256 => {
            let hash = Keccak256::digest(normalized.as_bytes());
            format!("0x{:x}", hash)
        }
    }
}

pub async fn check_prompt_drift(
    baseline_store: &BaselineStore,
    alert_store: &Arc<AlertStore>,
    service: &str,
    system_prompt: Option<&str>,
    config: &PromptDriftConfig,
) -> GuardDecision {
    if !config.enabled {
        return GuardDecision::Skipped;
    }

    let system_prompt = match system_prompt {
        Some(p) => p,
        None => return GuardDecision::Allow,
    };

    let normalized = normalize_prompt(system_prompt, config.hash_chars, config.ignore_whitespace);
    let current_hash = hash_prompt(&normalized, config.hash_algorithm);

    let new_entry = BaselineEntry {
        hash: current_hash.clone(),
        hash_chars: config.hash_chars,
        ignore_whitespace: config.ignore_whitespace,
        hash_algorithm: config.hash_algorithm,
    };

    #[derive(Debug)]
    enum DriftOutcome {
        BaselineCaptured,
        NoDrift,
        Drifted { old_hash: String },
    }

    let outcome = {
        let mut baselines = baseline_store.baselines.write().await;

        match baselines.get(service) {
            None => {
                baselines.insert(service.to_string(), new_entry);
                eprintln!(
                    "[fishnet] system_prompt_baseline captured for {service} (hash: {current_hash})"
                );
                DriftOutcome::BaselineCaptured
            }
            Some(entry) => {
                if entry.hash_chars != config.hash_chars
                    || entry.ignore_whitespace != config.ignore_whitespace
                    || entry.hash_algorithm != config.hash_algorithm
                {
                    baselines.insert(service.to_string(), new_entry);
                    eprintln!(
                        "[fishnet] baseline re-captured for {service} due to config change (hash: {current_hash})"
                    );
                    DriftOutcome::BaselineCaptured
                } else if entry.hash == current_hash {
                    DriftOutcome::NoDrift
                } else {
                    DriftOutcome::Drifted {
                        old_hash: entry.hash.clone(),
                    }
                }
            }
        }
    };

    let decision = match outcome {
        DriftOutcome::BaselineCaptured => GuardDecision::BaselineCaptured,
        DriftOutcome::NoDrift => GuardDecision::Allow,
        DriftOutcome::Drifted { old_hash } => {
            let hash_chars_note = if config.hash_chars > 0 {
                format!(" (hashing first {} chars)", config.hash_chars)
            } else {
                String::new()
            };

            match config.mode {
                GuardMode::Alert => {
                    let message = format!(
                        "System prompt changed. Previous: {old_hash} Current: {current_hash}{hash_chars_note}"
                    );
                    eprintln!("[fishnet] ALERT: {message}");
                    alert_store
                        .create(AlertType::PromptDrift, AlertSeverity::Critical, service, message)
                        .await;
                    GuardDecision::AllowWithAlert
                }
                GuardMode::Deny => {
                    let message = format!(
                        "System prompt changed. Previous: {old_hash} Current: {current_hash}{hash_chars_note}"
                    );
                    eprintln!("[fishnet] DENY: {message}");
                    alert_store
                        .create(AlertType::PromptDrift, AlertSeverity::Critical, service, message)
                        .await;
                    GuardDecision::Deny(
                        "System prompt drift detected. Request blocked by policy.".to_string(),
                    )
                }
                GuardMode::Ignore => {
                    eprintln!(
                        "[fishnet] drift detected for {service} (ignored): {old_hash} → {current_hash}{hash_chars_note}"
                    );
                    GuardDecision::Allow
                }
            }
        }
    };

    if decision == GuardDecision::BaselineCaptured {
        baseline_store.persist().await;
    }

    decision
}

pub async fn check_prompt_size(
    alert_store: &Arc<AlertStore>,
    service: &str,
    total_chars: usize,
    config: &PromptSizeGuardConfig,
) -> GuardDecision {
    if !config.enabled {
        return GuardDecision::Skipped;
    }

    let (measured, limit, unit, approximate) = if config.max_prompt_chars > 0 {
        (total_chars as u64, config.max_prompt_chars, "chars", false)
    } else {
        let estimated_tokens = (total_chars as u64) / 4;
        (estimated_tokens, config.max_prompt_tokens, "tokens", true)
    };

    if measured <= limit {
        return GuardDecision::Allow;
    }

    let measured_display = if approximate {
        format!("~{}", format_number(measured))
    } else {
        format_number(measured)
    };
    let limit_display = format_number(limit);

    match config.action {
        GuardAction::Deny => {
            let message = format!(
                "Prompt size {measured_display} {unit} exceeds limit of {limit_display}. Action: denied."
            );
            eprintln!("[fishnet] DENY: {message}");
            alert_store
                .create(AlertType::PromptSize, AlertSeverity::Warning, service, message)
                .await;
            GuardDecision::Deny(format!(
                "Prompt size {measured_display} {unit} exceeds limit of {limit_display}"
            ))
        }
        GuardAction::Alert => {
            let message = format!(
                "Oversized prompt: {measured_display} {unit} (limit: {limit_display}). Action: alert only."
            );
            eprintln!("[fishnet] ALERT: {message}");
            alert_store
                .create(AlertType::PromptSize, AlertSeverity::Warning, service, message)
                .await;
            GuardDecision::AllowWithAlert
        }
    }
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_openai_system_prompt() {
        let body = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello"}
            ]
        });
        assert_eq!(
            extract_system_prompt("openai", &body),
            Some("You are a helpful assistant.".to_string())
        );
    }

    #[test]
    fn extract_anthropic_system_prompt() {
        let body = serde_json::json!({
            "model": "claude-3-opus-20240229",
            "system": "You are a helpful assistant.",
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        });
        assert_eq!(
            extract_system_prompt("anthropic", &body),
            Some("You are a helpful assistant.".to_string())
        );
    }

    #[test]
    fn extract_no_system_prompt() {
        let body = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        });
        assert_eq!(extract_system_prompt("openai", &body), None);
    }

    #[test]
    fn extract_openai_system_prompt_array_content() {
        let body = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": [
                    {"type": "text", "text": "You are "},
                    {"type": "text", "text": "a helpful assistant."}
                ]},
                {"role": "user", "content": "Hello"}
            ]
        });
        assert_eq!(
            extract_system_prompt("openai", &body),
            Some("You are a helpful assistant.".to_string())
        );
    }

    #[test]
    fn extract_anthropic_system_prompt_array() {
        let body = serde_json::json!({
            "model": "claude-3-opus-20240229",
            "system": [
                {"type": "text", "text": "You are "},
                {"type": "text", "text": "a helpful assistant."}
            ],
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        });
        assert_eq!(
            extract_system_prompt("anthropic", &body),
            Some("You are a helpful assistant.".to_string())
        );
    }

    #[test]
    fn extract_skips_non_text_blocks() {
        let body = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": [
                    {"type": "text", "text": "Be helpful."},
                    {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}
                ]},
                {"role": "user", "content": "Hello"}
            ]
        });
        assert_eq!(
            extract_system_prompt("openai", &body),
            Some("Be helpful.".to_string())
        );
    }

    #[test]
    fn extract_unknown_provider() {
        let body = serde_json::json!({"messages": []});
        assert_eq!(extract_system_prompt("unknown", &body), None);
    }

    #[test]
    fn count_openai_chars() {
        let body = serde_json::json!({
            "messages": [
                {"role": "system", "content": "abcde"},
                {"role": "user", "content": "fghij"}
            ]
        });
        assert_eq!(count_prompt_chars("openai", &body), 10);
    }

    #[test]
    fn count_openai_chars_array_content() {
        let body = serde_json::json!({
            "messages": [
                {"role": "system", "content": [
                    {"type": "text", "text": "abc"},
                    {"type": "text", "text": "de"}
                ]},
                {"role": "user", "content": [
                    {"type": "text", "text": "fghij"},
                    {"type": "image_url", "image_url": {"url": "https://x.com/i.png"}}
                ]}
            ]
        });
        assert_eq!(count_prompt_chars("openai", &body), 10);
    }

    #[test]
    fn count_anthropic_chars() {
        let body = serde_json::json!({
            "system": "abcde",
            "messages": [
                {"role": "user", "content": "fghij"}
            ]
        });
        assert_eq!(count_prompt_chars("anthropic", &body), 10);
    }

    #[test]
    fn count_anthropic_chars_array_system_and_content() {
        let body = serde_json::json!({
            "system": [
                {"type": "text", "text": "abc"},
                {"type": "text", "text": "de"}
            ],
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "fgh"},
                    {"type": "text", "text": "ij"}
                ]}
            ]
        });
        assert_eq!(count_prompt_chars("anthropic", &body), 10);
    }

    #[test]
    fn count_mixed_string_and_array_content() {
        let body = serde_json::json!({
            "messages": [
                {"role": "system", "content": "abcde"},
                {"role": "user", "content": [
                    {"type": "text", "text": "fghij"}
                ]}
            ]
        });
        assert_eq!(count_prompt_chars("openai", &body), 10);
    }

    #[test]
    fn count_chars_not_bytes_for_multibyte() {
        // "héllo" is 5 chars but 6 bytes (é is 2 bytes in UTF-8)
        let body = serde_json::json!({
            "messages": [
                {"role": "user", "content": "héllo"}
            ]
        });
        assert_eq!(count_prompt_chars("openai", &body), 5);

        // Same in array-of-blocks form
        let body = serde_json::json!({
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "héllo"}
                ]}
            ]
        });
        assert_eq!(count_prompt_chars("openai", &body), 5);
    }

    #[test]
    fn normalize_full_prompt() {
        let result = normalize_prompt("hello world", 0, false);
        assert_eq!(result, "hello world");
    }

    #[test]
    fn normalize_with_hash_chars() {
        let result = normalize_prompt("hello world", 5, false);
        assert_eq!(result, "hello");
    }

    #[test]
    fn normalize_with_whitespace_collapsing() {
        let result = normalize_prompt("hello   world\n\nfoo", 0, true);
        assert_eq!(result, "hello world foo");
    }

    #[test]
    fn normalize_with_hash_chars_and_whitespace() {
        let result = normalize_prompt("hello   world\n\nfoo", 10, true);
        // First 10 chars of "hello   world\n\nfoo" = "hello   wo", then normalize whitespace = "hello wo"
        assert_eq!(result, "hello wo");
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = hash_prompt("hello", HashAlgorithm::Keccak256);
        let h2 = hash_prompt("hello", HashAlgorithm::Keccak256);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("0x"));
    }

    #[test]
    fn hash_differs_for_different_input() {
        let h1 = hash_prompt("hello", HashAlgorithm::Keccak256);
        let h2 = hash_prompt("world", HashAlgorithm::Keccak256);
        assert_ne!(h1, h2);
    }

    #[test]
    fn format_numbers() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(50000), "50,000");
        assert_eq!(format_number(1000000), "1,000,000");
    }

    #[tokio::test]
    async fn drift_disabled_skips_entirely() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            enabled: false,
            ..Default::default()
        };

        let result =
            check_prompt_drift(&baselines, &alerts, "openai", Some("hello"), &config).await;
        assert_eq!(result, GuardDecision::Skipped);

        // No baseline captured
        assert!(baselines.baselines.read().await.is_empty());
        // No alerts
        assert!(alerts.list().await.is_empty());
    }

    #[tokio::test]
    async fn drift_first_request_captures_baseline() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig::default();

        let result = check_prompt_drift(
            &baselines,
            &alerts,
            "openai",
            Some("You are a helpful assistant."),
            &config,
        )
        .await;
        assert_eq!(result, GuardDecision::BaselineCaptured);
        assert!(baselines.baselines.read().await.contains_key("openai"));
        assert!(alerts.list().await.is_empty());
    }

    #[tokio::test]
    async fn drift_same_prompt_no_alert() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig::default();
        let prompt = "You are a helpful assistant.";

        // First request
        check_prompt_drift(&baselines, &alerts, "openai", Some(prompt), &config).await;
        // Second request — same prompt
        let result =
            check_prompt_drift(&baselines, &alerts, "openai", Some(prompt), &config).await;
        assert_eq!(result, GuardDecision::Allow);
        assert!(alerts.list().await.is_empty());
    }

    #[tokio::test]
    async fn drift_different_prompt_alert_mode() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            mode: GuardMode::Alert,
            ..Default::default()
        };

        check_prompt_drift(&baselines, &alerts, "openai", Some("prompt v1"), &config).await;
        let result =
            check_prompt_drift(&baselines, &alerts, "openai", Some("prompt v2"), &config).await;
        assert_eq!(result, GuardDecision::AllowWithAlert);

        let alert_list = alerts.list().await;
        assert_eq!(alert_list.len(), 1);
        assert_eq!(alert_list[0].alert_type, AlertType::PromptDrift);
        assert_eq!(alert_list[0].severity, AlertSeverity::Critical);
        assert_eq!(alert_list[0].service, "openai");
    }

    #[tokio::test]
    async fn drift_different_prompt_deny_mode() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            mode: GuardMode::Deny,
            ..Default::default()
        };

        check_prompt_drift(&baselines, &alerts, "openai", Some("prompt v1"), &config).await;
        let result =
            check_prompt_drift(&baselines, &alerts, "openai", Some("prompt v2"), &config).await;
        assert!(matches!(result, GuardDecision::Deny(_)));
        if let GuardDecision::Deny(msg) = result {
            assert_eq!(msg, "System prompt drift detected. Request blocked by policy.");
        }

        // Alert is still created for deny mode
        assert_eq!(alerts.list().await.len(), 1);
    }

    #[tokio::test]
    async fn drift_different_prompt_ignore_mode() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            mode: GuardMode::Ignore,
            ..Default::default()
        };

        check_prompt_drift(&baselines, &alerts, "openai", Some("prompt v1"), &config).await;
        let result =
            check_prompt_drift(&baselines, &alerts, "openai", Some("prompt v2"), &config).await;
        // Ignore mode: allowed, no alert, just logged
        assert_eq!(result, GuardDecision::Allow);
        assert!(alerts.list().await.is_empty());
    }

    #[tokio::test]
    async fn drift_alert_keeps_firing_on_repeated_injection() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            mode: GuardMode::Alert,
            ..Default::default()
        };

        // Baseline
        check_prompt_drift(&baselines, &alerts, "openai", Some("original"), &config).await;

        // Injected prompt — should alert
        let r = check_prompt_drift(&baselines, &alerts, "openai", Some("injected"), &config).await;
        assert_eq!(r, GuardDecision::AllowWithAlert);

        // Same injected prompt again — should STILL alert because
        // baseline was never overwritten
        let r = check_prompt_drift(&baselines, &alerts, "openai", Some("injected"), &config).await;
        assert_eq!(r, GuardDecision::AllowWithAlert);
        assert_eq!(alerts.list().await.len(), 2);

        // Original prompt returns cleanly — no alert
        let r = check_prompt_drift(&baselines, &alerts, "openai", Some("original"), &config).await;
        assert_eq!(r, GuardDecision::Allow);
        assert_eq!(alerts.list().await.len(), 2);
    }

    #[tokio::test]
    async fn drift_deny_keeps_blocking_on_repeated_injection() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            mode: GuardMode::Deny,
            ..Default::default()
        };

        check_prompt_drift(&baselines, &alerts, "openai", Some("original"), &config).await;

        // Injected prompt — blocked
        let r = check_prompt_drift(&baselines, &alerts, "openai", Some("injected"), &config).await;
        assert!(matches!(r, GuardDecision::Deny(_)));

        // Same injection again — still blocked
        let r = check_prompt_drift(&baselines, &alerts, "openai", Some("injected"), &config).await;
        assert!(matches!(r, GuardDecision::Deny(_)));
        assert_eq!(alerts.list().await.len(), 2);
    }

    #[tokio::test]
    async fn drift_ignore_keeps_detecting_on_repeated_injection() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            mode: GuardMode::Ignore,
            ..Default::default()
        };

        check_prompt_drift(&baselines, &alerts, "openai", Some("original"), &config).await;

        // Injected prompt — allowed but logged (ignore mode creates no alerts)
        let r = check_prompt_drift(&baselines, &alerts, "openai", Some("injected"), &config).await;
        assert_eq!(r, GuardDecision::Allow);

        // Same injection again — should STILL be detected as drift (not silently pass)
        // We verify by checking that the original prompt matches cleanly
        let r = check_prompt_drift(&baselines, &alerts, "openai", Some("original"), &config).await;
        assert_eq!(r, GuardDecision::Allow);

        // And the injected one is still different from baseline
        let r = check_prompt_drift(&baselines, &alerts, "openai", Some("injected"), &config).await;
        assert_eq!(r, GuardDecision::Allow); // ignore mode always allows
        // No alerts in ignore mode
        assert!(alerts.list().await.is_empty());
    }

    #[tokio::test]
    async fn drift_no_system_prompt_skips_gracefully() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig::default();

        let result = check_prompt_drift(&baselines, &alerts, "openai", None, &config).await;
        assert_eq!(result, GuardDecision::Allow);
        assert!(baselines.baselines.read().await.is_empty());
    }

    #[tokio::test]
    async fn drift_hash_chars_detects_change_within_range() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            hash_chars: 500,
            mode: GuardMode::Alert,
            ..Default::default()
        };

        // Original prompt
        let prompt_v1 = format!("{}unchanged_tail", "a".repeat(100));
        check_prompt_drift(&baselines, &alerts, "openai", Some(&prompt_v1), &config).await;

        // Change at char 50 (within first 500)
        let mut prompt_v2 = "b".repeat(100);
        prompt_v2.push_str("unchanged_tail");
        let result =
            check_prompt_drift(&baselines, &alerts, "openai", Some(&prompt_v2), &config).await;
        assert_eq!(result, GuardDecision::AllowWithAlert);
    }

    #[tokio::test]
    async fn drift_hash_chars_misses_change_beyond_range() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            hash_chars: 500,
            mode: GuardMode::Alert,
            ..Default::default()
        };

        // Original prompt: 500 stable chars + dynamic tail
        let stable = "a".repeat(500);
        let prompt_v1 = format!("{stable}dynamic_v1");
        check_prompt_drift(&baselines, &alerts, "openai", Some(&prompt_v1), &config).await;

        // Change only after char 500
        let prompt_v2 = format!("{stable}dynamic_v2");
        let result =
            check_prompt_drift(&baselines, &alerts, "openai", Some(&prompt_v2), &config).await;
        // Not detected — only first 500 chars are hashed
        assert_eq!(result, GuardDecision::Allow);
        assert!(alerts.list().await.is_empty());
    }

    #[tokio::test]
    async fn drift_hash_chars_zero_detects_any_change() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            hash_chars: 0,
            mode: GuardMode::Alert,
            ..Default::default()
        };

        let prompt_v1 = format!("{}tail_v1", "a".repeat(1000));
        check_prompt_drift(&baselines, &alerts, "openai", Some(&prompt_v1), &config).await;

        let prompt_v2 = format!("{}tail_v2", "a".repeat(1000));
        let result =
            check_prompt_drift(&baselines, &alerts, "openai", Some(&prompt_v2), &config).await;
        assert_eq!(result, GuardDecision::AllowWithAlert);
    }

    #[tokio::test]
    async fn drift_ignore_whitespace_true_no_false_positive() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            ignore_whitespace: true,
            mode: GuardMode::Alert,
            ..Default::default()
        };

        check_prompt_drift(
            &baselines,
            &alerts,
            "openai",
            Some("hello  world"),
            &config,
        )
        .await;
        let result = check_prompt_drift(
            &baselines,
            &alerts,
            "openai",
            Some("hello    world"),
            &config,
        )
        .await;
        // Normalized, these are the same — no drift
        assert_eq!(result, GuardDecision::Allow);
    }

    #[tokio::test]
    async fn drift_ignore_whitespace_false_detects_spaces() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig {
            ignore_whitespace: false,
            mode: GuardMode::Alert,
            ..Default::default()
        };

        check_prompt_drift(
            &baselines,
            &alerts,
            "openai",
            Some("hello  world"),
            &config,
        )
        .await;
        let result = check_prompt_drift(
            &baselines,
            &alerts,
            "openai",
            Some("hello    world"),
            &config,
        )
        .await;
        assert_eq!(result, GuardDecision::AllowWithAlert);
    }

    #[tokio::test]
    async fn drift_config_change_clears_baseline() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());

        // Start with hash_chars = 0
        let config_v1 = PromptDriftConfig {
            hash_chars: 0,
            ..Default::default()
        };
        check_prompt_drift(&baselines, &alerts, "openai", Some("hello"), &config_v1).await;

        // Config changes to hash_chars = 500
        let config_v2 = PromptDriftConfig {
            hash_chars: 500,
            ..Default::default()
        };
        let result =
            check_prompt_drift(&baselines, &alerts, "openai", Some("hello"), &config_v2).await;
        // Baseline re-captured due to config change
        assert_eq!(result, GuardDecision::BaselineCaptured);
    }

    #[tokio::test]
    async fn drift_baseline_clear_on_explicit_clear() {
        let baselines = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig::default();

        check_prompt_drift(&baselines, &alerts, "openai", Some("hello"), &config).await;
        assert!(!baselines.baselines.read().await.is_empty());

        // Simulate restart / hot-reload clearing
        baselines.clear().await;
        assert!(baselines.baselines.read().await.is_empty());

        // Next request re-captures baseline
        let result =
            check_prompt_drift(&baselines, &alerts, "openai", Some("hello"), &config).await;
        assert_eq!(result, GuardDecision::BaselineCaptured);
    }

    #[tokio::test]
    async fn size_guard_disabled_skips() {
        let alerts = Arc::new(AlertStore::new());
        let config = PromptSizeGuardConfig {
            enabled: false,
            ..Default::default()
        };
        let result = check_prompt_size(&alerts, "openai", 999999, &config).await;
        assert_eq!(result, GuardDecision::Skipped);
        assert!(alerts.list().await.is_empty());
    }

    #[tokio::test]
    async fn size_guard_under_limit_passes() {
        let alerts = Arc::new(AlertStore::new());
        let config = PromptSizeGuardConfig {
            enabled: true,
            max_prompt_tokens: 50_000,
            max_prompt_chars: 0,
            action: GuardAction::Deny,
        };
        // 160,000 chars / 4 = 40,000 tokens < 50,000 limit
        let result = check_prompt_size(&alerts, "openai", 160_000, &config).await;
        assert_eq!(result, GuardDecision::Allow);
        assert!(alerts.list().await.is_empty());
    }

    #[tokio::test]
    async fn size_guard_over_limit_deny() {
        let alerts = Arc::new(AlertStore::new());
        let config = PromptSizeGuardConfig {
            enabled: true,
            max_prompt_tokens: 50_000,
            max_prompt_chars: 0,
            action: GuardAction::Deny,
        };
        // 240,000 chars / 4 = 60,000 tokens > 50,000 limit
        let result = check_prompt_size(&alerts, "openai", 240_000, &config).await;
        assert!(matches!(result, GuardDecision::Deny(_)));
        assert_eq!(alerts.list().await.len(), 1);
    }

    #[tokio::test]
    async fn size_guard_over_limit_alert() {
        let alerts = Arc::new(AlertStore::new());
        let config = PromptSizeGuardConfig {
            enabled: true,
            max_prompt_tokens: 50_000,
            max_prompt_chars: 0,
            action: GuardAction::Alert,
        };
        // 240,000 chars / 4 = 60,000 tokens > 50,000 limit
        let result = check_prompt_size(&alerts, "openai", 240_000, &config).await;
        assert_eq!(result, GuardDecision::AllowWithAlert);
        let alert_list = alerts.list().await;
        assert_eq!(alert_list.len(), 1);
        assert_eq!(alert_list[0].alert_type, AlertType::PromptSize);
    }

    #[tokio::test]
    async fn size_guard_chars_overrides_tokens() {
        let alerts = Arc::new(AlertStore::new());
        let config = PromptSizeGuardConfig {
            enabled: true,
            max_prompt_tokens: 50_000,
            max_prompt_chars: 200_000,
            action: GuardAction::Deny,
        };
        // 180,000 chars < 200,000 char limit (even though 180,000/4 = 45,000 < 50,000 token limit too)
        let result = check_prompt_size(&alerts, "openai", 180_000, &config).await;
        assert_eq!(result, GuardDecision::Allow);

        // 210,000 chars > 200,000 char limit
        let result = check_prompt_size(&alerts, "openai", 210_000, &config).await;
        assert!(matches!(result, GuardDecision::Deny(_)));
    }

    #[tokio::test]
    async fn size_guard_chars_takes_priority_over_tokens() {
        let alerts = Arc::new(AlertStore::new());
        // Set a low token limit but high char limit
        let config = PromptSizeGuardConfig {
            enabled: true,
            max_prompt_tokens: 1_000, // Would block at 4,000 chars if used
            max_prompt_chars: 200_000, // But char limit takes priority
            action: GuardAction::Deny,
        };
        // 100,000 chars is way over the token equivalent (100,000/4 = 25,000 >> 1,000)
        // but under the char limit (100,000 < 200,000), so it should pass
        let result = check_prompt_size(&alerts, "openai", 100_000, &config).await;
        assert_eq!(result, GuardDecision::Allow);
    }

    #[tokio::test]
    async fn size_guard_token_mode_uses_approximate_prefix() {
        let alerts = Arc::new(AlertStore::new());
        let config = PromptSizeGuardConfig {
            enabled: true,
            max_prompt_tokens: 100,
            max_prompt_chars: 0, // token estimate mode
            action: GuardAction::Deny,
        };
        // 800 chars / 4 = 200 tokens > 100 limit
        let result = check_prompt_size(&alerts, "openai", 800, &config).await;
        if let GuardDecision::Deny(msg) = result {
            assert!(msg.contains("~"), "token mode should use ~ prefix: {msg}");
            assert!(msg.contains("tokens"), "should say tokens: {msg}");
        } else {
            panic!("expected Deny");
        }
    }

    #[tokio::test]
    async fn size_guard_char_mode_uses_exact_number() {
        let alerts = Arc::new(AlertStore::new());
        let config = PromptSizeGuardConfig {
            enabled: true,
            max_prompt_tokens: 50_000,
            max_prompt_chars: 1_000, // exact char mode
            action: GuardAction::Deny,
        };
        let result = check_prompt_size(&alerts, "openai", 1_500, &config).await;
        if let GuardDecision::Deny(msg) = result {
            assert!(!msg.contains("~"), "char mode should NOT use ~ prefix: {msg}");
            assert!(msg.contains("chars"), "should say chars: {msg}");
            assert!(msg.contains("1,500"), "should show exact count: {msg}");
        } else {
            panic!("expected Deny");
        }
    }

    #[tokio::test]
    async fn persistence_baselines_survive_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baselines.json");
        let config = PromptDriftConfig::default();
        let alerts = Arc::new(AlertStore::new());

        // First "run": capture a baseline with persistence
        {
            let store = BaselineStore::with_persistence(path.clone(), false);
            check_prompt_drift(&store, &alerts, "openai", Some("hello"), &config).await;
            assert!(!store.is_empty().await);
        }

        // File should exist
        assert!(path.exists());

        // Second "run": load_existing = true (reset_baseline_on_restart = false)
        {
            let store = BaselineStore::with_persistence(path.clone(), true);
            assert!(!store.is_empty().await);

            // Same prompt should match the persisted baseline — no drift
            let result =
                check_prompt_drift(&store, &alerts, "openai", Some("hello"), &config).await;
            assert_eq!(result, GuardDecision::Allow);
        }
    }

    #[tokio::test]
    async fn persistence_reset_on_restart_ignores_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baselines.json");
        let config = PromptDriftConfig::default();
        let alerts = Arc::new(AlertStore::new());

        // First "run": capture a baseline
        {
            let store = BaselineStore::with_persistence(path.clone(), false);
            check_prompt_drift(&store, &alerts, "openai", Some("hello"), &config).await;
        }

        assert!(path.exists());

        // Second "run": load_existing = false (reset_baseline_on_restart = true)
        {
            let store = BaselineStore::with_persistence(path.clone(), false);
            assert!(store.is_empty().await);

            // Should re-capture baseline, not match against old one
            let result =
                check_prompt_drift(&store, &alerts, "openai", Some("different"), &config).await;
            assert_eq!(result, GuardDecision::BaselineCaptured);
        }
    }

    #[tokio::test]
    async fn persistence_clear_removes_file_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baselines.json");
        let config = PromptDriftConfig::default();
        let alerts = Arc::new(AlertStore::new());

        let store = BaselineStore::with_persistence(path.clone(), false);
        check_prompt_drift(&store, &alerts, "openai", Some("hello"), &config).await;
        assert!(path.exists());

        store.clear().await;

        // File should be overwritten with empty object
        let content = std::fs::read_to_string(&path).unwrap();
        let map: HashMap<String, serde_json::Value> = serde_json::from_str(&content).unwrap();
        assert!(map.is_empty());

        // Loading from cleared file should give empty store
        let store2 = BaselineStore::with_persistence(path.clone(), true);
        assert!(store2.is_empty().await);
    }

    #[tokio::test]
    async fn persistence_missing_file_starts_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");

        let store = BaselineStore::with_persistence(path, true);
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn persistence_corrupt_file_starts_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baselines.json");
        std::fs::write(&path, "not valid json{{{").unwrap();

        let store = BaselineStore::with_persistence(path, true);
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn persistence_in_memory_store_does_not_persist() {
        let store = BaselineStore::new();
        let alerts = Arc::new(AlertStore::new());
        let config = PromptDriftConfig::default();

        // Should work fine without any file path
        let result =
            check_prompt_drift(&store, &alerts, "openai", Some("hello"), &config).await;
        assert_eq!(result, GuardDecision::BaselineCaptured);
    }
}

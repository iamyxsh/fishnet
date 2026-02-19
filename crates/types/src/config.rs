use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FishnetConfig {
    pub llm: LlmConfig,
    pub dashboard: DashboardConfig,
    pub alerts: AlertsConfig,
}

impl Default for FishnetConfig {
    fn default() -> Self {
        Self {
            llm: LlmConfig::default(),
            dashboard: DashboardConfig::default(),
            alerts: AlertsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    pub prompt_drift: PromptDriftConfig,
    pub prompt_size_guard: PromptSizeGuardConfig,
    pub track_spend: bool,
    pub daily_budget_usd: f64,
    pub budget_warning_pct: u8,
    pub rate_limit_per_minute: u32,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            prompt_drift: PromptDriftConfig::default(),
            prompt_size_guard: PromptSizeGuardConfig::default(),
            track_spend: true,
            daily_budget_usd: 20.0,
            budget_warning_pct: 80,
            rate_limit_per_minute: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PromptDriftConfig {
    pub enabled: bool,
    pub mode: GuardMode,
    pub hash_chars: u64,
    pub hash_algorithm: HashAlgorithm,
    pub ignore_whitespace: bool,
    pub reset_baseline_on_restart: bool,
}

impl Default for PromptDriftConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: GuardMode::Alert,
            hash_chars: 0,
            hash_algorithm: HashAlgorithm::Keccak256,
            ignore_whitespace: true,
            reset_baseline_on_restart: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PromptSizeGuardConfig {
    pub enabled: bool,
    pub max_prompt_tokens: u64,
    pub max_prompt_chars: u64,
    pub action: GuardAction,
}

impl Default for PromptSizeGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_prompt_tokens: 50_000,
            max_prompt_chars: 0,
            action: GuardAction::Deny,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DashboardConfig {
    pub spend_history_days: u32,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            spend_history_days: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertsConfig {
    pub prompt_drift: bool,
    pub prompt_size: bool,
    pub budget_warning: bool,
    pub budget_exceeded: bool,
    pub onchain_denied: bool,
    pub rate_limit_hit: bool,
    pub retention_days: u32,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            prompt_drift: true,
            prompt_size: true,
            budget_warning: true,
            budget_exceeded: true,
            onchain_denied: true,
            rate_limit_hit: true,
            retention_days: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardMode {
    Alert,
    Deny,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardAction {
    Deny,
    Alert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Keccak256,
}

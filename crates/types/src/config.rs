use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FishnetConfig {
    pub llm: LlmConfig,
}

impl Default for FishnetConfig {
    fn default() -> Self {
        Self {
            llm: LlmConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    pub prompt_drift: PromptDriftConfig,
    pub prompt_size_guard: PromptSizeGuardConfig,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            prompt_drift: PromptDriftConfig::default(),
            prompt_size_guard: PromptSizeGuardConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardMode {
    Alert,
    Deny,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardAction {
    Deny,
    Alert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Keccak256,
}

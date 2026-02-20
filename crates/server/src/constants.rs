pub const OPENAI_API_BASE: &str = "https://api.openai.com";
pub const ANTHROPIC_API_BASE: &str = "https://api.anthropic.com";

pub const FISHNET_DIR: &str = ".fishnet";
pub const AUTH_FILE: &str = "auth.json";
pub const SPEND_DB_FILE: &str = "fishnet.db";
pub const ALERTS_DB_FILE: &str = "alerts.db";
pub const BASELINES_FILE: &str = "baselines.json";
pub const CONFIG_FILE: &str = "fishnet.toml";
pub const CONFIG_TEMP_EXT: &str = "toml.tmp";

pub const SESSION_TTL_HOURS: i64 = 4;
pub const MAX_SESSIONS: usize = 5;
pub const SESSION_TOKEN_PREFIX: &str = "fn_sess_";
pub const SESSION_TOKEN_BYTES: usize = 32;

pub const RATE_LIMIT_WINDOW_SECS: i64 = 60;
pub const LOGIN_MAX_FAILURES: usize = 5;

pub const PROXY_PATH_PREFIX: &str = "/proxy/";
pub const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

pub const CHARS_PER_TOKEN: u64 = 4;

pub const AUTH_FILE_MODE: u32 = 0o600;

pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 8473;

pub const ENV_FISHNET_CONFIG: &str = "FISHNET_CONFIG";
pub const ENV_FISHNET_HOST: &str = "FISHNET_HOST";

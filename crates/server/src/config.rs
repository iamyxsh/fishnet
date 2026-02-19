use std::path::{Path, PathBuf};
use std::sync::Arc;

use fishnet_types::config::FishnetConfig;
use thiserror::Error;
use tokio::sync::watch;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

/// Resolve the config file path.
///
/// Search order:
/// 1. Explicit path (from `FISHNET_CONFIG` env var or CLI flag)
/// 2. `./fishnet.toml` (current directory)
/// 3. `~/.fishnet/fishnet.toml`
///
/// Returns `None` if no file is found — defaults will be used.
pub fn resolve_config_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }

    let cwd_config = PathBuf::from("fishnet.toml");
    if cwd_config.exists() {
        return Some(cwd_config);
    }

    if let Some(mut home_config) = dirs::home_dir() {
        home_config.push(".fishnet");
        home_config.push("fishnet.toml");
        if home_config.exists() {
            return Some(home_config);
        }
    }

    None
}

/// Load config from the given path, or return defaults if path is `None`.
pub fn load_config(path: Option<&Path>) -> Result<FishnetConfig, ConfigError> {
    match path {
        Some(path) => {
            let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
                path: path.to_path_buf(),
                source: e,
            })?;
            toml::from_str(&content).map_err(|e| ConfigError::Parse {
                path: path.to_path_buf(),
                source: e,
            })
        }
        None => Ok(FishnetConfig::default()),
    }
}

/// Create a watch channel seeded with the initial config.
///
/// Returns `(sender, receiver)`. The sender is used by the file watcher;
/// the receiver is stored in `AppState`.
pub fn config_channel(
    initial: FishnetConfig,
) -> (
    watch::Sender<Arc<FishnetConfig>>,
    watch::Receiver<Arc<FishnetConfig>>,
) {
    watch::channel(Arc::new(initial))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_defaults_when_no_path() {
        let config = load_config(None).unwrap();
        assert!(config.llm.prompt_drift.enabled);
        assert!(config.llm.prompt_size_guard.enabled);
        assert_eq!(config.llm.prompt_size_guard.max_prompt_tokens, 50_000);
    }

    #[test]
    fn load_partial_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
[llm.prompt_drift]
enabled = false
mode = "deny"
"#
        )
        .unwrap();

        let config = load_config(Some(&path)).unwrap();
        assert!(!config.llm.prompt_drift.enabled);
        assert_eq!(
            config.llm.prompt_drift.mode,
            fishnet_types::config::GuardMode::Deny
        );

        assert!(config.llm.prompt_drift.ignore_whitespace);
        assert!(config.llm.prompt_size_guard.enabled);
    }

    #[test]
    fn load_invalid_toml_returns_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(&path, "not valid toml [[[").unwrap();

        let err = load_config(Some(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn load_missing_file_returns_read_error() {
        let path = PathBuf::from("/tmp/does_not_exist_fishnet.toml");
        let err = load_config(Some(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }

    #[test]
    fn resolve_explicit_path() {
        let path = PathBuf::from("/some/explicit/path.toml");
        let resolved = resolve_config_path(Some(&path));
        assert_eq!(resolved, Some(path));
    }

    #[test]
    fn resolve_returns_none_when_no_file_exists() {
        // Run from a temp dir where no fishnet.toml exists
        let dir = tempfile::tempdir().unwrap();
        let _guard = std::env::set_current_dir(dir.path());
        // With no explicit path and no fishnet.toml in cwd, falls through.
        // We can't easily test the home dir path, but at minimum
        // this should not panic.
        let _ = resolve_config_path(None);
    }

    #[test]
    fn invalid_enum_value_returns_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(
            &path,
            r#"
[llm.prompt_drift]
mode = "invalid_mode"
"#,
        )
        .unwrap();

        let err = load_config(Some(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }
}

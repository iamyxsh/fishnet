use std::sync::Arc;

use fishnet_server::{
    alert::AlertStore,
    audit::AuditStore,
    config::{config_channel, resolve_config_path},
    create_router,
    llm_guard::BaselineStore,
    onchain::OnchainStore,
    password::FilePasswordStore,
    rate_limit::{LoginRateLimiter, ProxyRateLimiter},
    session::SessionStore,
    signer::SignerTrait,
    spend::SpendStore,
    state::AppState,
    vault::CredentialStore,
    watch::spawn_config_watcher,
};
#[cfg(not(feature = "dev-seed"))]
use fishnet_server::{config::load_config, signer::StubSigner};
#[cfg(target_os = "macos")]
use security_framework::passwords::{get_generic_password, set_generic_password};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() {
    let explicit_config = std::env::var(fishnet_server::constants::ENV_FISHNET_CONFIG)
        .ok()
        .map(std::path::PathBuf::from);
    let config_path = resolve_config_path(explicit_config.as_deref());

    #[cfg(not(feature = "dev-seed"))]
    let config = match load_config(config_path.as_deref()) {
        Ok(c) => {
            match &config_path {
                Some(p) => eprintln!("[fishnet] config loaded from {}", p.display()),
                None => eprintln!("[fishnet] no config file found, using defaults"),
            }
            c
        }
        Err(e) => {
            eprintln!("[fishnet] fatal: {e}");
            std::process::exit(1);
        }
    };

    #[cfg(feature = "dev-seed")]
    let config = {
        eprintln!("[fishnet] dev-seed: overriding config with dev defaults (anvil chain 31337)");
        fishnet_server::seed::dev_config()
    };

    let load_baselines = !config.llm.prompt_drift.reset_baseline_on_restart;

    let (config_tx, config_rx) = config_channel(config);

    let config_path_for_state = config_path
        .clone()
        .or_else(fishnet_server::config::default_config_path)
        .unwrap_or_else(|| std::path::PathBuf::from(fishnet_server::constants::CONFIG_FILE));
    let _watcher_guard = config_path
        .clone()
        .map(|path| spawn_config_watcher(path, config_tx.clone()));

    let baseline_store = Arc::new(match BaselineStore::default_path() {
        Some(path) => BaselineStore::with_persistence(path, load_baselines),
        None => {
            eprintln!(
                "[fishnet] could not determine home directory, baselines will not be persisted"
            );
            BaselineStore::new()
        }
    });

    let spend_store = Arc::new(match SpendStore::default_path() {
        Some(path) => match SpendStore::open(path.clone()) {
            Ok(store) => {
                eprintln!("[fishnet] spend database opened at {}", path.display());
                store
            }
            Err(e) => {
                eprintln!("[fishnet] fatal: failed to open spend database: {e}");
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("[fishnet] fatal: could not determine home directory for spend database");
            std::process::exit(1);
        }
    });

    let alert_store = Arc::new(match AlertStore::default_path() {
        Some(path) => match AlertStore::open(path.clone()) {
            Ok(store) => {
                eprintln!("[fishnet] alerts database opened at {}", path.display());
                store
            }
            Err(e) => {
                eprintln!("[fishnet] fatal: failed to open alerts database: {e}");
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("[fishnet] fatal: could not determine home directory for alerts database");
            std::process::exit(1);
        }
    });

    let audit_store = Arc::new(match AuditStore::default_path() {
        Some(path) => match AuditStore::open(path.clone()) {
            Ok(store) => {
                eprintln!("[fishnet] audit database opened at {}", path.display());
                store
            }
            Err(e) => {
                eprintln!("[fishnet] fatal: failed to open audit database: {e}");
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("[fishnet] fatal: could not determine home directory for audit database");
            std::process::exit(1);
        }
    });

    let credential_store = Arc::new(match CredentialStore::default_path() {
        Some(path) => match open_credential_store(path.clone()) {
            Ok(store) => {
                eprintln!("[fishnet] vault database opened at {}", path.display());
                store
            }
            Err(e) => {
                eprintln!("[fishnet] fatal: failed to open vault database: {e}");
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("[fishnet] fatal: could not determine home directory for vault database");
            std::process::exit(1);
        }
    });

    #[cfg(feature = "dev-seed")]
    let signer: Arc<dyn SignerTrait> = {
        let s = fishnet_server::seed::dev_signer();
        eprintln!(
            "[fishnet] dev-seed: signer initialized with anvil account #0 (address: {})",
            s.status().address
        );
        Arc::new(s)
    };
    #[cfg(not(feature = "dev-seed"))]
    let signer: Arc<dyn SignerTrait> = {
        let s = StubSigner::new();
        eprintln!(
            "[fishnet] signer initialized (mode: stub-secp256k1, address: {})",
            s.status().address
        );
        Arc::new(s)
    };

    let state = AppState::new(
        Arc::new(FilePasswordStore::new(FilePasswordStore::default_path())),
        Arc::new(SessionStore::new()),
        Arc::new(LoginRateLimiter::new()),
        Arc::new(ProxyRateLimiter::new()),
        config_tx,
        config_rx,
        config_path_for_state,
        alert_store,
        audit_store,
        baseline_store.clone(),
        spend_store,
        credential_store,
        Arc::new(tokio::sync::Mutex::new(())),
        reqwest::Client::new(),
        Arc::new(OnchainStore::new()),
        signer,
        std::time::Instant::now(),
    );

    spawn_baseline_config_watcher(state.config_rx.clone(), baseline_store);

    {
        let retention_days = state.config().alerts.retention_days;
        if let Err(e) = state.alert_store.cleanup(retention_days).await {
            eprintln!("[fishnet] startup alert cleanup failed: {e}");
        }
    }

    #[cfg(feature = "dev-seed")]
    fishnet_server::seed::run(&state).await;

    let app = create_router(state);

    let host = std::env::var(fishnet_server::constants::ENV_FISHNET_HOST)
        .unwrap_or_else(|_| fishnet_server::constants::DEFAULT_HOST.into());
    let port = match std::env::var(fishnet_server::constants::ENV_FISHNET_PORT) {
        Ok(raw) => match raw.parse::<u16>() {
            Ok(port) => port,
            Err(e) => {
                eprintln!(
                    "[fishnet] fatal: invalid {}='{}': {e}",
                    fishnet_server::constants::ENV_FISHNET_PORT,
                    raw
                );
                std::process::exit(1);
            }
        },
        Err(_) => fishnet_server::constants::DEFAULT_PORT,
    };
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    eprintln!("[fishnet] listening on http://{addr}");
    axum::serve(listener, app).await.unwrap();
}

fn spawn_baseline_config_watcher(
    mut config_rx: tokio::sync::watch::Receiver<Arc<fishnet_types::config::FishnetConfig>>,
    baseline_store: Arc<BaselineStore>,
) {
    let initial = config_rx.borrow().clone();
    let mut prev_hash_chars = initial.llm.prompt_drift.hash_chars;
    let mut prev_ignore_ws = initial.llm.prompt_drift.ignore_whitespace;
    let mut prev_hash_algo = initial.llm.prompt_drift.hash_algorithm;

    tokio::spawn(async move {
        while config_rx.changed().await.is_ok() {
            let config: Arc<fishnet_types::config::FishnetConfig> = config_rx.borrow().clone();
            let new_hash_chars = config.llm.prompt_drift.hash_chars;
            let new_ignore_ws = config.llm.prompt_drift.ignore_whitespace;
            let new_hash_algo = config.llm.prompt_drift.hash_algorithm;

            if new_hash_chars != prev_hash_chars
                || new_ignore_ws != prev_ignore_ws
                || new_hash_algo != prev_hash_algo
            {
                eprintln!(
                    "[fishnet] drift config changed (hash_chars: {prev_hash_chars} → {new_hash_chars}, \
                     ignore_whitespace: {prev_ignore_ws} → {new_ignore_ws}, \
                     hash_algorithm: {prev_hash_algo:?} → {new_hash_algo:?}), clearing baselines"
                );
                baseline_store.clear().await;
                prev_hash_chars = new_hash_chars;
                prev_ignore_ws = new_ignore_ws;
                prev_hash_algo = new_hash_algo;
            }
        }
    });
}

fn open_credential_store(path: std::path::PathBuf) -> Result<CredentialStore, String> {
    if let Ok(master_password) =
        std::env::var(fishnet_server::constants::ENV_FISHNET_MASTER_PASSWORD)
    {
        unsafe {
            std::env::remove_var(fishnet_server::constants::ENV_FISHNET_MASTER_PASSWORD);
        }
        let master_password = Zeroizing::new(master_password);
        let store = CredentialStore::open(path, master_password.as_str())
            .map_err(|e| format!("failed to unlock vault with master password: {e}"))?;
        maybe_store_derived_key_in_keychain(&store);
        return Ok(store);
    }

    #[cfg(target_os = "macos")]
    {
        match read_vault_material_from_keychain() {
            Ok(Some(KeychainVaultMaterial::DerivedKey(derived_key))) => {
                match CredentialStore::open_with_derived_key(path.clone(), derived_key.as_slice()) {
                    Ok(store) => {
                        eprintln!("[fishnet] loaded vault derived key from macOS Keychain");
                        return Ok(store);
                    }
                    Err(e) => {
                        eprintln!(
                            "[fishnet] warning: keychain derived key did not unlock vault: {e}"
                        );
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!(
                    "[fishnet] warning: could not load vault key material from keychain: {e}"
                );
            }
        }
    }

    Err(format!(
        "{} is not set and no usable keychain vault key was found",
        fishnet_server::constants::ENV_FISHNET_MASTER_PASSWORD
    ))
}

#[cfg(target_os = "macos")]
const KEYCHAIN_DERIVED_KEY_PREFIX: &str = "derived_hex:v1:";

#[cfg(target_os = "macos")]
enum KeychainVaultMaterial {
    DerivedKey(Zeroizing<Vec<u8>>),
}

#[cfg(target_os = "macos")]
fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

#[cfg(target_os = "macos")]
fn keychain_service_account() -> (String, String) {
    let service = std::env::var(fishnet_server::constants::ENV_FISHNET_KEYCHAIN_SERVICE)
        .unwrap_or_else(|_| "fishnet".to_string());
    let account = std::env::var(fishnet_server::constants::ENV_FISHNET_KEYCHAIN_ACCOUNT)
        .unwrap_or_else(|_| "vault_derived_key".to_string());
    (service, account)
}

#[cfg(target_os = "macos")]
fn maybe_store_derived_key_in_keychain(store: &CredentialStore) {
    let allow_store =
        env_flag_enabled(fishnet_server::constants::ENV_FISHNET_STORE_DERIVED_KEY_IN_KEYCHAIN);
    if !allow_store {
        return;
    }

    let wrapped = format!("{KEYCHAIN_DERIVED_KEY_PREFIX}{}", store.derived_key_hex());
    match store_keychain_value(&wrapped) {
        Ok(()) => {
            eprintln!("[fishnet] vault derived key stored in macOS Keychain");
        }
        Err(e) => {
            eprintln!("[fishnet] warning: failed to store vault derived key in keychain: {e}");
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn maybe_store_derived_key_in_keychain(_store: &CredentialStore) {}

#[cfg(target_os = "macos")]
fn read_vault_material_from_keychain() -> Result<Option<KeychainVaultMaterial>, String> {
    let Some(value) = read_keychain_value()? else {
        return Ok(None);
    };
    parse_keychain_material(value).map(Some)
}

#[cfg(target_os = "macos")]
fn parse_keychain_material(value: String) -> Result<KeychainVaultMaterial, String> {
    if let Some(hex_key) = value.strip_prefix(KEYCHAIN_DERIVED_KEY_PREFIX) {
        let decoded = hex::decode(hex_key)
            .map_err(|e| format!("invalid derived key encoding in keychain: {e}"))?;
        return Ok(KeychainVaultMaterial::DerivedKey(Zeroizing::new(decoded)));
    }
    Err("unsupported keychain value format; expected derived_hex:v1:<hex>".to_string())
}

#[cfg(target_os = "macos")]
fn read_keychain_value() -> Result<Option<String>, String> {
    let (service, account) = keychain_service_account();
    match get_generic_password(&service, &account) {
        Ok(bytes) => {
            let value = String::from_utf8(bytes)
                .map_err(|e| format!("invalid UTF-8 from keychain: {e}"))?;
            if value.is_empty() {
                return Ok(None);
            }
            Ok(Some(value))
        }
        Err(e) => {
            // errSecItemNotFound
            if e.code() == -25300 {
                return Ok(None);
            }
            Err(format!("failed to read macOS keychain item: {e}"))
        }
    }
}

#[cfg(target_os = "macos")]
fn store_keychain_value(value: &str) -> Result<(), String> {
    let (service, account) = keychain_service_account();
    set_generic_password(&service, &account, value.as_bytes())
        .map_err(|e| format!("failed to write macOS keychain item: {e}"))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn parse_keychain_material_derived_key_roundtrip() {
        let raw = vec![0xAB, 0xCD, 0xEF, 0x01];
        let wrapped = format!("{KEYCHAIN_DERIVED_KEY_PREFIX}{}", hex::encode(&raw));
        let parsed = parse_keychain_material(wrapped).unwrap();
        match parsed {
            KeychainVaultMaterial::DerivedKey(bytes) => {
                assert_eq!(bytes.as_slice(), raw.as_slice())
            }
        }
    }

    #[test]
    fn parse_keychain_material_invalid_hex_rejected() {
        let wrapped = format!("{KEYCHAIN_DERIVED_KEY_PREFIX}not-hex-data");
        let err = match parse_keychain_material(wrapped) {
            Ok(_) => panic!("expected invalid derived key encoding error"),
            Err(e) => e,
        };
        assert!(err.contains("invalid derived key encoding"));
    }

    #[test]
    fn parse_keychain_material_legacy_value_rejected() {
        let legacy = "legacy-master-password".to_string();
        let err = match parse_keychain_material(legacy) {
            Ok(_) => panic!("expected unsupported keychain value format error"),
            Err(e) => e,
        };
        assert!(err.contains("unsupported keychain value format"));
    }
}

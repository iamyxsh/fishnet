use std::sync::Arc;

use fishnet_server::{
    alert::AlertStore,
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
    watch::spawn_config_watcher,
};
#[cfg(not(feature = "dev-seed"))]
use fishnet_server::{config::load_config, signer::StubSigner};

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
    let _watcher_guard = config_path.map(|path| spawn_config_watcher(path, config_tx));

    let baseline_store = Arc::new(match BaselineStore::default_path() {
        Some(path) => BaselineStore::with_persistence(path, load_baselines),
        None => {
            eprintln!("[fishnet] could not determine home directory, baselines will not be persisted");
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

    let state = AppState {
        password_store: Arc::new(FilePasswordStore::new(FilePasswordStore::default_path())),
        session_store: Arc::new(SessionStore::new()),
        rate_limiter: Arc::new(LoginRateLimiter::new()),
        proxy_rate_limiter: Arc::new(ProxyRateLimiter::new()),
        config_rx,
        config_path: config_path_for_state,
        alert_store,
        baseline_store: baseline_store.clone(),
        spend_store,
        http_client: reqwest::Client::new(),
        onchain_store: Arc::new(OnchainStore::new()),
        signer,
    };

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
    let addr = format!("{host}:{}", fishnet_server::constants::DEFAULT_PORT);
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

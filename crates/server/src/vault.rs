use std::path::{Path as StdPath, PathBuf};
use std::sync::{Arc, Mutex};

use argon2::{Algorithm, Argon2, Params, Version};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox;
use zeroize::{Zeroize, Zeroizing};

use crate::constants;
use crate::state::AppState;

const ARGON2_MEMORY_COST_KIB: u32 = 262_144;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const DERIVED_KEY_LEN: usize = secretbox::KEYBYTES;
const SALT_LEN: usize = 16;
const META_SALT_KEY: &str = "salt";
const META_CANARY_KEY: &str = "canary";
const CANARY_PLAINTEXT: &[u8] = b"fishnet-vault-canary-v1";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("{0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("argon2 parameters are invalid: {0}")]
    Argon2Params(String),
    #[error("argon2 derivation failed: {0}")]
    Argon2Derive(String),
    #[error("sodium initialization failed")]
    SodiumInit,
    #[error("invalid master password")]
    InvalidMasterPassword,
    #[error("vault metadata salt has invalid length: expected {expected}, found {found}")]
    InvalidSaltLength { expected: usize, found: usize },
    #[error("invalid nonce length")]
    InvalidNonce,
    #[error("invalid derived key length")]
    InvalidDerivedKey,
    #[error("credential key is not valid UTF-8")]
    InvalidUtf8,
    #[error("credential not found")]
    NotFound,
    #[error("failed to lock sensitive memory with mlock: {0}")]
    MlockFailed(String),
}

struct LockedSecretboxKey {
    key: secretbox::Key,
    locked: bool,
}

impl LockedSecretboxKey {
    fn from_bytes(derived_key: &[u8], require_mlock: bool) -> Result<Self, VaultError> {
        let Some(key) = secretbox::Key::from_slice(derived_key) else {
            return Err(VaultError::InvalidDerivedKey);
        };
        Self::new(key, require_mlock)
    }

    fn new(mut key: secretbox::Key, require_mlock: bool) -> Result<Self, VaultError> {
        let rc = unsafe { libc::mlock(key.0.as_ptr().cast(), key.0.len()) };
        if rc != 0 {
            let err = std::io::Error::last_os_error().to_string();
            if require_mlock {
                key.0.zeroize();
                return Err(VaultError::MlockFailed(err));
            }
            eprintln!(
                "[fishnet] warning: mlock failed for vault key material; continuing without memory lock: {err}"
            );
            return Ok(Self { key, locked: false });
        }

        Ok(Self { key, locked: true })
    }

    fn as_secretbox_key(&self) -> &secretbox::Key {
        &self.key
    }

    fn as_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }
}

impl Drop for LockedSecretboxKey {
    fn drop(&mut self) {
        if self.locked {
            unsafe {
                libc::munlock(self.key.0.as_ptr().cast(), self.key.0.len());
            }
        }
        self.key.0.zeroize();
    }
}

struct MasterKey {
    locked_key: LockedSecretboxKey,
}

impl MasterKey {
    fn from_derived_bytes(derived_key: &[u8]) -> Result<Self, VaultError> {
        Ok(Self {
            locked_key: LockedSecretboxKey::from_bytes(derived_key, require_mlock())?,
        })
    }

    fn secretbox_key(&self) -> &secretbox::Key {
        self.locked_key.as_secretbox_key()
    }

    fn derived_key_hex(&self) -> String {
        hex::encode(self.locked_key.as_bytes())
    }
}

#[derive(Clone)]
pub struct CredentialStore {
    conn: Arc<Mutex<Connection>>,
    key: Arc<MasterKey>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialMetadata {
    pub id: String,
    pub service: String,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

pub struct DecryptedCredential {
    pub id: String,
    pub key: Zeroizing<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCredentialRequest {
    pub service: String,
    pub name: String,
    pub key: String,
}

impl CredentialStore {
    pub fn open(path: PathBuf, master_password: &str) -> Result<Self, VaultError> {
        let conn = Self::open_sqlite(&path)?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            key: Arc::new(Self::load_master_key(master_password, &path)?),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_with_derived_key(path: PathBuf, derived_key: &[u8]) -> Result<Self, VaultError> {
        let conn = Self::open_sqlite(&path)?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            key: Arc::new(Self::load_master_key_from_derived(&path, derived_key)?),
        };
        store.migrate()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn open_in_memory(master_password: &str) -> Result<Self, VaultError> {
        if sodiumoxide::init().is_err() {
            return Err(VaultError::SodiumInit);
        }
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            key: Arc::new(Self::load_master_key_in_memory(master_password)?),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn default_path() -> Option<PathBuf> {
        let mut path = dirs::home_dir()?;
        path.push(constants::FISHNET_DIR);
        path.push(constants::VAULT_DB_FILE);
        Some(path)
    }

    pub fn derived_key_hex(&self) -> String {
        self.key.derived_key_hex()
    }

    fn migrate(&self) -> Result<(), VaultError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                service TEXT NOT NULL,
                name TEXT NOT NULL,
                encrypted_key BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_used_at INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service);
            CREATE INDEX IF NOT EXISTS idx_credentials_created_at ON credentials(created_at);

            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
        )?;
        Ok(())
    }

    fn load_master_key(master_password: &str, path: &StdPath) -> Result<MasterKey, VaultError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
        )?;

        let salt = Self::load_or_create_salt(&conn)?;
        let key = Self::derive_secretbox_key(master_password, &salt)?;
        Self::validate_or_create_canary(&conn, key.secretbox_key())?;
        Ok(key)
    }

    fn load_master_key_from_derived(
        path: &StdPath,
        derived_key: &[u8],
    ) -> Result<MasterKey, VaultError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
        )?;
        let key = Self::master_key_from_derived(derived_key)?;
        Self::validate_or_create_canary(&conn, key.secretbox_key())?;
        Ok(key)
    }

    #[cfg(test)]
    fn load_master_key_in_memory(master_password: &str) -> Result<MasterKey, VaultError> {
        let salt = rand::random::<[u8; SALT_LEN]>();
        Self::derive_secretbox_key(master_password, &salt)
    }

    fn master_key_from_derived(derived_key: &[u8]) -> Result<MasterKey, VaultError> {
        if derived_key.len() != DERIVED_KEY_LEN {
            return Err(VaultError::InvalidDerivedKey);
        }
        MasterKey::from_derived_bytes(derived_key)
    }

    fn open_sqlite(path: &StdPath) -> Result<Connection, VaultError> {
        if sodiumoxide::init().is_err() {
            return Err(VaultError::SodiumInit);
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    parent,
                    std::fs::Permissions::from_mode(constants::DATA_DIR_MODE),
                )?;
            }
        }

        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(constants::AUTH_FILE_MODE),
            )?;
        }

        Ok(conn)
    }

    fn load_or_create_salt(conn: &Connection) -> Result<[u8; SALT_LEN], VaultError> {
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = ?1",
                params![META_SALT_KEY],
                |row| row.get(0),
            )
            .optional()?;

        match existing {
            Some(bytes) if bytes.len() == SALT_LEN => {
                let mut out = [0u8; SALT_LEN];
                out.copy_from_slice(&bytes);
                Ok(out)
            }
            Some(bytes) => Err(VaultError::InvalidSaltLength {
                expected: SALT_LEN,
                found: bytes.len(),
            }),
            None => {
                let salt = rand::random::<[u8; SALT_LEN]>();
                conn.execute(
                    "INSERT INTO vault_meta(key, value) VALUES(?1, ?2)",
                    params![META_SALT_KEY, salt.to_vec()],
                )?;
                Ok(salt)
            }
        }
    }

    fn derive_secretbox_key(
        master_password: &str,
        salt: &[u8; SALT_LEN],
    ) -> Result<MasterKey, VaultError> {
        let params = Params::new(
            ARGON2_MEMORY_COST_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(DERIVED_KEY_LEN),
        )
        .map_err(|e| VaultError::Argon2Params(e.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut derived = Zeroizing::new(vec![0u8; DERIVED_KEY_LEN]);
        argon2
            .hash_password_into(master_password.as_bytes(), salt, &mut derived)
            .map_err(|e| VaultError::Argon2Derive(e.to_string()))?;
        MasterKey::from_derived_bytes(&derived)
    }

    fn validate_or_create_canary(
        conn: &Connection,
        key: &secretbox::Key,
    ) -> Result<(), VaultError> {
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = ?1",
                params![META_CANARY_KEY],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(blob) = existing {
            if blob.len() < secretbox::NONCEBYTES {
                return Err(VaultError::InvalidMasterPassword);
            }
            let nonce = secretbox::Nonce::from_slice(&blob[..secretbox::NONCEBYTES])
                .ok_or(VaultError::InvalidMasterPassword)?;
            let cipher = &blob[secretbox::NONCEBYTES..];
            let plaintext = secretbox::open(cipher, &nonce, key)
                .map_err(|_| VaultError::InvalidMasterPassword)?;
            if plaintext != CANARY_PLAINTEXT {
                return Err(VaultError::InvalidMasterPassword);
            }
            return Ok(());
        }

        let nonce = secretbox::gen_nonce();
        let cipher = secretbox::seal(CANARY_PLAINTEXT, &nonce, key);
        let mut blob = nonce.0.to_vec();
        blob.extend_from_slice(&cipher);
        conn.execute(
            "INSERT INTO vault_meta(key, value) VALUES(?1, ?2)",
            params![META_CANARY_KEY, blob],
        )?;
        Ok(())
    }

    pub async fn list_credentials(&self) -> Result<Vec<CredentialMetadata>, VaultError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<CredentialMetadata>, VaultError> {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, service, name, created_at, last_used_at
                 FROM credentials
                 ORDER BY created_at DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(CredentialMetadata {
                    id: row.get(0)?,
                    service: row.get(1)?,
                    name: row.get(2)?,
                    created_at: row.get(3)?,
                    last_used_at: row.get(4)?,
                })
            })?;

            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
        .await?
    }

    pub async fn add_credential(
        &self,
        service: &str,
        name: &str,
        raw_key: &str,
    ) -> Result<CredentialMetadata, VaultError> {
        let conn = self.conn.clone();
        let key = self.key.clone();
        let service = service.trim().to_string();
        let name = name.trim().to_string();
        let mut key_value = Zeroizing::new(raw_key.to_string());

        tokio::task::spawn_blocking(move || -> Result<CredentialMetadata, VaultError> {
            let conn = conn.lock().unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let now = chrono::Utc::now().timestamp();
            let nonce = secretbox::gen_nonce();
            let encrypted = secretbox::seal(key_value.as_bytes(), &nonce, key.secretbox_key());

            conn.execute(
                "INSERT INTO credentials(id, service, name, encrypted_key, nonce, created_at, last_used_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    id,
                    service,
                    name,
                    encrypted,
                    nonce.0.to_vec(),
                    now
                ],
            )?;

            key_value.zeroize();

            Ok(CredentialMetadata {
                id,
                service,
                name,
                created_at: now,
                last_used_at: None,
            })
        })
        .await?
    }

    pub async fn delete_credential(&self, id: &str) -> Result<bool, VaultError> {
        let conn = self.conn.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || -> Result<bool, VaultError> {
            let conn = conn.lock().unwrap();
            let deleted = conn.execute("DELETE FROM credentials WHERE id = ?1", params![id])?;
            Ok(deleted > 0)
        })
        .await?
    }

    pub async fn decrypt_for_service(
        &self,
        service: &str,
    ) -> Result<Option<DecryptedCredential>, VaultError> {
        let conn = self.conn.clone();
        let key = self.key.clone();
        let service = service.to_string();
        tokio::task::spawn_blocking(move || -> Result<Option<DecryptedCredential>, VaultError> {
            let conn = conn.lock().unwrap();
            let row: Option<(String, Vec<u8>, Vec<u8>)> = conn
                .query_row(
                    "SELECT id, encrypted_key, nonce
                     FROM credentials
                     WHERE service = ?1
                     ORDER BY created_at DESC
                     LIMIT 1",
                    params![service],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;

            let Some((id, encrypted_key, nonce_bytes)) = row else {
                return Ok(None);
            };
            let nonce =
                secretbox::Nonce::from_slice(&nonce_bytes).ok_or(VaultError::InvalidNonce)?;
            let plaintext = secretbox::open(&encrypted_key, &nonce, key.secretbox_key())
                .map_err(|_| VaultError::InvalidMasterPassword)?;
            let key_str = String::from_utf8(plaintext).map_err(|_| VaultError::InvalidUtf8)?;

            Ok(Some(DecryptedCredential {
                id,
                key: Zeroizing::new(key_str),
            }))
        })
        .await?
    }

    pub async fn decrypt_for_service_and_name(
        &self,
        service: &str,
        name: &str,
    ) -> Result<Option<DecryptedCredential>, VaultError> {
        let conn = self.conn.clone();
        let key = self.key.clone();
        let service = service.to_string();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || -> Result<Option<DecryptedCredential>, VaultError> {
            let conn = conn.lock().unwrap();
            let row: Option<(String, Vec<u8>, Vec<u8>)> = conn
                .query_row(
                    "SELECT id, encrypted_key, nonce
                     FROM credentials
                     WHERE service = ?1 AND name = ?2
                     ORDER BY created_at DESC
                     LIMIT 1",
                    params![service, name],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;

            let Some((id, encrypted_key, nonce_bytes)) = row else {
                return Ok(None);
            };
            let nonce =
                secretbox::Nonce::from_slice(&nonce_bytes).ok_or(VaultError::InvalidNonce)?;
            let plaintext = secretbox::open(&encrypted_key, &nonce, key.secretbox_key())
                .map_err(|_| VaultError::InvalidMasterPassword)?;
            let key_str = String::from_utf8(plaintext).map_err(|_| VaultError::InvalidUtf8)?;

            Ok(Some(DecryptedCredential {
                id,
                key: Zeroizing::new(key_str),
            }))
        })
        .await?
    }

    pub async fn touch_last_used(&self, id: &str) -> Result<(), VaultError> {
        let conn = self.conn.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || -> Result<(), VaultError> {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE credentials SET last_used_at = ?1 WHERE id = ?2",
                params![chrono::Utc::now().timestamp(), id],
            )?;
            Ok(())
        })
        .await?
    }

    #[cfg(test)]
    pub fn insert_plaintext_for_test(
        &self,
        service: &str,
        name: &str,
        raw_key: &str,
    ) -> Result<String, VaultError> {
        let conn = self.conn.lock().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        let nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(raw_key.as_bytes(), &nonce, self.key.secretbox_key());
        conn.execute(
            "INSERT INTO credentials(id, service, name, encrypted_key, nonce, created_at, last_used_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![id, service, name, encrypted, nonce.0.to_vec(), now],
        )?;
        Ok(id)
    }
}

#[cfg(test)]
fn require_mlock() -> bool {
    false
}

#[cfg(not(test))]
fn require_mlock() -> bool {
    match std::env::var(constants::ENV_FISHNET_VAULT_REQUIRE_MLOCK) {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

pub async fn list_credentials(State(state): State<AppState>) -> impl IntoResponse {
    match state.credential_store.list_credentials().await {
        Ok(credentials) => Json(credentials).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("vault error: {e}") })),
        )
            .into_response(),
    }
}

pub async fn create_credential(
    State(state): State<AppState>,
    Json(req): Json<CreateCredentialRequest>,
) -> impl IntoResponse {
    if req.service.trim().is_empty() || req.name.trim().is_empty() || req.key.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "service, name, and key are required"
            })),
        )
            .into_response();
    }

    match state
        .credential_store
        .add_credential(&req.service, &req.name, &req.key)
        .await
    {
        Ok(credential) => Json(serde_json::json!(credential)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("vault error: {e}") })),
        )
            .into_response(),
    }
}

pub async fn delete_credential(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.credential_store.delete_credential(&id).await {
        Ok(true) => Json(serde_json::json!({ "deleted": true })).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "credential not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("vault error: {e}") })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(DecryptedCredential: Copy, Clone, std::fmt::Debug, serde::Serialize);

    fn metadata_by_id<'a>(
        credentials: &'a [CredentialMetadata],
        id: &str,
    ) -> &'a CredentialMetadata {
        credentials
            .iter()
            .find(|credential| credential.id == id)
            .expect("credential must exist")
    }

    #[tokio::test]
    async fn derived_key_can_reopen_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");

        let store = CredentialStore::open(path.clone(), "master-password").unwrap();
        store
            .add_credential("openai", "primary", "sk-test-123")
            .await
            .unwrap();
        let derived_hex = store.derived_key_hex();
        drop(store);

        let derived = hex::decode(derived_hex).unwrap();
        let reopened = CredentialStore::open_with_derived_key(path, &derived).unwrap();
        let credential = reopened
            .decrypt_for_service("openai")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(credential.key.as_str(), "sk-test-123");
    }

    #[test]
    fn invalid_derived_key_length_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let store = CredentialStore::open(path.clone(), "master-password").unwrap();
        drop(store);

        let result = CredentialStore::open_with_derived_key(path, &[0u8; 8]);
        assert!(matches!(result, Err(VaultError::InvalidDerivedKey)));
    }

    #[tokio::test]
    async fn touch_last_used_updates_timestamp_after_short_delay() {
        let store = CredentialStore::open_in_memory("master-password").unwrap();
        let credential_id = store
            .insert_plaintext_for_test("openai", "primary", "sk-test-timing")
            .unwrap();

        let initial = store.list_credentials().await.unwrap();
        assert!(
            metadata_by_id(&initial, &credential_id)
                .last_used_at
                .is_none()
        );

        store.touch_last_used(&credential_id).await.unwrap();
        let first = store.list_credentials().await.unwrap();
        let first_used = metadata_by_id(&first, &credential_id)
            .last_used_at
            .expect("first touch must set last_used_at");

        tokio::time::sleep(Duration::from_millis(1200)).await;

        store.touch_last_used(&credential_id).await.unwrap();
        let second = store.list_credentials().await.unwrap();
        let second_used = metadata_by_id(&second, &credential_id)
            .last_used_at
            .expect("second touch must keep last_used_at set");

        assert!(
            second_used > first_used,
            "last_used_at should move forward after later access"
        );
    }

    #[tokio::test]
    async fn credential_remains_decryptable_across_millisecond_intervals() {
        let store = CredentialStore::open_in_memory("master-password").unwrap();
        store
            .add_credential("openai", "primary", "sk-test-interval")
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(25)).await;
        let first = store
            .decrypt_for_service("openai")
            .await
            .unwrap()
            .expect("credential must exist");
        assert_eq!(first.key.as_str(), "sk-test-interval");
        drop(first);

        tokio::time::sleep(Duration::from_millis(25)).await;
        let second = store
            .decrypt_for_service("openai")
            .await
            .unwrap()
            .expect("credential must exist");
        assert_eq!(second.key.as_str(), "sk-test-interval");
    }

    #[tokio::test]
    async fn list_credentials_metadata_never_contains_raw_secret() {
        let store = CredentialStore::open_in_memory("master-password").unwrap();
        let raw_secret = "sk-never-visible";
        store
            .add_credential("openai", "primary", raw_secret)
            .await
            .unwrap();

        let metadata = store.list_credentials().await.unwrap();
        let serialized = serde_json::to_string(&metadata).unwrap();
        assert!(!serialized.contains(raw_secret));
    }

    #[test]
    fn malformed_existing_salt_is_rejected_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let malformed_salt = vec![1u8, 2, 3];

        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO vault_meta(key, value) VALUES(?1, ?2)",
            params![META_SALT_KEY, malformed_salt.clone()],
        )
        .unwrap();
        drop(conn);

        let err = match CredentialStore::open(path.clone(), "master-password") {
            Ok(_) => panic!("expected malformed salt to be rejected"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            VaultError::InvalidSaltLength {
                expected: SALT_LEN,
                found: 3
            }
        ));

        let conn = Connection::open(path).unwrap();
        let persisted: Vec<u8> = conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = ?1",
                params![META_SALT_KEY],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted, malformed_salt);
    }
}

use async_trait::async_trait;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use k256::ecdsa::{SigningKey, RecoveryId, signature::hazmat::PrehashSigner};
use serde::Serialize;
use sha3::{Digest, Keccak256};

use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct SignerInfo {
    pub mode: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FishnetPermit {
    pub wallet: String,
    pub chain_id: u64,
    pub nonce: u64,
    pub expiry: u64,
    pub target: String,
    pub value: String,
    pub calldata_hash: String,
    pub policy_hash: Option<String>,
    pub verifying_contract: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

#[async_trait]
pub trait SignerTrait: Send + Sync {
    async fn sign_permit(&self, permit: &FishnetPermit) -> Result<Vec<u8>, SignerError>;
    fn status(&self) -> SignerInfo;
}

pub struct StubSigner {
    signing_key: SigningKey,
    address: [u8; 20],
}

impl Default for StubSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl StubSigner {
    pub fn new() -> Self {
        let secret_bytes: [u8; 32] = rand::random();
        Self::from_bytes(secret_bytes)
    }

    pub fn from_bytes(secret_bytes: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes((&secret_bytes).into())
            .expect("valid 32-byte key");
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let hash = Keccak256::digest(&public_key_bytes.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        Self {
            signing_key,
            address,
        }
    }

    fn eip712_hash(&self, permit: &FishnetPermit) -> [u8; 32] {

        let domain_type_hash = Keccak256::digest(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        let name_hash = Keccak256::digest(b"FishnetPermit");
        let version_hash = Keccak256::digest(b"1");

        let mut domain_data = Vec::new();
        domain_data.extend_from_slice(&domain_type_hash);
        domain_data.extend_from_slice(&name_hash);
        domain_data.extend_from_slice(&version_hash);

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[24..].copy_from_slice(&permit.chain_id.to_be_bytes());
        domain_data.extend_from_slice(&chain_id_bytes);

        let vc_bytes = hex::decode(
            permit.verifying_contract.strip_prefix("0x").unwrap_or(&permit.verifying_contract),
        )
        .unwrap_or_default();
        let mut vc_padded = [0u8; 32];
        if vc_bytes.len() <= 32 {
            vc_padded[32 - vc_bytes.len()..].copy_from_slice(&vc_bytes);
        }
        domain_data.extend_from_slice(&vc_padded);
        let domain_separator = Keccak256::digest(&domain_data);


        let permit_type_hash = Keccak256::digest(
            b"FishnetPermit(address wallet,uint256 chainId,uint256 nonce,uint256 expiry,address target,uint256 value,bytes32 calldataHash,bytes32 policyHash)"
        );

        let mut struct_data = Vec::new();
        struct_data.extend_from_slice(&permit_type_hash);


        let wallet_bytes = hex::decode(permit.wallet.strip_prefix("0x").unwrap_or(&permit.wallet)).unwrap_or_default();
        let mut wallet_padded = [0u8; 32];
        if wallet_bytes.len() <= 32 {
            wallet_padded[32 - wallet_bytes.len()..].copy_from_slice(&wallet_bytes);
        }
        struct_data.extend_from_slice(&wallet_padded);


        struct_data.extend_from_slice(&chain_id_bytes);


        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[24..].copy_from_slice(&permit.nonce.to_be_bytes());
        struct_data.extend_from_slice(&nonce_bytes);


        let mut expiry_bytes = [0u8; 32];
        expiry_bytes[24..].copy_from_slice(&permit.expiry.to_be_bytes());
        struct_data.extend_from_slice(&expiry_bytes);


        let target_bytes = hex::decode(permit.target.strip_prefix("0x").unwrap_or(&permit.target)).unwrap_or_default();
        let mut target_padded = [0u8; 32];
        if target_bytes.len() <= 32 {
            target_padded[32 - target_bytes.len()..].copy_from_slice(&target_bytes);
        }
        struct_data.extend_from_slice(&target_padded);


        let value_u256 = alloy_primitives::U256::from_str_radix(&permit.value, 10)
            .unwrap_or(alloy_primitives::U256::ZERO);
        struct_data.extend_from_slice(&value_u256.to_be_bytes::<32>());


        let calldata_hash_bytes = hex::decode(permit.calldata_hash.strip_prefix("0x").unwrap_or(&permit.calldata_hash)).unwrap_or_default();
        let mut calldata_padded = [0u8; 32];
        if calldata_hash_bytes.len() == 32 {
            calldata_padded.copy_from_slice(&calldata_hash_bytes);
        }
        struct_data.extend_from_slice(&calldata_padded);


        let policy_padded = match &permit.policy_hash {
            Some(ph) => {
                let ph_bytes = hex::decode(ph.strip_prefix("0x").unwrap_or(ph)).unwrap_or_default();
                let mut padded = [0u8; 32];
                if ph_bytes.len() == 32 {
                    padded.copy_from_slice(&ph_bytes);
                }
                padded
            }
            None => [0u8; 32],
        };
        struct_data.extend_from_slice(&policy_padded);

        let struct_hash = Keccak256::digest(&struct_data);


        let mut final_data = Vec::with_capacity(66);
        final_data.push(0x19);
        final_data.push(0x01);
        final_data.extend_from_slice(&domain_separator);
        final_data.extend_from_slice(&struct_hash);

        let result = Keccak256::digest(&final_data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

#[async_trait]
impl SignerTrait for StubSigner {
    async fn sign_permit(&self, permit: &FishnetPermit) -> Result<Vec<u8>, SignerError> {
        let hash = self.eip712_hash(permit);
        let (signature, recovery_id): (k256::ecdsa::Signature, RecoveryId) = self
            .signing_key
            .sign_prehash(&hash)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;


        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&signature.to_bytes());
        sig_bytes.push(recovery_id.to_byte() + 27);
        Ok(sig_bytes)
    }

    fn status(&self) -> SignerInfo {
        SignerInfo {
            mode: "stub-secp256k1".to_string(),
            address: format!("0x{}", hex::encode(self.address)),
        }
    }
}

pub async fn status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config();

    if !config.onchain.enabled {
        return Json(serde_json::json!({
            "enabled": false,
            "mode": null,
            "address": null,
            "chain_ids": [],
            "config": {},
            "stats": {},
        }));
    }

    let signer_info = state.signer.status();
    let stats = state
        .spend_store
        .get_onchain_stats()
        .await
        .unwrap_or_default();

    Json(serde_json::json!({
        "enabled": true,
        "mode": signer_info.mode,
        "address": signer_info.address,
        "chain_ids": config.onchain.chain_ids,
        "config": {
            "max_tx_value_usd": config.onchain.limits.max_tx_value_usd,
            "daily_spend_cap_usd": config.onchain.limits.daily_spend_cap_usd,
            "cooldown_seconds": config.onchain.limits.cooldown_seconds,
            "max_slippage_bps": config.onchain.limits.max_slippage_bps,
            "permit_expiry_seconds": config.onchain.permits.expiry_seconds,
        },
        "stats": {
            "total_permits_signed": stats.total_signed,
            "total_permits_denied": stats.total_denied,
            "spent_today_usd": stats.spent_today_usd,
            "last_permit_at": stats.last_permit_at,
        },
    }))
}

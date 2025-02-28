use serde::{Deserialize, Serialize};
use thiserror::Error;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use vaultrs::kv2;

use crate::idp::ext::IdpConfig;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault client error: {0}")]
    ClientError(#[from] ClientError),

    #[error("Missing OIDC token: {0}")]
    MissingToken(String),

    #[error("Failed to create token: {0}")]
    TokenCreationError(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultToken {
    pub client_token: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub renewable: bool,
    pub lease_duration: u64,
}

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub address: String,
    pub token: String,
    pub oidc_path: String,
    pub oidc_role: String,
}

pub struct VaultService {
    client: VaultClient,
    config: VaultConfig,
}

impl VaultService {
    pub async fn from_env() -> Result<Self, VaultError> {
        let address = std::env::var("VAULT_ADDR").ok().unwrap();
        let token = std::env::var("VAULT_TOKEN").ok().unwrap();
        let config = VaultConfig {
            address,
            token,
            oidc_path: "oidc".to_string(), // Path from vault_jwt_auth_backend.keycloak in terraform
            oidc_role: "default".to_string(), // Role from vault_jwt_auth_backend_role.default in terraform
        };
        Self::new(config).await
    }

    pub async fn new(config: VaultConfig) -> Result<Self, VaultError> {
        let settings = VaultClientSettingsBuilder::default()
            .address(&config.address)
            .token(&config.token)
            .build()
            .expect("Unable to build the vault client");

        let client = VaultClient::new(settings)?;

        Ok(Self {
            client,
            config: config,
        })
    }

    pub async fn get_idp_config_from_vault(&self) -> Result<IdpConfig, VaultError> {
        let key = "idp/app-config";
        match kv2::read::<IdpConfig>(&self.client, "secret", key).await {
            Ok(secret) => {
                tracing::debug!("Got secret {}", key);
                Ok(secret)
            }
            Err(e) => {
                tracing::error!("Failed to get secret {}: {}", key, e);
                Err(e.into())
            }
        }
    }
}

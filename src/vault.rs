// Todo: Remove the admin client from this file. It's not needed here.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use moka::future::{Cache, CacheBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use vaultrs::api::token::requests::CreateRoleTokenRequestBuilder;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use vaultrs::kv2;

use crate::idp::ext::IdpConfig;
use crate::oidc::keycloak::KeyCloakToken;
use crate::{AiclIdentity, Role};

// API token structure returned to users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub client_token: String,
    pub expires_at: u64, // Unix timestamp in seconds
    pub renewable: bool,
    pub policies: Vec<String>,
}

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault client error: {0}")]
    ClientError(#[from] ClientError),

    #[error("Missing OIDC token: {0}")]
    MissingToken(String),

    #[error("Failed to create token: {0}")]
    TokenCreationError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("OIDC error: {0}")]
    OidcError(String),

    #[error("System time error: {0}")]
    TimeError(String),
}

#[derive(Error, Debug, Clone)]
#[error("Token verification failed: {0}")]
pub struct VerificationError(String);

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub address: String,
    pub token: String,
    pub oidc_path: String,
    pub oidc_role: String,
}

pub struct VaultService {
    admin_client: VaultClient,
    config: VaultConfig,
    // Cache for user data by user ID
    token_cache: Cache<String, Result<Uuid, VerificationError>>,
}

impl VaultService {
    pub async fn from_env() -> Result<Self, VaultError> {
        #[cfg(not(feature = "test-utils"))]
        let address = std::env::var("VAULT_ADDR").ok().unwrap();
        #[cfg(not(feature = "test-utils"))]
        let token = std::env::var("VAULT_TOKEN").ok().unwrap();
        #[cfg(feature = "test-utils")]
        let address = "http://localhost:8200".to_string();
        #[cfg(feature = "test-utils")]
        let token = "myroot".to_string();

        let config = VaultConfig {
            address,
            token,
            oidc_path: "jwt".to_string(), // Path from vault_jwt_auth_backend.keycloak in terraform
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

        let admin_client = VaultClient::new(settings)?;
        let token_cache = CacheBuilder::new(1000)
            .time_to_live(Duration::from_secs(60))
            .build();

        Ok(Self {
            admin_client,
            config: config,
            token_cache,
        })
    }

    pub async fn get_idp_config_from_vault(&self) -> Result<IdpConfig, VaultError> {
        let key = "idp/app-config";
        match kv2::read::<IdpConfig>(&self.admin_client, "secret", key).await {
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

    // Get current Unix timestamp
    fn current_timestamp() -> Result<u64, VaultError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| VaultError::TimeError(e.to_string()))
    }

    // Create a new Vault client authenticated via OIDC for the user
    async fn create_user_vault_client(
        &self,
        jwt: &str,
        role: Option<String>,
    ) -> Result<VaultClient, VaultError> {
        tracing::info!("Creating a new Vault client for the user");
        let login =
            vaultrs::auth::oidc::login(&self.admin_client, &self.config.oidc_path, jwt, role)
                .await?;

        // Create a new Vault client with the user's token
        let user_settings = VaultClientSettingsBuilder::default()
            .address(&self.config.address)
            .token(&login.client_token)
            .build()
            .map_err(|e| VaultError::OidcError(format!("Failed to build Vault client: {}", e)))?;

        let user_client =
            VaultClient::new(user_settings).map_err(|e| VaultError::ClientError(e))?;

        Ok(user_client)
    }

    // Create a new API token for the user using their OIDC token
    pub async fn create_api_token_with_oidc(
        &self,
        identity: &AiclIdentity,
        oidc_token: &KeyCloakToken,
    ) -> Result<ApiToken, VaultError> {
        // Get the ID token string
        let id_token_str = oidc_token.id_token.to_string();
        tracing::debug!(identity.username, "Creating API token for user");

        let vault_role = match (&identity.team, &identity.role) {
            (Some(team), Role::Captain) => Some(format!("team-{}-captain", team.name)),
            (Some(team), _) => Some(format!("team-{}-member", team.name)),
            (None, Role::Admin) => Some("global-admin".to_string()),
            (None, Role::Spectator) => Some("global-spectator".to_string()),
            _ => None,
        };

        // Create a Vault client authenticated as the user via OIDC
        let user_client = self
            .create_user_vault_client(&id_token_str, vault_role.clone())
            .await?;
        tracing::debug!("User Vault client created");
        // Prepare token creation parameters using builder
        let mut builder = CreateRoleTokenRequestBuilder::default();
        // Set display name
        let timestamp = Self::current_timestamp().unwrap_or(0);
        let display_name = format!("api-token-{}-{}", identity.username, timestamp);
        builder.display_name(display_name);

        // Create token metadata
        let mut metadata = HashMap::new();
        metadata.insert("user_id".to_string(), identity.id.to_string());
        metadata.insert("role".to_string(), identity.role.as_str().to_string());
        builder.meta(metadata);
        tracing::debug!("Token metadata set");
        // Create the token using the user's Vault client with the builder

        let token_role = match (&identity.team, &identity.role) {
            (Some(team), Role::Captain) => Some(format!("team-{}-captain", team.name)),
            (Some(team), _) => Some(format!("team-{}-member", team.name)),
            (None, Role::Admin) => Some("global-admin".to_string()),
            (None, Role::Spectator) => Some("global-spectator".to_string()),
            _ => None,
        };
        let token_result =
            vaultrs::token::new_role(&user_client, &token_role.unwrap(), Some(&mut builder))
                .await
                .map_err(|e| VaultError::TokenCreationError(e.to_string()))?;
        tracing::debug!("Token created successfully");
        // Calculate expiration time as Unix timestamp
        let now = Self::current_timestamp()?;
        let expires_at = now + token_result.lease_duration;

        Ok(ApiToken {
            client_token: token_result.client_token,
            expires_at,
            renewable: token_result.renewable,
            policies: token_result.policies,
        })
    }

    // Verify an API token and extract the user ID
    async fn verify_token_inter(&self, token: &str) -> Result<uuid::Uuid, VerificationError> {
        // Lookup the token in Vault using the admin client
        // todo!(Make this log in with the token instead of listing it)
        let lookup_result = vaultrs::token::lookup(&self.admin_client, token)
            .await
            .map_err(|e| VerificationError(e.to_string()))?;

        // Check if token is expired by verifying ttl is greater than 0
        if lookup_result.ttl <= 0 {
            return Err(VerificationError("Token is expired".to_string()));
        }

        // Extract metadata
        let metadata = lookup_result
            .meta
            .ok_or_else(|| VerificationError("Token has no metadata".to_string()))?;

        // Extract user_id
        let user_id = metadata
            .get("user_id")
            .ok_or_else(|| VerificationError("Token missing user_id metadata".to_string()))?;

        // Parse user ID
        let user_id = uuid::Uuid::parse_str(user_id)
            .map_err(|_| VerificationError("Invalid user ID format".to_string()))?;

        Ok(user_id)
    }

    pub async fn verify_token(
        self: &Arc<Self>,
        token: &str,
    ) -> Result<uuid::Uuid, VerificationError> {
        let this = self.clone();
        let this_token = token.to_string();
        self.token_cache
            .get_with(
                this_token,
                async move { this.verify_token_inter(token).await },
            )
            .await
    }

    // Revoke an API token
    pub async fn revoke_token(&self, token: &str) -> Result<(), VaultError> {
        // Revoke the token in Vault using the admin client
        vaultrs::token::revoke(&self.admin_client, token)
            .await
            .map_err(|e| VaultError::ClientError(e))?;

        Ok(())
    }

    // Allow users to revoke their own tokens using their user-scoped Vault client
    pub async fn revoke_own_token(
        &self,
        oidc_token: &KeyCloakToken,
        token_to_revoke: &str,
    ) -> Result<(), VaultError> {
        // Get the ID token string
        let id_token_str = oidc_token.id_token.to_string();

        // Create a Vault client authenticated as the user via OIDC
        let user_client = self.create_user_vault_client(&id_token_str, None).await?;

        // Revoke the token using the user's Vault client
        vaultrs::token::revoke(&user_client, token_to_revoke)
            .await
            .map_err(|e| VaultError::ClientError(e))?;

        Ok(())
    }
}

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use uuid::Uuid;

/// A generic user representation that can be used across different identity providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: bool,
    pub attributes: HashMap<String, Vec<String>>,
}

/// A generic group representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpGroup {
    pub id: Uuid,
    pub name: String,
    pub path: String,
    pub parent_id: Option<Uuid>,
    pub attributes: HashMap<String, Vec<String>>,
}

/// A generic group representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpGroupHeader {
    pub id: Uuid,
    pub name: String,
}

/// A generic role representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpRole {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_composite: bool,
    pub source: String, // "realm", "client", etc.
}

/// Error types for identity provider operations
#[derive(Debug, Error, Clone)]
pub enum IdpError {
    #[error("Oidc Error {0}")]
    OidcError(#[from] Arc<axum_oidc::error::Error>),

    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// The core trait that all identity providers must implement
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Initialize the identity provider with configuration
    async fn initialize(&mut self) -> Result<(), IdpError>;

    fn issuer(&self) -> String;

    /// Get all users from the identity provider
    async fn get_users(&self) -> Result<Vec<IdpUser>, IdpError>;

    /// Get a specific user by ID
    async fn get_user(&self, user_id: Uuid) -> Result<IdpUser, IdpError>;

    /// Get users by username (exact or partial match)
    async fn find_users_by_username(&self, username: &str) -> Result<Vec<IdpUser>, IdpError>;

    /// Get all groups from the identity provider
    async fn get_groups(&self) -> Result<Vec<IdpGroupHeader>, IdpError>;

    /// Get a specific group by ID
    async fn get_group(&self, group_id: Uuid) -> Result<IdpGroup, IdpError>;

    /// Get members of a specific group
    async fn get_group_members(&self, group_id: Uuid) -> Result<Vec<IdpUser>, IdpError>;

    /// Get groups that a user belongs to
    async fn get_user_groups(&self, user_id: Uuid) -> Result<Vec<IdpGroup>, IdpError>;

    /// Get roles assigned to a user
    async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<IdpRole>, IdpError>;

    /// Get a flattened list of all groups (including nested subgroups)
    fn flatten_groups(&self, groups: &[IdpGroup]) -> Vec<IdpGroup>;
}

/// Configuration for identity providers
#[derive(Debug, Clone, Deserialize)]
pub struct IdpConfig {
    pub provider_type: String, // "keycloak", "google", etc.
    pub base_url: String,
    pub realm: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub admin_username: Option<String>,
    pub admin_password: Option<String>,
    pub service_account_key_path: Option<String>,
    pub domain: Option<String>,
}

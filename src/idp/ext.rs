use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use crate::{AiclIdentity, InstitutionIdentity, Role, TeamIdentity};

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
#[serde(rename_all = "camelCase")]
pub struct IdpGroupHeader {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
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
    async fn get_groups(&self, parent: Option<Uuid>) -> Result<Vec<IdpGroupHeader>, IdpError>;

    /// Get a specific group by ID
    async fn get_group(&self, group_id: Uuid) -> Result<IdpGroup, IdpError>;

    /// Get members of a specific group
    async fn get_group_members(&self, group_id: Uuid) -> Result<Vec<IdpUser>, IdpError>;

    /// Get groups that a user belongs to
    async fn get_user_groups(&self, user_id: Uuid) -> Result<Vec<IdpGroup>, IdpError>;

    /// Get roles assigned to a user
    async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<IdpRole>, IdpError>;

    async fn to_domain_user(
        &self,
        user: &IdpUser,
    ) -> Result<AiclIdentity, IdpError> {
        // Extract team information from user's groups
        let groups = self.get_user_groups(user.id).await?;
        tracing::debug!("User {} is in groups {:?}", user.id, groups);
        let team = groups.iter().find_map(|group| {
            if group.path.starts_with("/Teams/") {
                Some(TeamIdentity {
                    id: group.id,
                    name: group.name.clone(),
                })
            } else {
                None
            }
        });
        let institution = groups.iter().find_map(|group| {
            if group.path.starts_with("/Institutions/") {
                Some(InstitutionIdentity {
                    id: group.id,
                    name: group.name.clone(),
                })
            } else {
                None
            }
        });
        let roles = self.get_user_roles(user.id).await?;
        tracing::debug!(user.username, "User has {} roles.", roles.len());
        if roles.len() > 1 {
            tracing::error!(
                user.username,
                "User has multiple roles, only the first one will be used."
            );
        }
        if roles.len() == 0 {
            tracing::error!(user.username, "User has no roles.");
        }

        let role = match roles.first().map(|r| Role::parse(&r.name)) {
            Some(role) => role,
            _ => Role::Spectator,
        };

        let username = user.username.clone();

        Ok(AiclIdentity {
            username,
            team,
            institution,
            role,
            email: user.email.clone(),
            id: user.id,
        })
    }

    async fn get_domain_user(
        &self,
        user_id: Uuid,
    ) -> Result<AiclIdentity, IdpError> {
        let user = self.get_user(user_id).await?;
        self.to_domain_user(&user).await
    }
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

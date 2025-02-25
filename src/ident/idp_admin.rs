use moka::future::{Cache, CacheBuilder};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use thiserror::Error;

use super::{keycloak::KeycloakProvider, AiclIdentity};

/// A generic user representation that can be used across different identity providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpUser {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: bool,
    pub groups: Vec<IdpGroup>,
    pub roles: Vec<IdpRole>,
    pub attributes: HashMap<String, Vec<String>>,
}

/// A generic group representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpGroup {
    pub id: String,
    pub name: String,
    pub path: String,
    pub parent_id: Option<String>,
    pub attributes: HashMap<String, Vec<String>>,
}

/// A generic role representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpRole {
    pub id: String,
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
pub trait IdentityProvider: Send + Sync {
    /// Initialize the identity provider with configuration
    async fn initialize(&mut self) -> Result<(), IdpError>;

    /// Get all users from the identity provider
    async fn get_users(&self) -> Result<Vec<IdpUser>, IdpError>;

    /// Get a specific user by ID
    async fn get_user(&self, user_id: &str) -> Result<IdpUser, IdpError>;

    /// Get users by username (exact or partial match)
    async fn find_users_by_username(&self, username: &str) -> Result<Vec<IdpUser>, IdpError>;

    /// Get users by email (exact or partial match)
    async fn find_users_by_email(&self, email: &str) -> Result<Vec<IdpUser>, IdpError>;

    /// Get all groups from the identity provider
    async fn get_groups(&self) -> Result<Vec<IdpGroup>, IdpError>;

    /// Get a specific group by ID
    async fn get_group(&self, group_id: &str) -> Result<IdpGroup, IdpError>;

    /// Get members of a specific group
    async fn get_group_members(&self, group_id: &str) -> Result<Vec<IdpUser>, IdpError>;

    /// Get groups that a user belongs to
    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<IdpGroup>, IdpError>;

    /// Get all roles defined in the identity provider
    async fn get_roles(&self) -> Result<Vec<IdpRole>, IdpError>;

    /// Get roles assigned to a user
    async fn get_user_roles(&self, user_id: &str) -> Result<Vec<IdpRole>, IdpError>;

    /// Get a flattened list of all groups (including nested subgroups)
    fn flatten_groups(&self, groups: &[IdpGroup]) -> Vec<IdpGroup>;

    /// Get a comprehensive report of all users with their groups and roles
    async fn get_comprehensive_report(&self) -> Result<Vec<IdpUser>, IdpError>;

    /// Convert provider-specific user to application domain model
    fn to_domain_user(&self, user: &IdpUser) -> Result<AiclIdentity,IdpError>;
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

pub struct IdpAdmin {
    config: IdpConfig,
    provider: KeycloakProvider,
    // Cache for user data by user ID
    users_by_id: Cache<Arc<str>, Result<IdpUser, IdpError>>,
    // Cache for all users
    all_users: Cache<(), Result<Vec<IdpUser>, IdpError>>,
    // Cache for users by username
    users_by_username: Cache<Arc<str>, Result<Vec<IdpUser>, IdpError>>,
    // Cache for users by email
    users_by_email: Cache<Arc<str>, Result<Vec<IdpUser>, IdpError>>,
    // Cache for all groups
    all_groups: Cache<(), Result<Vec<IdpGroup>, IdpError>>,
    // Cache for group by ID
    group_by_id: Cache<Arc<str>, Result<IdpGroup, IdpError>>,
    // Cache for group members
    group_members: Cache<Arc<str>, Result<Vec<IdpUser>, IdpError>>,
    // Cache for user groups
    user_groups: Cache<Arc<str>, Result<Vec<IdpGroup>, IdpError>>,
    // Cache for all roles
    all_roles: Cache<(), Result<Vec<IdpRole>, IdpError>>,
    // Cache for user roles
    user_roles: Cache<Arc<str>, Result<Vec<IdpRole>, IdpError>>,
    // Cache for comprehensive report
    comprehensive_report: Cache<(), Result<Vec<IdpUser>, IdpError>>,
}

impl IdpAdmin {
    pub async fn new(config: IdpConfig) -> Result<Arc<Self>, IdpError> {
        let mut provider = match config.provider_type.as_str() {
            "keycloak" => KeycloakProvider::new(&config)?,
            _ => return Err(IdpError::InvalidInput(format!(
                "Unsupported identity provider type: {}", 
                config.provider_type
            ))),
        };

        provider.initialize().await?;

        // Create caches with appropriate TTL settings
        let cache_ttl = Duration::from_secs(120); // 2 minutes
        
        let users_by_id = CacheBuilder::new(1000)
            .time_to_idle(cache_ttl)
            .build();
            
        let all_users = CacheBuilder::new(10) // Small size as this is just a single key
            .time_to_idle(cache_ttl)
            .build();
            
        let users_by_username = CacheBuilder::new(500)
            .time_to_idle(cache_ttl)
            .build();
            
        let users_by_email = CacheBuilder::new(500)
            .time_to_idle(cache_ttl)
            .build();
            
        let all_groups = CacheBuilder::new(10)
            .time_to_idle(cache_ttl)
            .build();
            
        let group_by_id = CacheBuilder::new(500)
            .time_to_idle(cache_ttl)
            .build();
            
        let group_members = CacheBuilder::new(500)
            .time_to_idle(cache_ttl)
            .build();
            
        let user_groups = CacheBuilder::new(1000)
            .time_to_idle(cache_ttl)
            .build();
            
        let all_roles = CacheBuilder::new(10)
            .time_to_idle(cache_ttl)
            .build();
            
        let user_roles = CacheBuilder::new(1000)
            .time_to_idle(cache_ttl)
            .build();
            
        let comprehensive_report = CacheBuilder::new(10)
            .time_to_idle(cache_ttl)
            .build();

        Ok(Arc::new(IdpAdmin { 
            config, 
            provider, 
            users_by_id,
            all_users,
            users_by_username,
            users_by_email,
            all_groups,
            group_by_id,
            group_members,
            user_groups,
            all_roles,
            user_roles,
            comprehensive_report,
        }))
    }

    /// Get a specific user by ID with caching
    pub async fn get_user(self: &Arc<Self>, user_id: &str) -> Result<IdpUser, IdpError> {
        let user_id_arc = Arc::from(user_id);
        let this = self.clone();
        
        self.users_by_id.get_with(user_id_arc, async move {
            this.provider.get_user(user_id).await
        }).await
    }

    /// Get all users with caching
    pub async fn get_users(self: &Arc<Self>) -> Result<Vec<IdpUser>, IdpError> {
        let this = self.clone();
        
        self.all_users.get_with((), async move {
            this.provider.get_users().await
        }).await
    }

    /// Find users by username with caching
    pub async fn find_users_by_username(self: &Arc<Self>, username: &str) -> Result<Vec<IdpUser>, IdpError> {
        let username_arc = Arc::from(username);
        let this = self.clone();
        
        self.users_by_username.get_with(username_arc, async move {
            this.provider.find_users_by_username(username).await
        }).await
    }

    /// Find users by email with caching
    pub async fn find_users_by_email(self: &Arc<Self>, email: &str) -> Result<Vec<IdpUser>, IdpError> {
        let email_arc = Arc::from(email);
        let this = self.clone();
        
        self.users_by_email.get_with(email_arc, async move {
            this.provider.find_users_by_email(email).await
        }).await
    }

    /// Get all groups with caching
    pub async fn get_groups(self: &Arc<Self>) -> Result<Vec<IdpGroup>, IdpError> {
        let this = self.clone();
        
        self.all_groups.get_with((), async move {
            this.provider.get_groups().await
        }).await
    }

    /// Get a specific group by ID with caching
    pub async fn get_group(self: &Arc<Self>, group_id: &str) -> Result<IdpGroup, IdpError> {
        let group_id_arc = Arc::from(group_id);
        let this = self.clone();
        
        self.group_by_id.get_with(group_id_arc, async move {
            this.provider.get_group(group_id).await
        }).await
    }

    /// Get members of a specific group with caching
    pub async fn get_group_members(self: &Arc<Self>, group_id: &str) -> Result<Vec<IdpUser>, IdpError> {
        let group_id_arc = Arc::from(group_id);
        let this = self.clone();
        
        self.group_members.get_with(group_id_arc, async move {
            this.provider.get_group_members(group_id).await
        }).await
    }

    /// Get groups that a user belongs to with caching
    pub async fn get_user_groups(self: &Arc<Self>, user_id: &str) -> Result<Vec<IdpGroup>, IdpError> {
        let user_id_arc = Arc::from(user_id);
        let this = self.clone();
        
        self.user_groups.get_with(user_id_arc, async move {
            this.provider.get_user_groups(user_id).await
        }).await
    }

    /// Get all roles with caching
    pub async fn get_roles(self: &Arc<Self>) -> Result<Vec<IdpRole>, IdpError> {
        let this = self.clone();
        
        self.all_roles.get_with((), async move {
            this.provider.get_roles().await
        }).await
    }

    /// Get roles assigned to a user with caching
    pub async fn get_user_roles(self: &Arc<Self>, user_id: &str) -> Result<Vec<IdpRole>, IdpError> {
        let user_id_arc = Arc::from(user_id);
        let this = self.clone();
        
        self.user_roles.get_with(user_id_arc, async move {
            this.provider.get_user_roles(user_id).await
        }).await
    }

    /// Get a flattened list of all groups (including nested subgroups)
    pub async fn flatten_groups(self: &Arc<Self>, groups: &[IdpGroup]) -> Vec<IdpGroup> {
        self.provider.flatten_groups(groups)
    }

    /// Get a comprehensive report of all users with their groups and roles with caching
    pub async fn get_comprehensive_report(self: &Arc<Self>) -> Result<Vec<IdpUser>, IdpError> {
        let this = self.clone();
        
        self.comprehensive_report.get_with((), async move {
            this.provider.get_comprehensive_report().await
        }).await
    }

    /// Convert provider-specific user to application domain model
    pub fn to_domain_user(self: &Arc<Self>, user: &IdpUser) -> Result<AiclIdentity, IdpError> {
        self.provider.to_domain_user(user)
    }
    
    /// Invalidate all caches - useful when data might have changed externally
    pub fn invalidate_caches(self: &Arc<Self>) {
        self.users_by_id.invalidate_all();
        self.all_users.invalidate_all();
        self.users_by_username.invalidate_all();
        self.users_by_email.invalidate_all();
        self.all_groups.invalidate_all();
        self.group_by_id.invalidate_all();
        self.group_members.invalidate_all();
        self.user_groups.invalidate_all();
        self.all_roles.invalidate_all();
        self.user_roles.invalidate_all();
        self.comprehensive_report.invalidate_all();
    }
    
    /// Invalidate cache for a specific user
    pub fn invalidate_user_cache(self: &Arc<Self>, user_id: &str) {
        let user_id_arc = Arc::from(user_id);
        self.users_by_id.invalidate(&user_id_arc);
        // Also invalidate collections that might contain this user
        self.all_users.invalidate_all();
        self.users_by_username.invalidate_all();
        self.users_by_email.invalidate_all();
        self.group_members.invalidate_all();
        self.user_groups.invalidate(&user_id_arc);
        self.user_roles.invalidate(&user_id_arc);
        self.comprehensive_report.invalidate_all();
    }
    
    /// Invalidate cache for a specific group
    pub fn invalidate_group_cache(self: &Arc<Self>, group_id: &str) {
        let group_id_arc = Arc::from(group_id);
        self.group_by_id.invalidate(&group_id_arc);
        self.group_members.invalidate(&group_id_arc);
        // Also invalidate collections that might contain this group
        self.all_groups.invalidate_all();
        self.user_groups.invalidate_all();
        self.comprehensive_report.invalidate_all();
    }
}
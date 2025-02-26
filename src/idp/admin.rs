use atomic_time::AtomicInstant;
use moka::future::{Cache, CacheBuilder};
use std::{
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
use uuid::Uuid;

use crate::{AiclIdentity, InstitutionIdentity, Role, TeamIdentity};

use super::{
    ext::{IdentityProvider, IdpConfig, IdpError, IdpGroup, IdpGroupHeader, IdpRole, IdpUser},
    keycloak::KeycloakProvider,
};

pub struct IdpAdmin {
    _config: IdpConfig,
    provider: Box<dyn IdentityProvider>,
    teams_group_id: Uuid,
    institutions_group_id: Uuid,
    // Cache for user data by user ID
    users_by_id: Cache<Uuid, Result<IdpUser, IdpError>>,
    // Cache for all users
    all_users_call: AtomicInstant,
    // Cache for users by username
    users_by_username: Cache<Arc<str>, Result<Vec<IdpUser>, IdpError>>,
    // Cache for users by email
    users_by_email: Cache<Arc<str>, Result<Vec<IdpUser>, IdpError>>,
    // Cache for group by ID
    all_groups: Cache<(), Vec<IdpGroupHeader>>,
    group_by_id: Cache<Uuid, Result<IdpGroup, IdpError>>,
    // Cache for group members
    group_members: Cache<Uuid, Result<Vec<IdpUser>, IdpError>>,
    // Cache for user groups
    user_groups: Cache<Uuid, Result<Vec<IdpGroup>, IdpError>>,
    // Cache for user roles
    user_roles: Cache<Uuid, Result<Vec<IdpRole>, IdpError>>,
    // Cache for comprehensive report
    comprehensive_report: Cache<(), Result<Vec<IdpUser>, IdpError>>,
}

impl IdpAdmin {
    pub async fn new(config: IdpConfig) -> Result<Arc<Self>, IdpError> {
        let mut provider = match config.provider_type.as_str() {
            "keycloak" => KeycloakProvider::new(&config)?,
            _ => {
                return Err(IdpError::InvalidInput(format!(
                    "Unsupported identity provider type: {}",
                    config.provider_type
                )))
            }
        };

        provider.initialize().await?;
        let groups = provider.get_groups().await?;
        let teams_group_id = groups.iter().find(|g| g.name == "Teams").map(|g| g.id);
        if teams_group_id.is_none() {
            return Err(IdpError::InvalidInput("Teams group not found".to_string()));
        }
        let teams_group_id = teams_group_id.unwrap();

        let institutions_group_id = groups
            .iter()
            .find(|g| g.name == "Institutions")
            .map(|g| g.id);
        if institutions_group_id.is_none() {
            return Err(IdpError::InvalidInput(
                "Institutions group not found".to_string(),
            ));
        }
        let institutions_group_id = institutions_group_id.unwrap();

        // Create caches with appropriate TTL settings
        let cache_ttl = Duration::from_secs(120); // 2 minutes

        let users_by_id = CacheBuilder::new(1000).time_to_idle(cache_ttl).build();

        let all_users_call = AtomicInstant::new(Instant::now() - Duration::from_secs(2000));

        let users_by_username = CacheBuilder::new(500).time_to_idle(cache_ttl).build();

        let users_by_email = CacheBuilder::new(500).time_to_idle(cache_ttl).build();
        let all_groups = CacheBuilder::new(1).time_to_idle(cache_ttl).build();
        let group_by_id = CacheBuilder::new(500).time_to_idle(cache_ttl).build();

        let group_members = CacheBuilder::new(500).time_to_idle(cache_ttl).build();

        let user_groups = CacheBuilder::new(1000).time_to_idle(cache_ttl).build();

        let user_roles = CacheBuilder::new(1000).time_to_idle(cache_ttl).build();

        let comprehensive_report = CacheBuilder::new(10).time_to_idle(cache_ttl).build();

        Ok(Arc::new(IdpAdmin {
            _config: config,
            provider: Box::new(provider),
            teams_group_id,
            institutions_group_id,
            all_users_call,
            users_by_id,
            users_by_username,
            users_by_email,
            all_groups,
            group_by_id,
            group_members,
            user_groups,
            user_roles,
            comprehensive_report,
        }))
    }

    /// Get a specific user by ID with caching
    pub async fn get_user(self: &Arc<Self>, user_id: Uuid) -> Result<IdpUser, IdpError> {
        let this = self.clone();

        self.users_by_id
            .get_with(
                user_id,
                async move { this.provider.get_user(user_id).await },
            )
            .await
    }

    /// Get all users with caching
    pub async fn get_users(self: &Arc<Self>) -> Result<Vec<IdpUser>, IdpError> {
        let this = self.clone();
        let all_users_call = self.all_users_call.load(Ordering::Relaxed);
        if all_users_call.elapsed() > std::time::Duration::from_secs(60) {
            self.all_users_call
                .store(std::time::Instant::now(), Ordering::Relaxed);
            let all_users = this.provider.get_users().await?;
            for user in all_users {
                self.users_by_id.insert(user.id, Ok(user)).await;
            }
        }
        Ok(self
            .users_by_id
            .iter()
            .filter_map(|(_, user)| user.ok())
            .collect())
    }

    /// Find users by username with caching
    pub async fn find_users_by_username(
        self: &Arc<Self>,
        username: &str,
    ) -> Result<Vec<IdpUser>, IdpError> {
        let username_arc = Arc::from(username);
        let this = self.clone();

        self.users_by_username
            .get_with(username_arc, async move {
                this.provider.find_users_by_username(username).await
            })
            .await
    }

    /// Get all groups with caching
    pub async fn get_groups(self: &Arc<Self>) -> Result<Vec<IdpGroupHeader>, Arc<IdpError>> {
        let this = self.clone();
        self.all_groups
            .entry(())
            .or_try_insert_with(async move { this.provider.get_groups().await })
            .await
            .map(|entry| entry.into_value())
    }

    /// Get a specific group by ID with caching
    pub async fn get_group(self: &Arc<Self>, group_id: Uuid) -> Result<IdpGroup, IdpError> {
        let this = self.clone();

        self.group_by_id
            .get_with(
                group_id,
                async move { this.provider.get_group(group_id).await },
            )
            .await
    }

    /// Get members of a specific group with caching
    pub async fn get_group_members(
        self: &Arc<Self>,
        group_id: Uuid,
    ) -> Result<Vec<IdpUser>, IdpError> {
        let this = self.clone();

        self.group_members
            .get_with(group_id, async move {
                this.provider.get_group_members(group_id).await
            })
            .await
    }

    /// Get groups that a user belongs to with caching
    pub async fn get_user_groups(
        self: &Arc<Self>,
        user_id: Uuid,
    ) -> Result<Vec<IdpGroup>, IdpError> {
        let this = self.clone();

        self.user_groups
            .get_with(user_id, async move {
                this.provider.get_user_groups(user_id).await
            })
            .await
    }

    /// Get roles assigned to a user with caching
    pub async fn get_user_roles(self: &Arc<Self>, user_id: Uuid) -> Result<Vec<IdpRole>, IdpError> {
        let this = self.clone();

        self.user_roles
            .get_with(user_id, async move {
                this.provider.get_user_roles(user_id).await
            })
            .await
    }

    /// Get a flattened list of all groups (including nested subgroups)
    pub async fn flatten_groups(self: &Arc<Self>, groups: &[IdpGroup]) -> Vec<IdpGroup> {
        self.provider.flatten_groups(groups)
    }

    /// Get a comprehensive report of all users with their groups and roles with caching
    pub async fn get_comprehensive_report(self: &Arc<Self>) -> Result<Vec<AiclIdentity>, IdpError> {
        let users = self.get_users().await?;
        let mut report = Vec::new();
        for user in users {
            report.push(self.to_domain_user(&user).await?);
        }
        Ok(report)
    }

    pub async fn to_domain_user(
        self: &Arc<Self>,
        user: &IdpUser,
    ) -> Result<AiclIdentity, IdpError> {
        // Extract team information from user's groups
        let groups = self.get_user_groups(user.id).await?;
        tracing::debug!("User {} is in groups {:?}", user.id, groups);
        let team = groups.iter().find_map(|group| {
            if group.parent_id == Some(self.teams_group_id) {
                Some(TeamIdentity {
                    id: group.id,
                    name: group.name.clone(),
                })
            } else {
                None
            }
        });
        let institution = groups.iter().find_map(|group| {
            if group.parent_id == Some(self.institutions_group_id) {
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

    pub async fn get_domain_user(self: &Arc<Self>, user_id: Uuid) -> Result<AiclIdentity, IdpError> {
        let user = self.get_user(user_id).await?;
        self.to_domain_user(&user).await
    }

    /// Invalidate all caches - useful when data might have changed externally
    pub fn invalidate_caches(self: &Arc<Self>) {
        self.users_by_id.invalidate_all();
        self.users_by_username.invalidate_all();
        self.users_by_email.invalidate_all();
        self.group_by_id.invalidate_all();
        self.group_members.invalidate_all();
        self.user_groups.invalidate_all();
        self.user_roles.invalidate_all();
        self.comprehensive_report.invalidate_all();
    }

    /// Invalidate cache for a specific user
    pub async fn invalidate_user_cache(self: &Arc<Self>, user_id: Uuid) {
        self.users_by_id.invalidate(&user_id).await;
        // Also invalidate collections that might contain this user
        self.users_by_username.invalidate_all();
        self.users_by_email.invalidate_all();
        self.group_members.invalidate_all();
        self.user_groups.invalidate(&user_id).await;
        self.user_roles.invalidate(&user_id).await;
        self.comprehensive_report.invalidate_all();
    }

    /// Invalidate cache for a specific group
    pub async fn invalidate_group_cache(self: &Arc<Self>, group_id: Uuid) {
        self.group_by_id.invalidate(&group_id).await;
        self.group_members.invalidate(&group_id).await;
        // Also invalidate collections that might contain this group
        self.user_groups.invalidate_all();
        self.comprehensive_report.invalidate_all();
    }
}

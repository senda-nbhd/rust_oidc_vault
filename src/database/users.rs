use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use crate::{idp::ext::IdpUser, Role};

use super::IdpSyncService;

/// Complete user entity with all related information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: bool,
    pub attributes: serde_json::Value,
    pub role: Role,
    pub team_id: Option<Uuid>,
    pub institution_id: Option<Uuid>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

impl IdpSyncService {
    /// Synchronize all users from Keycloak
    #[instrument(skip(self), level = "info")]
    pub async fn sync_all_users(&self) -> anyhow::Result<usize> {
        info!("Starting synchronization of all users from Keycloak");
        
        // Start a transaction
        let mut tx = self.db.begin().await.context("Failed to begin transaction")?;
        
        // Get all users from Keycloak
        let idp_users = self.idp_admin.get_users().await
            .context("Failed to get users from Keycloak")?;
        
        info!(count = idp_users.len(), "Found users in Keycloak");
        let mut count = 0;
        
        // Process each user
        for idp_user in &idp_users {
            let user = self.sync_user(&mut tx, idp_user).await?;
            if self.update_user_cache(user).await {
                count += 1;
            }
        }
        
        // Commit the transaction
        tx.commit().await.context("Failed to commit transaction")?;
        
        info!(count, "Successfully synchronized users");
        
        Ok(count)
    }

    #[instrument(skip(self, tx, idp_user), fields(user_id = %idp_user.id, username = %idp_user.username), level = "debug")]
    async fn sync_user(
        &self, 
        tx: &mut Transaction<'_, Postgres>, 
        idp_user: &IdpUser
    ) -> anyhow::Result<CompleteUser> {
        debug!("Synchronizing user: {}", idp_user.username);

        // Convert attributes to JSON if any
        let attributes = serde_json::to_value(&idp_user.attributes)
            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));
        
        // Check if user already exists in idp_entities
        let entity_exists = sqlx::query!(
            r#"
            SELECT id FROM idp_entities 
            WHERE id = $1 AND type = 'user'
            "#,
            idp_user.id
        )
        .fetch_optional(&mut **tx)
        .await
        .context("Failed to query if user entity exists")?;

        // User entity record
        let entity_id = match entity_exists {
            Some(record) => {
                // Update existing entity
                debug!("Updating existing user entity: {}", idp_user.username);
                sqlx::query!(
                    r#"
                    UPDATE idp_entities 
                    SET 
                        name = $1, 
                        email = $2,
                        attributes = $3, 
                        updated_at = CURRENT_TIMESTAMP,
                        last_sync_at = CURRENT_TIMESTAMP
                    WHERE id = $4
                    "#,
                    idp_user.username,
                    idp_user.email,
                    attributes,
                    idp_user.id
                )
                .execute(&mut **tx)
                .await
                .context("Failed to update user entity")?;
                
                record.id
            },
            None => {
                // Insert new entity
                debug!("Creating new user entity: {}", idp_user.username);
                sqlx::query!(
                    r#"
                    INSERT INTO idp_entities 
                    (id, type, name, email, attributes, last_sync_at)
                    VALUES ($1, 'user', $2, $3, $4, CURRENT_TIMESTAMP)
                    RETURNING id
                    "#,
                    idp_user.id,
                    idp_user.username,
                    idp_user.email,
                    attributes
                )
                .fetch_one(&mut **tx)
                .await
                .context("Failed to insert user entity")?
                .id
            }
        };

        // Convert to a domain user to get team and institution information
        let domain_user = self.idp_admin.to_domain_user(idp_user).await
            .context("Failed to convert to domain user")?;


        // Check if user entry already exists
        let user_exists = sqlx::query!(
            r#"
            SELECT u.id, u.created_at, u.updated_at
            FROM users u
            WHERE u.entity_id = $1
            "#,
            entity_id
        )
        .fetch_optional(&mut **tx)
        .await
        .context("Failed to query if user exists")?;

        // User record
        let user_id = match user_exists {
            Some(record) => {
                // Update existing user
                debug!("Updating existing user: {}", idp_user.username);
                sqlx::query!(
                    r#"
                    UPDATE users 
                    SET 
                        username = $1,
                        email = $2,
                        first_name = $3,
                        last_name = $4,
                        enabled = $5,
                        attributes = $6,
                        role = $7,
                        team_id = $8,
                        institution_id = $9
                    WHERE id = $10
                    "#,
                    idp_user.username,
                    idp_user.email,
                    idp_user.first_name,
                    idp_user.last_name,
                    idp_user.enabled,
                    attributes,
                    domain_user.role.as_str(),
                    domain_user.team.as_ref().map(|t| t.id),
                    domain_user.institution.as_ref().map(|t| t.id),
                    record.id
                )
                .execute(&mut **tx)
                .await
                .context("Failed to update user")?;
                
                record.id
            },
            None => {
                // Insert new user
                debug!("Creating new user: {}", idp_user.username);
                sqlx::query!(
                    r#"
                    INSERT INTO users 
                    (entity_id, username, email, first_name, last_name, enabled, attributes, role, team_id, institution_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    RETURNING id
                    "#,
                    entity_id,
                    idp_user.username,
                    idp_user.email,
                    idp_user.first_name,
                    idp_user.last_name,
                    idp_user.enabled,
                    attributes,
                    domain_user.role.as_str(),
                    domain_user.team.as_ref().map(|t| t.id),
                    domain_user.institution.as_ref().map(|t| t.id),
                )
                .fetch_one(&mut **tx)
                .await
                .context("Failed to insert user")?
                .id
            }
        };

        // Now retrieve the complete user data with team and institution information
        self.get_complete_user(&mut *tx, user_id).await
    }

    /// Get a complete user with team and institution details
    async fn get_complete_user(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        user_id: Uuid
    ) -> anyhow::Result<CompleteUser> {
        // First get the basic user info
        let user = sqlx::query!(
            r#"
            SELECT 
                u.id,
                u.username,
                u.email,
                u.first_name,
                u.last_name,
                u.enabled,
                u.attributes,
                u.role,
                u.team_id,
                u.institution_id,
                u.created_at,
                u.updated_at
            FROM users u
            WHERE u.id = $1
            "#,
            user_id
        )
        .fetch_one(&mut **tx)
        .await
        .context("Failed to fetch user data")?;

        // Construct the complete user
        let attributes = user.attributes.unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        let role = Role::parse(&user.role);

        Ok(CompleteUser {
            id: user.id,
            username: user.username,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            enabled: user.enabled,
            attributes,
            role,
            team_id: user.team_id,
            institution_id: user.institution_id,
            created_at: user.created_at,
            updated_at: user.updated_at,
        })
    }

    async fn update_user_cache(&self, user: CompleteUser) -> bool {
        let id = user.id;
        let existing = self.users.get(&id).await;
        
        // Convert user to Arc for storage and comparison
        let user_arc = Arc::new(user);
        
        match existing {
            Some(cached) => {
                // We need to compare the contents to see if they're different
                if !are_users_equal(&cached, &user_arc) {
                    // Update cache if different
                    self.users.insert(id, user_arc).await;
                    true
                } else {
                    // No change needed
                    false
                }
            },
            None => {
                // No existing entry, always insert
                self.users.insert(id, user_arc).await;
                true
            }
        }
    }

    /// Get users by role
    pub async fn get_users_by_role(&self, role: &str) -> anyhow::Result<Vec<Arc<CompleteUser>>> {
        let user_ids = sqlx::query!(
            r#"
            SELECT id
            FROM users
            WHERE role = $1
            "#,
            role
        )
        .fetch_all(&self.db)
        .await
        .context("Failed to fetch users by role")?;

        let mut users = Vec::with_capacity(user_ids.len());
        for user_id_row in user_ids {
            match self.get_user(user_id_row.id).await {
                Some(user) => users.push(user),
                None => debug!("Failed to get user {}", user_id_row.id),
            }
        }

        Ok(users)
    }

    /// Get team members
    pub async fn get_team_users(&self, team_id: Uuid) -> anyhow::Result<Vec<Arc<CompleteUser>>> {
        let user_ids = sqlx::query!(
            r#"
            SELECT id
            FROM users
            WHERE team_id = $1
            "#,
            team_id
        )
        .fetch_all(&self.db)
        .await
        .context("Failed to fetch team users")?;

        let mut users = Vec::with_capacity(user_ids.len());
        for user_id_row in user_ids {
            match self.get_user(user_id_row.id).await {
                Some(user) => users.push(user),
                None => debug!("Failed to get user {}", user_id_row.id),
            }
        }

        Ok(users)
    }

    /// Get institution members
    pub async fn get_institution_users(&self, institution_id: Uuid) -> anyhow::Result<Vec<Arc<CompleteUser>>> {
        let user_ids = sqlx::query!(
            r#"
            SELECT id
            FROM users
            WHERE institution_id = $1
            "#,
            institution_id
        )
        .fetch_all(&self.db)
        .await
        .context("Failed to fetch institution users")?;

        let mut users = Vec::with_capacity(user_ids.len());
        for user_id_row in user_ids {
            match self.get_user(user_id_row.id).await {
                Some(user) => users.push(user),
                None => debug!("Failed to get user {}", user_id_row.id),
            }
        }

        Ok(users)
    }

    pub async fn get_user(&self, id: Uuid) -> Option<Arc<CompleteUser>> {
        self.users.get(&id).await
    }

    pub async fn all_users(&self) -> Vec<Arc<CompleteUser>> {
        self.users.iter().map(|(_, v)| v).collect()
    }
}

fn are_users_equal(a: &Arc<CompleteUser>, b: &Arc<CompleteUser>) -> bool {
    a.id == b.id &&
    a.username == b.username &&
    a.email == b.email &&
    a.first_name == b.first_name &&
    a.last_name == b.last_name &&
    a.enabled == b.enabled &&
    a.role == b.role &&
    a.team_id == b.team_id &&
    a.institution_id == b.institution_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AiclIdentifier;
    use sqlx::PgPool;
    
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_sync_users(pool: PgPool) -> anyhow::Result<()> {
        // Get the IdpAdmin from the environment
        let identifier = AiclIdentifier::from_env(pool).await?;
        let sync_service = identifier.db.clone();
        
        // First sync institutions and teams since users may reference them
        sync_service.sync_all_institutions().await?;
        sync_service.sync_all_teams().await?;
        
        // Run the user sync
        let count = sync_service.sync_all_users().await?;
        let users = sync_service.all_users().await;
        // Verify some data was synced
        assert_eq!(count, users.len());
        
        // Check specific users
        let admin = users.iter().find(|u| u.username == "admin");
        assert!(admin.is_some(), "Admin user not found in sync results");
        
        let captain = users.iter().find(|u| u.username == "captain1");
        assert!(captain.is_some(), "Team captain not found in sync results");
        
        if let Some(captain) = captain {
            assert!(captain.team_id.is_some(), "Captain should have team info");
            assert_eq!(captain.role, Role::Captain, "Captain should have Captain role");
        }
        
        let advisor = users.iter().find(|u| u.username == "advisor1");
        assert!(advisor.is_some(), "Advisor not found in sync results");
        
        if let Some(advisor) = advisor {
            assert!(advisor.institution_id.is_some(), "Advisor should have institution info");
            assert_eq!(advisor.role, Role::Advisor, "Advisor should have Advisor role");
        }
        
        // Test get_users_by_role
        let captains = sync_service.get_users_by_role("captain").await?;
        assert!(!captains.is_empty(), "Should have found captains");
        assert!(captains.iter().all(|u| u.role == Role::Captain), "All returned users should be captains");
        
        // Test get_team_users
        if let Some(captain) = captain.and_then(|c| c.team_id.as_ref().map(|t| (c, t))) {
            let team_users = sync_service.get_team_users(*captain.1).await?;
            assert!(!team_users.is_empty(), "Should have found team users");
            assert_eq!(
                team_users.iter().filter(|u| u.username == "captain1").count(), 
                1, 
                "Team users should include captain1"
            );
        }
        
        // Test get_institution_users
        if let Some(advisor) = advisor.and_then(|a| a.institution_id.as_ref().map(|i| (a, i))) {
            let institution_users = sync_service.get_institution_users(*advisor.1).await?;
            assert!(!institution_users.is_empty(), "Should have found institution users");
            assert!(
                institution_users.iter().any(|u| u.username == "advisor1"), 
                "Institution users should include advisor1"
            );
        }
        let count = sync_service.sync_all_users().await?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_user_relationships(pool: PgPool) -> anyhow::Result<()> {
        // Get the IdpAdmin from the environment
        let identifier = AiclIdentifier::from_env(pool).await?;
        let sync_service = identifier.db.clone();
        
        // Sync everything
        sync_service.sync_all_institutions().await?;
        sync_service.sync_all_teams().await?;
        sync_service.sync_all_users().await?;
        
        // Query for Team1 users
        let team1_id = find_team_by_id(&sync_service.db, "Team1").await?;
        let team1_users = sync_service.get_team_users(team1_id).await?;
        
        // Verify Team1 users have the correct roles
        let has_captain = team1_users.iter().any(|u| u.username == "captain1" && u.role == Role::Captain);
        let has_student = team1_users.iter().any(|u| u.username == "member1" && u.role == Role::Student);
        let has_spectator = team1_users.iter().any(|u| u.username == "viewer1" && u.role == Role::Spectator);
        
        assert!(has_captain, "Team1 should have captain1 with Captain role");
        assert!(has_student, "Team1 should have member1 with Student role");
        assert!(has_spectator, "Team1 should have viewer1 with Spectator role");
        
        // Verify all Team1 users have the same institution
        if !team1_users.is_empty() {
            let first_user = &team1_users[0];
            if let Some(inst) = &first_user.institution_id {
                assert!(
                    team1_users.iter().all(|u| {
                        u.institution_id.unwrap() == *inst
                    }),
                    "All Team1 users should have the same institution"
                );
            }
        }
        
        // Query for School1 users
        let school1_id = find_institution_by_id(&sync_service.db, "School1").await?;
        let school1_users = sync_service.get_institution_users(school1_id).await?;
        
        // Verify School1 has an advisor
        let has_advisor = school1_users.iter().any(|u| u.username == "advisor1" && u.role == Role::Advisor);
        assert!(has_advisor, "School1 should have advisor1 with Advisor role");
        
        Ok(())
    }

    // Helper function to find a team ID by name
    async fn find_team_by_id(pool: &PgPool, name: &str) -> anyhow::Result<Uuid> {
        let result = sqlx::query!(
            r#"
            SELECT t.id
            FROM teams t
            JOIN idp_entities e ON t.entity_id = e.id
            WHERE e.name = $1
            "#,
            name
        )
        .fetch_optional(pool)
        .await?;

        match result {
            Some(row) => Ok(row.id),
            None => anyhow::bail!("Team not found: {}", name),
        }
    }

    // Helper function to find an institution ID by name
    async fn find_institution_by_id(pool: &PgPool, name: &str) -> anyhow::Result<Uuid> {
        let result = sqlx::query!(
            r#"
            SELECT i.id
            FROM institutions i
            JOIN idp_entities e ON i.entity_id = e.id
            WHERE e.name = $1
            "#,
            name
        )
        .fetch_optional(pool)
        .await?;

        match result {
            Some(row) => Ok(row.id),
            None => anyhow::bail!("Institution not found: {}", name),
        }
    }
}
use sqlx::{Postgres, Pool, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use crate::idp::admin::IdpAdmin;
use crate::Role;
use std::sync::Arc;
use anyhow::{Result, Context};

/// Database representation of an IdP entity
#[derive(Debug, Serialize, Deserialize)]
pub struct IdpEntity {
    pub id: Uuid,
    pub r#type: String,
    pub name: String,
    pub path: Option<String>,
    pub email: Option<String>,
    pub attributes: serde_json::Value,
    pub parent_id: Option<Uuid>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
    pub last_sync_at: Option<OffsetDateTime>,
}

/// Database representation of a user role
#[derive(Debug, Serialize, Deserialize)]
pub struct UserRole {
    pub id: Uuid,
    pub user_entity_id: Uuid,
    pub team_id: Option<Uuid>,
    pub institution_id: Option<Uuid>,
    pub role: String,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

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
    pub team: Option<CompleteTeam>,
    pub institution: Option<CompleteInstitution>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}





/// Service for synchronizing IdP data with the database
pub struct IdpSyncService {
    db: Pool<Postgres>,
    idp_admin: Arc<IdpAdmin>,
}

impl IdpSyncService {
    /// Create a new IdpSyncService
    pub fn new(db: Pool<Postgres>, idp_admin: Arc<IdpAdmin>) -> Self {
        Self { db, idp_admin }
    }

    /// Synchronize all IdP entities with the database
    pub async fn sync_all(&self) -> Result<()> {
        let mut tx = self.db.begin().await?;
        
        // Sync users
        self.sync_users(&mut tx).await?;
        
        // Sync groups (institutions and teams)
        self.sync_groups(&mut tx).await?;
        
        // Sync relationships (user roles, team-institution relationships)
        self.sync_relationships(&mut tx).await?;
        
        // Commit the transaction
        tx.commit().await?;
        
        Ok(())
    }
    
    /// Synchronize users from Keycloak to the database
    async fn sync_users(&self, tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        // Get all users from Keycloak
        let users = self.idp_admin.get_users().await
            .context("Failed to get users from Keycloak")?;
        
        for user in users {
            // Convert attributes to JSON
            let attributes = serde_json::to_value(&user.attributes)
                .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));
            
            // Check if user already exists in the database
            let existing = sqlx::query!(
                r#"
                SELECT id FROM idp_entities 
                WHERE id = $1 AND type = 'user'
                "#,
                user.id
            )
            .fetch_optional(tx.as_mut())
            .await?;
            
            if let Some(existing) = existing {
                // Update existing user
                sqlx::query!(
                    r#"
                    UPDATE idp_entities 
                    SET name = $1, email = $2, attributes = $3, last_sync_at = NOW()
                    WHERE id = $4
                    "#,
                    user.username,
                    user.email,
                    attributes,
                    existing.id
                )
                .execute(tx.as_mut())
                .await?;
            } else {
                // Insert new user
                sqlx::query!(
                    r#"
                    INSERT INTO idp_entities 
                    (id, type, name, email, attributes, last_sync_at)
                    VALUES ($1, 'user', $2, $3, $4, NOW())
                    "#,
                    user.id,
                    user.username,
                    user.email,
                    attributes
                )
                .execute(tx.as_mut())
                .await?;
            }
        }
        
        Ok(())
    }
    
    /// Synchronize groups from Keycloak to the database
    async fn sync_groups(&self, tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        // Get all groups from Keycloak
        let groups = self.idp_admin.get_groups().await
            .context("Failed to get groups from Keycloak")?;
        
        // First pass: create/update the groups
        for group_header in groups.iter() {
            let group = self.idp_admin.get_group(group_header.id).await
                .context("Failed to get group details")?;
            
            // Convert attributes to JSON
            let attributes = serde_json::to_value(&group.attributes)
                .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));
            
            // Determine the group type based on path 
            // Assume format is "/Teams/{team_name}" or "/Institutions/{institution_name}"
            let group_type = if group.path.starts_with("/Teams/") {
                "team"
            } else if group.path.starts_with("/Institutions/") {
                "institution"
            } else {
                "group" // Generic group
            };
            
            // Check if group already exists in the database
            let existing = sqlx::query!(
                r#"
                SELECT id FROM idp_entities 
                WHERE id = $1 AND type = $2
                "#,
                group.id,
                group_type
            )
            .fetch_optional(tx.as_mut())
            .await?;
            
            if let Some(existing) = existing {
                // Update existing group
                sqlx::query!(
                    r#"
                    UPDATE idp_entities 
                    SET name = $1, path = $2, attributes = $3, last_sync_at = NOW()
                    WHERE id = $4
                    "#,
                    group.name,
                    group.path,
                    attributes,
                    existing.id
                )
                .execute(tx.as_mut())
                .await?;
            } else {
                // Insert new group
                sqlx::query!(
                    r#"
                    INSERT INTO idp_entities 
                    (id, type, name, path, attributes, last_sync_at)
                    VALUES ($1, $2, $3, $4, $5, NOW())
                    "#,
                    group.id,
                    group_type,
                    group.name,
                    group.path,
                    attributes
                )
                .execute(tx.as_mut())
                .await?;
                
                // If it's a team or institution, create the corresponding record
                if group_type == "team" {
                    // Handle team creation
                    let entity_id = sqlx::query!(
                        r#"
                        SELECT id FROM idp_entities 
                        WHERE id = $1 AND type = 'team'
                        "#,
                        group.id
                    )
                    .fetch_one(tx.as_mut())
                    .await?
                    .id;
                    
                    // Create the team record
                    sqlx::query!(
                        r#"
                        INSERT INTO teams (entity_id)
                        VALUES ($1)
                        "#,
                        entity_id
                    )
                    .execute(tx.as_mut())
                    .await?;
                    
                } else if group_type == "institution" {
                    // Handle institution creation
                    let entity_id = sqlx::query!(
                        r#"
                        SELECT id FROM idp_entities 
                        WHERE id = $1 AND type = 'institution'
                        "#,
                        group.id
                    )
                    .fetch_one(tx.as_mut())
                    .await?
                    .id;
                    
                    // Create the institution record
                    sqlx::query!(
                        r#"
                        INSERT INTO institutions (entity_id)
                        VALUES ($1)
                        "#,
                        entity_id
                    )
                    .execute(tx.as_mut())
                    .await?;
                }
            }
        }
        
        // Second pass: update parent_id relationships
        for group_header in groups.iter() {
            let group = self.idp_admin.get_group(group_header.id).await
                .context("Failed to get group details")?;
            
            if let Some(parent_id) = group.parent_id {
                // Get the database IDs for both entities
                let group_type = if group.path.starts_with("/Teams/") {
                    "team"
                } else if group.path.starts_with("/Institutions/") {
                    "institution"
                } else {
                    "group"
                };
                
                let parent_entity = sqlx::query!(
                    r#"
                    SELECT id FROM idp_entities 
                    WHERE id = $1
                    "#,
                    parent_id
                )
                .fetch_optional(tx.as_mut())
                .await?;
                
                if let Some(parent_entity) = parent_entity {
                    sqlx::query!(
                        r#"
                        UPDATE idp_entities 
                        SET parent_id = $1
                        WHERE id = $2 AND type = $3
                        "#,
                        parent_entity.id,
                        group.id,
                        group_type
                    )
                    .execute(tx.as_mut())
                    .await?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Synchronize relationships (user roles, team-institution relationships)
    async fn sync_relationships(&self, tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        // Get all users for processing
        let users = self.idp_admin.get_users().await
            .context("Failed to get users from Keycloak")?;
            
        // Process each user's roles and group memberships
        for user in users {
            // Get user's roles
            let user_roles = self.idp_admin.get_user_roles(user.id).await
                .context("Failed to get user roles")?;
                
            // Determine the user's primary role
            let primary_role = if user_roles.iter().any(|r| r.name == "admin") {
                Role::Admin
            } else if user_roles.iter().any(|r| r.name == "advisor") {
                Role::Advisor
            } else if user_roles.iter().any(|r| r.name == "captain") {
                Role::Captain
            } else if user_roles.iter().any(|r| r.name == "student") {
                Role::Student
            } else {
                Role::Spectator
            };
                
            // Convert to domain user to get team/institution info
            let domain_user = self.idp_admin.to_domain_user(&user).await
                .context("Failed to convert to domain user")?;
                
            // Delete existing roles for this user
            sqlx::query!(
                r#"
                DELETE FROM user_roles
                WHERE user_entity_id = $1
                "#,
                user.id
            )
            .execute(tx.as_mut())
            .await?;
            
            // Insert the appropriate role record based on user type
            match primary_role {
                Role::Admin => {
                    // Global admin role (no team or institution)
                    sqlx::query!(
                        r#"
                        INSERT INTO user_roles (user_entity_id, role)
                        VALUES ($1, $2)
                        "#,
                        user.id,
                        primary_role.as_str()
                    )
                    .execute(tx.as_mut())
                    .await?;
                },
                Role::Advisor => {
                    // Advisor is associated with an institution
                    if let Some(institution) = &domain_user.institution {
                        // Find the institution record
                        let institution_record = sqlx::query!(
                            r#"
                            SELECT id FROM institutions
                            WHERE entity_id = $1
                            "#,
                            institution.id
                        )
                        .fetch_optional(tx.as_mut())
                        .await?;
                        
                        if let Some(institution_record) = institution_record {
                            sqlx::query!(
                                r#"
                                INSERT INTO user_roles (user_entity_id, institution_id, role)
                                VALUES ($1, $2, $3)
                                "#,
                                user.id,
                                institution_record.id,
                                primary_role.as_str()
                            )
                            .execute(tx.as_mut())
                            .await?;
                        }
                    }
                },
                // For team members (captain, student, spectator)
                Role::Captain | Role::Student | Role::Spectator => {
                    if let Some(team) = &domain_user.team {
                        // Find the team record
                        let team_record = sqlx::query!(
                            r#"
                            SELECT id FROM teams
                            WHERE entity_id = $1
                            "#,
                            team.id
                        )
                        .fetch_optional(tx.as_mut())
                        .await?;
                        
                        if let Some(team_record) = team_record {
                            sqlx::query!(
                                r#"
                                INSERT INTO user_roles (user_entity_id, team_id, role)
                                VALUES ($1, $2, $3)
                                "#,
                                user.id,
                                team_record.id,
                                primary_role.as_str()
                            )
                            .execute(tx.as_mut())
                            .await?;
                        }
                    }
                }
            }
            
            // Update team-institution relationships
            if let (Some(team), Some(institution)) = (&domain_user.team, &domain_user.institution) {
                // Find the team and institution records
                let team_record = sqlx::query!(
                    r#"
                    SELECT id FROM teams
                    WHERE entity_id = $1
                    "#,
                    team.id
                )
                .fetch_optional(tx.as_mut())
                .await?;
                
                let institution_record = sqlx::query!(
                    r#"
                    SELECT id FROM institutions
                    WHERE entity_id = $1
                    "#,
                    institution.id
                )
                .fetch_optional(tx.as_mut())
                .await?;
                
                // Link team to institution if both exist
                if let (Some(team_record), Some(institution_record)) = (team_record, institution_record) {
                    sqlx::query!(
                        r#"
                        UPDATE teams
                        SET institution_id = $1
                        WHERE id = $2
                        "#,
                        institution_record.id,
                        team_record.id
                    )
                    .execute(tx.as_mut())
                    .await?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Get users with a specific role
    pub async fn get_users_by_role(&self, role: &str) -> Result<Vec<IdpEntity>> {
        let users = sqlx::query_as!(
            IdpEntity,
            r#"
            SELECT e.* 
            FROM idp_entities e
            JOIN user_roles r ON e.id = r.user_entity_id
            WHERE r.role = $1
            "#,
            role
        )
        .fetch_all(&self.db)
        .await?;
        
        Ok(users)
    }
    
    /// Get team members
    pub async fn get_team_members(&self, team_id: Uuid) -> Result<Vec<(IdpEntity, String)>> {
        let members = sqlx::query!(
            r#"
            SELECT e.*, r.role
            FROM idp_entities e
            JOIN user_roles r ON e.id = r.user_entity_id
            WHERE r.team_id = $1
            "#,
            team_id
        )
        .fetch_all(&self.db)
        .await?;
        
        let result = members.into_iter().map(|row| {
            let entity = IdpEntity {
                id: row.id,
                r#type: row.r#type,
                name: row.name,
                path: row.path,
                email: row.email,
                attributes: row.attributes.unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())),
                parent_id: row.parent_id,
                created_at: row.created_at,
                updated_at: row.updated_at,
                last_sync_at: row.last_sync_at,
            };
            
            (entity, row.role)
        }).collect();
        
        Ok(result)
    }
    
    /// Get institution members
    pub async fn get_institution_members(&self, institution_id: Uuid) -> Result<Vec<(IdpEntity, String)>> {
        let members = sqlx::query!(
            r#"
            SELECT e.*, r.role
            FROM idp_entities e
            JOIN user_roles r ON e.id = r.user_entity_id
            WHERE r.institution_id = $1
            "#,
            institution_id
        )
        .fetch_all(&self.db)
        .await?;
        
        let result = members.into_iter().map(|row| {
            let entity = IdpEntity {
                id: row.id,
                r#type: row.r#type,
                name: row.name,
                path: row.path,
                email: row.email,
                attributes: row.attributes.unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())),
                parent_id: row.parent_id,
                created_at: row.created_at,
                updated_at: row.updated_at,
                last_sync_at: row.last_sync_at,
            };
            
            (entity, row.role)
        }).collect();
        
        Ok(result)
    }
    
    /// Get all teams with their institution data
    pub async fn get_teams_with_institutions(&self) -> Result<Vec<(Team, Option<Institution>)>> {
        let teams = sqlx::query!(
            r#"
            SELECT 
                t.*,
                i.entity_id as institution_entity_id,
                i.domain as institution_domain,
                i.description as institution_description,
                i.website_url as institution_website_url,
                i.logo_url as institution_logo_url,
                i.created_at as institution_created_at,
                i.updated_at as institution_updated_at
            FROM 
                teams t
            LEFT JOIN institutions i ON t.institution_id = i.id
            "#
        )
        .fetch_all(&self.db)
        .await?;
        
        let result = teams.into_iter().map(|row| {
            let team = Team {
                id: row.id,
                entity_id: row.entity_id,
                institution_id: row.institution_id,
                competition_year: row.competition_year,
                description: row.description,
                logo_url: row.logo_url,
                created_at: row.created_at,
                updated_at: row.updated_at,
            };
            
            let institution = if row.institution_id.is_some() {
                Some(Institution {
                    id: row.institution_id.unwrap(),
                    entity_id: row.institution_entity_id.unwrap(),
                    domain: row.institution_domain,
                    description: row.institution_description,
                    website_url: row.institution_website_url,
                    logo_url: row.institution_logo_url,
                    created_at: row.institution_created_at,
                    updated_at: row.institution_updated_at,
                })
            } else {
                None
            };
            
            (team, institution)
        }).collect();
        
        Ok(result)
    }
    
    /// Get the database ID for a Keycloak entity
    pub async fn get_db_id_for_id(&self, id: Uuid, entity_type: &str) -> Result<Option<Uuid>> {
        let result = sqlx::query!(
            r#"
            SELECT id FROM idp_entities 
            WHERE id = $1 AND type = $2
            "#,
            id,
            entity_type
        )
        .fetch_optional(&self.db)
        .await?;
        
        Ok(result.map(|row| row.id))
    }
}

/// Helper function to convert an AiclIdentity to a database entity ID
pub async fn get_entity_id_for_aicl_identity(
    pool: &Pool<Postgres>, 
    identity: &crate::AiclIdentity
) -> Result<Uuid> {
    let result = sqlx::query!(
        r#"
        SELECT id FROM idp_entities 
        WHERE id = $1 AND type = 'user'
        "#,
        identity.id
    )
    .fetch_optional(pool)
    .await?;
    
    result.map(|row| row.id)
        .context("User not found in database")
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;

    use super::*;
    use crate::{AiclIdentifier, Role};

    
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_sync_all(pool: PgPool) -> Result<()> {            
        // Get the IdpAdmin from the environment
        let identifier = AiclIdentifier::from_env().await?;
        
        // Create the sync service
        let sync_service = IdpSyncService::new(pool, identifier.idp.clone());
        
        // Run the sync
        sync_service.sync_all().await?;
        
        // Verify some data was synced
        let count = sqlx::query!("SELECT COUNT(*) as count FROM idp_entities")
            .fetch_one(&sync_service.db)
            .await?
            .count
            .unwrap_or(0);
            
        assert!(count > 0, "No entities were synced");
        
        Ok(())
    }
    
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_get_team_members(pool: PgPool) -> Result<()> {
        // Get the IdpAdmin from the environment
        let identifier = AiclIdentifier::from_env().await?;
        let sync_service = IdpSyncService::new(pool.clone(), identifier.idp.clone());
        sync_service.sync_all().await?;
        
        // Get a team ID from the database
        let team = sqlx::query!("SELECT id FROM teams LIMIT 1")
            .fetch_optional(&pool)
            .await?;
            
        if let Some(team) = team {
            // Get the team members
            let members = sync_service.get_team_members(team.id).await?;
            
            // Simply verify we can fetch team members
            println!("Found {} team members", members.len());
        } else {
            println!("No teams found to test");
        }
        
        Ok(())
    }

    // Helper to find a team entity by name
    async fn find_team_by_name(pool: &PgPool, name: &str) -> Result<Uuid> {
        let result = sqlx::query!(
            r#"
            SELECT t.id
            FROM teams t
            JOIN idp_entities e ON t.entity_id = e.id
            WHERE e.name = $1 AND e.type = 'team'
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

    // Helper to find an institution entity by name
    async fn find_institution_by_name(pool: &PgPool, name: &str) -> Result<Uuid> {
        let result = sqlx::query!(
            r#"
            SELECT i.id
            FROM institutions i
            JOIN idp_entities e ON i.entity_id = e.id
            WHERE e.name = $1 AND e.type = 'institution'
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

    // Helper to find a user entity by username
    async fn find_user_by_username(pool: &PgPool, username: &str) -> Result<Uuid> {
        let result = sqlx::query!(
            r#"
            SELECT id 
            FROM idp_entities 
            WHERE name = $1 AND type = 'user'
            "#,
            username
        )
        .fetch_optional(pool)
        .await?;

        match result {
            Some(row) => Ok(row.id),
            None => anyhow::bail!("User not found: {}", username),
        }
    }

    // Helper to get user role for a specific user
    async fn get_user_role(pool: &PgPool, user_entity_id: Uuid) -> Result<String> {
        let result = sqlx::query!(
            r#"
            SELECT role 
            FROM user_roles 
            WHERE user_entity_id = $1
            "#,
            user_entity_id
        )
        .fetch_optional(pool)
        .await?;

        match result {
            Some(row) => Ok(row.role),
            None => anyhow::bail!("No role found for user"),
        }
    }

    // Test Team1 exists and has the expected structure
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_team1_exists(pool: PgPool) -> Result<()> {
        // Initialize the sync service and sync the data
        let identifier = AiclIdentifier::from_env().await?;
        let sync_service = IdpSyncService::new(pool.clone(), identifier.idp.clone());
        sync_service.sync_all().await?;

        // Get Team1 ID
        let team1_id = find_team_by_name(&pool, "Team1").await?;
        
        // Check team members
        let members = sync_service.get_team_members(team1_id).await?;
        
        // Verify we have at least the captain, a student, and a spectator
        assert!(members.len() >= 3, "Team1 should have at least 3 members");
        
        // Verify captain1 exists and has the captain role
        let captain_found = members.iter().any(|(entity, role)| 
            entity.name == "captain1" && role == "captain"
        );
        assert!(captain_found, "Captain1 should be in Team1 with role 'captain'");
        
        // Verify member1 exists with the student role
        let student_found = members.iter().any(|(entity, role)| 
            entity.name == "member1" && role == "student"
        );
        assert!(student_found, "Member1 should be in Team1 with role 'student'");
        
        // Verify viewer1 exists with the spectator role
        let spectator_found = members.iter().any(|(entity, role)| 
            entity.name == "viewer1" && role == "spectator"
        );
        assert!(spectator_found, "Viewer1 should be in Team1 with role 'spectator'");

        Ok(())
    }

    // Test Team1 is properly linked to School1
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_team1_linked_to_school1(pool: PgPool) -> Result<()> {
        // Initialize the sync service and sync the data
        let identifier = AiclIdentifier::from_env().await?;
        let sync_service = IdpSyncService::new(pool.clone(), identifier.idp.clone());
        sync_service.sync_all().await?;

        // Get Teams with institutions
        let teams_with_institutions = sync_service.get_teams_with_institutions().await?;
        let team_1_id = find_team_by_name(&pool, "Team1").await?;
        // Find Team1
        let team1 = teams_with_institutions.iter()
            .find(|(team, _)| {
                team.id == team_1_id
            });
        
        assert!(team1.is_some(), "Team1 should exist");
        
        let (_, institution) = team1.unwrap();
        assert!(institution.is_some(), "Team1 should be linked to an institution");
        
        let institution = institution.as_ref().unwrap();
        let institution_name = sqlx::query!(
            "SELECT name FROM idp_entities WHERE id = $1",
            institution.entity_id
        )
        .fetch_one(&pool)
        .await?
        .name;
        
        assert_eq!(institution_name, "School1", "Team1 should be linked to School1");

        Ok(())
    }

    // Test advisor1 is properly linked to School1
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_advisor1_linked_to_school1(pool: PgPool) -> Result<()> {
        // Initialize the sync service and sync the data
        let identifier = AiclIdentifier::from_env().await?;
        let sync_service = IdpSyncService::new(pool.clone(), identifier.idp.clone());
        sync_service.sync_all().await?;

        // Find advisor1 and School1
        let advisor1_id = find_user_by_username(&pool, "advisor1").await?;
        let school1_id = find_institution_by_name(&pool, "School1").await?;
        
        // Check if advisor1 is linked to School1
        let result = sqlx::query!(
            r#"
            SELECT *
            FROM user_roles 
            WHERE user_entity_id = $1 AND institution_id = $2 AND role = 'advisor'
            "#,
            advisor1_id,
            school1_id
        )
        .fetch_optional(&pool)
        .await?;
        
        assert!(result.is_some(), "Advisor1 should be linked to School1 with role 'advisor'");

        Ok(())
    }

    // Test admin users have the correct role
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_admin_users(pool: PgPool) -> Result<()> {
        // Initialize the sync service and sync the data
        let identifier = AiclIdentifier::from_env().await?;
        let sync_service = IdpSyncService::new(pool.clone(), identifier.idp.clone());
        sync_service.sync_all().await?;

        // Find admin users
        let admin_users = sync_service.get_users_by_role("admin").await?;
        
        // Verify we have admin users
        assert!(!admin_users.is_empty(), "Should have at least one admin user");
        
        // Verify admin and admin2 are in the list
        let admin_found = admin_users.iter().any(|u| u.name == "admin");
        let admin2_found = admin_users.iter().any(|u| u.name == "admin2");
        
        assert!(admin_found, "User 'admin' should be found with admin role");
        assert!(admin2_found, "User 'admin2' should be found with admin role");

        Ok(())
    }

    // Test all three teams exist and have correct structures
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_all_teams_exist(pool: PgPool) -> Result<()> {
        // Initialize the sync service and sync the data
        let identifier = AiclIdentifier::from_env().await?;
        let sync_service = IdpSyncService::new(pool.clone(), identifier.idp.clone());
        sync_service.sync_all().await?;

        // Check if all three teams exist
        let team_names = ["Team1", "Team2", "Team3"];
        
        for team_name in team_names {
            // Get the team ID
            let team_id = find_team_by_name(&pool, team_name).await?;
            
            // Get the team members
            let members = sync_service.get_team_members(team_id).await?;
            
            // Each team should have at least one captain and one member
            let has_captain = members.iter().any(|(_, role)| role == "captain");
            let has_member = members.iter().any(|(_, role)| role == "student" || role == "spectator");
            
            assert!(has_captain, "{} should have a captain", team_name);
            assert!(has_member, "{} should have a student or spectator", team_name);
            
            println!("{} has {} members", team_name, members.len());
        }

        Ok(())
    }

    // Test Team3 is linked to School2
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_team3_linked_to_school2(pool: PgPool) -> Result<()> {
        // Initialize the sync service and sync the data
        let identifier = AiclIdentifier::from_env().await?;
        let sync_service = IdpSyncService::new(pool.clone(), identifier.idp.clone());
        sync_service.sync_all().await?;

        // Get Teams with institutions
        let teams_with_institutions = sync_service.get_teams_with_institutions().await?;
        let team_3_id = find_team_by_name(&pool, "Team3").await?;
        
        // Find Team3
        let team3 = teams_with_institutions.iter()
            .find(|(team, _)| {
                team.id == team_3_id
            });
        
        assert!(team3.is_some(), "Team3 should exist");
        
        let (_, institution) = team3.unwrap();
        assert!(institution.is_some(), "Team3 should be linked to an institution");
        
        let institution = institution.as_ref().unwrap();
        let institution_name = sqlx::query!(
            "SELECT name FROM idp_entities WHERE id = $1",
            institution.entity_id
        )
        .fetch_one(&pool)
        .await?
        .name;
        
        assert_eq!(institution_name, "School2", "Team3 should be linked to School2");

        Ok(())
    }

    // Test roles enum mapping
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_role_mapping(pool: PgPool) -> Result<()> {
        // Initialize the sync service and sync the data
        let identifier = AiclIdentifier::from_env().await?;
        let sync_service = IdpSyncService::new(pool.clone(), identifier.idp.clone());
        sync_service.sync_all().await?;

        // Test some key users
        let users = [
            ("admin", Role::Admin),
            ("captain1", Role::Captain),
            ("member1", Role::Student),
            ("viewer1", Role::Spectator),
            ("advisor1", Role::Advisor)
        ];
        
        for (username, expected_role) in users {
            let user_id = find_user_by_username(&pool, username).await?;
            let db_role = get_user_role(&pool, user_id).await?;
            
            assert_eq!(
                db_role, 
                expected_role.as_str(), 
                "User {} should have role {}", 
                username, 
                expected_role.as_str()
            );
        }

        Ok(())
    }

    // Test institution view
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_institution_members_view(pool: PgPool) -> Result<()> {
        // Initialize the sync service and sync the data
        let identifier = AiclIdentifier::from_env().await?;
        let sync_service = IdpSyncService::new(pool.clone(), identifier.idp.clone());
        sync_service.sync_all().await?;

        // Query institution_members_view for School1
        let results = sqlx::query!(
            r#"
            SELECT username, role 
            FROM institution_members_view
            WHERE institution_name = 'School1'
            "#
        )
        .fetch_all(&pool)
        .await?;
        
        // Verify we have advisor1 and spec_school1
        let has_advisor = results.iter().any(|row| 
            row.username.as_ref().map(|s| s == "advisor1").unwrap_or_default() && row.role.as_ref().map(|s| s == "advisor").unwrap_or_default()
        );
        
        let has_spectator = results.iter().any(|row| 
            row.username.as_ref().map(|s| s == "spec_school1").unwrap_or_default() && row.role.as_ref().map(|s| s == "spectator").unwrap_or_default()
        );
        
        assert!(has_advisor, "School1 should have advisor1 as an advisor");
        assert!(has_spectator, "School1 should have spec_school1 as a spectator");

        Ok(())
    }

    // Test team members view
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_team_members_view(pool: PgPool) -> Result<()> {
        // Initialize the sync service and sync the data
        let identifier = AiclIdentifier::from_env().await?;
        let sync_service = IdpSyncService::new(pool.clone(), identifier.idp.clone());
        sync_service.sync_all().await?;

        // Query team_members_view for Team1
        let results = sqlx::query!(
            r#"
            SELECT username, role, institution_name
            FROM team_members_view
            WHERE team_name = 'Team1'
            "#
        )
        .fetch_all(&pool)
        .await?;
        
        // Verify institution is correct
        for row in &results {
            assert_eq!(row.institution_name.as_deref(), Some("School1"), 
                "Team1 members should be linked to School1");
        }
        
        // Verify we have captain1, member1 and viewer1
        let has_captain = results.iter().any(|row| 
            row.username.as_ref().map(|s| s == "captain1").unwrap_or_default() && row.role.as_ref().map(|s| s == "captain").unwrap_or_default()
        );
        
        let has_member = results.iter().any(|row| 
            row.username.as_ref().map(|s| s == "member1").unwrap_or_default() && row.role.as_ref().map(|s| s == "student").unwrap_or_default()
        );
        
        let has_viewer = results.iter().any(|row| 
            row.username.as_ref().map(|s| s == "viewer1").unwrap_or_default() && row.role.as_ref().map(|s| s == "spectator").unwrap_or_default()
        );
        
        assert!(has_captain, "Team1 should have captain1 as a captain");
        assert!(has_member, "Team1 should have member1 as a student");
        assert!(has_viewer, "Team1 should have viewer1 as a spectator");

        Ok(())
    }

    // Test teams_with_institutions_view
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_teams_with_institutions_view(pool: PgPool) -> Result<()> {
        // Initialize the sync service and sync the data
        let identifier = AiclIdentifier::from_env().await?;
        let sync_service = IdpSyncService::new(pool.clone(), identifier.idp.clone());
        sync_service.sync_all().await?;

        // Query the view
        let results = sqlx::query!(
            r#"
            SELECT 
                team_name, 
                institution_name, 
                member_count,
                captain_count,
                student_count
            FROM teams_with_institutions_view
            "#
        )
        .fetch_all(&pool)
        .await?;
        
        // Check Team1-School1 relationship
        let team1 = results.iter().find(|row| row.team_name.as_ref().map(|s| s == "Team1").unwrap_or_default());
        assert!(team1.is_some(), "Team1 should exist in the view");
        
        let team1 = team1.unwrap();
        assert_eq!(team1.institution_name.as_deref(), Some("School1"), 
            "Team1 should be linked to School1");
        assert!(team1.member_count.unwrap_or(0) >= 3, 
            "Team1 should have at least 3 members");
        assert_eq!(team1.captain_count.unwrap_or(0), 1, 
            "Team1 should have 1 captain");
        assert_eq!(team1.student_count.unwrap_or(0), 1, 
            "Team1 should have 1 student");
            
        // Check Team3-School2 relationship
        let team3 = results.iter().find(|row| row.team_name.as_ref().map(|s| s == "Team3").unwrap_or_default());
        assert!(team3.is_some(), "Team3 should exist in the view");
        
        let team3 = team3.unwrap();
        assert_eq!(team3.institution_name.as_deref(), Some("School2"), 
            "Team3 should be linked to School2");

        Ok(())
    }
}
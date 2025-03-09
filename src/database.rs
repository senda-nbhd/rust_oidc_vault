use sqlx::{Postgres, Pool, Transaction};
use time::UtcDateTime;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use crate::idp::admin::IdpAdmin;
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
    pub created_at: UtcDateTime,
    pub updated_at: UtcDateTime,
    pub last_sync_at: UtcDateTime,
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
                    
                    // Extract parent institution ID if applicable
                    let institution_entity_id = if let Some(parent_id) = group.parent_id {
                        sqlx::query!(
                            r#"
                            SELECT i.id 
                            FROM institutions i
                            JOIN idp_entities e ON i.entity_id = e.id
                            WHERE e.id = $1
                            "#,
                            parent_id
                        )
                        .fetch_optional(tx.as_mut())
                        .await?
                        .map(|row| row.id)
                    } else {
                        None
                    };
                    
                    // Create the team record
                    sqlx::query!(
                        r#"
                        INSERT INTO teams (entity_id, institution_id)
                        VALUES ($1, $2)
                        "#,
                        entity_id,
                        institution_entity_id
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
    use crate::AiclIdentifier;
    
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
}
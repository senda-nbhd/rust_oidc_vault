use anyhow::Context;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use crate::idp::ext::IdpGroup;

use super::IdpSyncService;

/// Complete institution entity with all related information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteInstitution {
    pub id: Uuid,
    pub name: String,
    pub domain: Option<String>,
    pub description: Option<String>,
    pub website_url: Option<String>,
    pub logo_url: Option<String>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

impl IdpSyncService {
    /// Synchronize all institutions from Keycloak
    #[instrument(skip(self), level = "info")]
    pub async fn sync_all_institutions(&self) -> anyhow::Result<Vec<CompleteInstitution>> {
        info!("Starting synchronization of all institutions from Keycloak");
        
        // Start a transaction
        let mut tx = self.db.begin().await.context("Failed to begin transaction")?;
        
        // Get all institutions from Keycloak
        // First, get the parent "Institutions" group
        let idp_institutions = self.idp_admin.get_institutions().await
            .context("Failed to get groups from Keycloak")?;

        info!(count = idp_institutions.len(), "Found institutions in Keycloak");
        
        // Process each institution
        let mut institutions = Vec::with_capacity(idp_institutions.len());
        for idp_institution in &idp_institutions {
            let idp_group = self.idp_admin.get_group(idp_institution.id).await
                .context("Failed to get group by ID from Keycloak")?;
            if let Ok(institution) = self.sync_institution(&mut tx, &idp_group).await {
                institutions.push(institution);
            }
        }
        
        // Commit the transaction
        tx.commit().await.context("Failed to commit transaction")?;
        
        info!(synced = institutions.len(), "Successfully synchronized institutions");
        
        Ok(institutions)
    }

    #[instrument(skip(self, tx, idp_institution), fields(institution_id = %idp_institution.id, name = %idp_institution.name), level = "debug")]
    async fn sync_institution(
        &self, 
        tx: &mut Transaction<'_, Postgres>, 
        idp_institution: &IdpGroup
    ) -> anyhow::Result<CompleteInstitution> {
        debug!("Synchronizing institution: {}", idp_institution.name);

        // Convert attributes to JSON if any
        let attributes = serde_json::to_value(&idp_institution.attributes)
            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));
        
        // Check if institution already exists in idp_entities
        let entity_exists = sqlx::query!(
            r#"
            SELECT id FROM idp_entities 
            WHERE id = $1 AND type = 'institution'
            "#,
            idp_institution.id
        )
        .fetch_optional(&mut **tx)
        .await
        .context("Failed to query if institution entity exists")?;

        // Institution entity record
        let entity_id = match entity_exists {
            Some(record) => {
                // Update existing entity
                debug!("Updating existing institution entity: {}", idp_institution.name);
                sqlx::query!(
                    r#"
                    UPDATE idp_entities 
                    SET 
                        name = $1, 
                        path = $2, 
                        attributes = $3, 
                        updated_at = CURRENT_TIMESTAMP,
                        last_sync_at = CURRENT_TIMESTAMP
                    WHERE id = $4
                    "#,
                    idp_institution.name,
                    idp_institution.path,
                    attributes,
                    idp_institution.id
                )
                .execute(&mut **tx)
                .await
                .context("Failed to update institution entity")?;
                
                record.id
            },
            None => {
                // Insert new entity
                debug!("Creating new institution entity: {}", idp_institution.name);
                sqlx::query!(
                    r#"
                    INSERT INTO idp_entities 
                    (id, type, name, path, attributes, last_sync_at)
                    VALUES ($1, 'institution', $2, $3, $4, CURRENT_TIMESTAMP)
                    RETURNING id
                    "#,
                    idp_institution.id,
                    idp_institution.name,
                    idp_institution.path,
                    attributes
                )
                .fetch_one(&mut **tx)
                .await
                .context("Failed to insert institution entity")?
                .id
            }
        };

        // Check if institution entry already exists
        let institution_exists = sqlx::query!(
            r#"
            SELECT i.id, i.domain, i.created_at, i.updated_at
            FROM institutions i
            WHERE i.entity_id = $1
            "#,
            entity_id
        )
        .fetch_optional(&mut **tx)
        .await
        .context("Failed to query if institution exists")?;

        // Institution record
        let institution_id = match institution_exists {
            Some(record) => {
                // Institution exists, but we don't update user-provided fields
                debug!("Institution entry already exists: {}", idp_institution.name);
                record.id
            },
            None => {
                // Create new institution entry
                debug!("Creating new institution entry: {}", idp_institution.name);
                
                sqlx::query!(
                    r#"
                    INSERT INTO institutions (entity_id)
                    VALUES ($1)
                    RETURNING id
                    "#,
                    entity_id
                )
                .fetch_one(&mut **tx)
                .await
                .context("Failed to insert institution")?
                .id
            }
        };

        // Now retrieve the complete institution data
        let institution = sqlx::query!(
            r#"
            SELECT 
                i.id,
                e.name,
                i.domain,
                e.attributes->'description' as description,
                i.website_url,
                i.logo_url,
                i.created_at,
                i.updated_at
            FROM 
                institutions i
            JOIN
                idp_entities e ON i.entity_id = e.id
            WHERE 
                i.id = $1
            "#,
            institution_id
        )
        .fetch_one(&mut **tx)
        .await
        .context("Failed to fetch complete institution data")?;

        // Convert to the CompleteInstitution struct
        let description = institution
            .description
            .and_then(|v| v.as_str().map(|s| s.to_string()));

        Ok(CompleteInstitution {
            id: institution.id,
            name: institution.name,
            domain: institution.domain,
            description,
            website_url: institution.website_url,
            logo_url: institution.logo_url,
            created_at: institution.created_at,
            updated_at: institution.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AiclIdentifier;
    use sqlx::PgPool;
    
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_sync_institutions(pool: PgPool) -> anyhow::Result<()> {
        // Get the IdpAdmin from the environment
        let identifier = AiclIdentifier::from_env().await?;
        
        // Create the sync service
        let sync_service = IdpSyncService::new(pool, identifier.idp.clone());
        
        // Run the team sync
        let institutions = sync_service.sync_all_institutions().await?;
        
        // Verify some data was synced
        assert!(!institutions.is_empty(), "No institutions were synced");
        
        // Check specific institutions
        let school1 = institutions.iter().find(|t| t.name == "School1");
        assert!(school1.is_some(), "School1 not found in sync results");
        
        Ok(())
    }
}
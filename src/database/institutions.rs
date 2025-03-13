use std::sync::Arc;

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
    pub async fn sync_all_institutions(&self) -> anyhow::Result<usize> {
        info!("Starting synchronization of all institutions from Keycloak");
        
        // Start a transaction
        let mut tx = self.db.begin().await.context("Failed to begin transaction")?;
        
        // Get all institutions from Keycloak
        // First, get the parent "Institutions" group
        let idp_institutions = self.idp_admin.get_institutions().await
            .context("Failed to get groups from Keycloak")?;

        info!(count = idp_institutions.len(), "Found institutions in Keycloak");
        let mut count = 0;
        
        // Process each institution
        for idp_institution in &idp_institutions {
            let idp_group = self.idp_admin.get_group(idp_institution.id).await
                .context("Failed to get group by ID from Keycloak")?;
            if let Ok(institution) = self.sync_institution(&mut tx, &idp_group).await {
                if self.update_institution_cache(institution).await {
                    count += 1;
                }
            }
        }
        
        // Commit the transaction
        tx.commit().await.context("Failed to commit transaction")?;
        
        info!("Successfully synchronized institutions");
        
        Ok(count)
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
        match institution_exists {
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
                    INSERT INTO institutions (id, entity_id)
                    VALUES ($1, $2)
                    RETURNING id
                    "#,
                    idp_institution.id,
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
            idp_institution.id
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

    /// Update cache selectively by comparing the new entity with the cached version
    /// Returns true if the cache was updated, false if it was the same
    async fn update_institution_cache(&self, institution: CompleteInstitution) -> bool {
        let id = institution.id;
        let existing = self.institutions.get(&id).await;
        
        // Convert institution to Arc for storage and comparison
        let institution_arc = Arc::new(institution);
        
        match existing {
            Some(cached) => {
                // We need to compare the contents to see if they're different
                if !are_institutions_equal(&cached, &institution_arc) {
                    // Update cache if different
                    self.institutions.insert(id, institution_arc).await;
                    true
                } else {
                    // No change needed
                    false
                }
            },
            None => {
                // No existing entry, always insert
                self.institutions.insert(id, institution_arc).await;
                true
            }
        }
    }

    pub async fn get_institution(&self, id: Uuid) -> Option<Arc<CompleteInstitution>> {
        self.institutions.get(&id).await
    }

    pub async fn all_institutions(&self) -> Vec<Arc<CompleteInstitution>> {
        self.institutions.iter().map(|(_, v)| v).collect()
    }
}

fn are_institutions_equal(a: &Arc<CompleteInstitution>, b: &Arc<CompleteInstitution>) -> bool {
    a.id == b.id &&
    a.name == b.name &&
    a.domain == b.domain &&
    a.description == b.description &&
    a.website_url == b.website_url &&
    a.logo_url == b.logo_url
}

#[cfg(test)]
mod tests {
    use crate::AiclIdentifier;
    use sqlx::PgPool;
    
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_sync_institutions(pool: PgPool) -> anyhow::Result<()> {
        // Get the IdpAdmin from the environment
        let identifier = AiclIdentifier::from_env(pool).await?;
        let sync_service = identifier.db.clone();
        
        // Run the team sync
        let count = sync_service.sync_all_institutions().await?;
        let institutions = sync_service.all_institutions().await;
        assert_eq!(count, institutions.len());

        // Verify some data was synced
        assert!(!institutions.is_empty(), "No institutions were synced");
        
        // Check specific institutions
        let school1 = institutions.iter().find(|t| t.name == "School1");
        assert!(school1.is_some(), "School1 not found in sync results");

        let count = sync_service.sync_all_institutions().await?;
        assert_eq!(count, 0);
        
        Ok(())
    }
}
use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use crate::idp::ext::IdpGroup;

use super::IdpSyncService;

/// Complete team entity with all related information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteTeam {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub competition_year: Option<i32>,
    pub logo_url: Option<String>,
    pub institution_id: Option<Uuid>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}


impl IdpSyncService {
    /// Synchronize all teams from Keycloak
    #[instrument(skip(self), level = "info")]
    pub async fn sync_all_teams(&self) -> anyhow::Result<usize> {
        info!("Starting synchronization of all teams from Keycloak");
        
        // Start a transaction
        let mut tx = self.db.begin().await.context("Failed to begin transaction")?;
        
        // Get all teams from Keycloak
        // First, get the parent "Teams" group
        let idp_teams = self.idp_admin.get_teams().await
            .context("Failed to get groups from Keycloak")?;
        
        info!(count = idp_teams.len(), "Found teams in Keycloak");
        let mut count = 0;
        // Process each team
        for team_header in &idp_teams {
            let idp_group = self.idp_admin.get_group(team_header.id).await
                .context("Failed to get group by ID from Keycloak")?;
            if let Ok(team) = self.sync_team(&mut tx, &idp_group).await {
                if self.update_team_cache(team).await {
                    count += 1;
                }
            }
        }
        
        // Commit the transaction
        tx.commit().await.context("Failed to commit transaction")?;
        
        info!("Successfully synchronized teams");
        
        Ok(count)
    }

    #[instrument(skip(self, tx, idp_team), fields(team_id = %idp_team.id, name = %idp_team.name), level = "debug")]
    async fn sync_team(
        &self, 
        tx: &mut Transaction<'_, Postgres>, 
        idp_team: &IdpGroup
    ) -> anyhow::Result<CompleteTeam> {
        debug!("Synchronizing team: {}", idp_team.name);

        // Convert attributes to JSON if any
        let attributes = serde_json::to_value(&idp_team.attributes)
            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));
        
        // Check if team already exists in idp_entities
        let entity_exists = sqlx::query!(
            r#"
            SELECT id FROM idp_entities 
            WHERE id = $1 AND type = 'team'
            "#,
            idp_team.id
        )
        .fetch_optional(&mut **tx)
        .await
        .context("Failed to query if team entity exists")?;

        // Team entity record
        let entity_id = match entity_exists {
            Some(record) => {
                // Update existing entity
                debug!("Updating existing team entity: {}", idp_team.name);
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
                    idp_team.name,
                    idp_team.path,
                    attributes,
                    idp_team.id
                )
                .execute(&mut **tx)
                .await
                .context("Failed to update team entity")?;
                
                record.id
            },
            None => {
                // Insert new entity
                debug!("Creating new team entity: {}", idp_team.name);
                sqlx::query!(
                    r#"
                    INSERT INTO idp_entities 
                    (id, type, name, path, attributes, last_sync_at)
                    VALUES ($1, 'team', $2, $3, $4, CURRENT_TIMESTAMP)
                    RETURNING id
                    "#,
                    idp_team.id,
                    idp_team.name,
                    idp_team.path,
                    attributes
                )
                .fetch_one(&mut **tx)
                .await
                .context("Failed to insert team entity")?
                .id
            }
        };

        // Check if team entry already exists
        let team_exists = sqlx::query!(
            r#"
            SELECT t.id, t.competition_year, t.created_at, t.updated_at, t.institution_id
            FROM teams t
            WHERE t.entity_id = $1
            "#,
            entity_id
        )
        .fetch_optional(&mut **tx)
        .await
        .context("Failed to query if team exists")?;

        // Team record
        let team_id = match team_exists {
            Some(record) => {
                // Team exists, update institution_id if needed
                debug!("Team entry already exists: {}", idp_team.name);
                record.id
            },
            None => {
                // Create new team entry
                debug!("Creating new team entry: {}", idp_team.name);
                
                sqlx::query!(
                    r#"
                    INSERT INTO teams (id, entity_id)
                    VALUES ($1, $2)
                    RETURNING id
                    "#,
                    idp_team.id,
                    entity_id
                )
                .fetch_one(&mut **tx)
                .await
                .context("Failed to insert team")?
                .id
            }
        };

        // Now retrieve the complete team data with institution
        let team = sqlx::query!(
            r#"
            SELECT 
                t.id,
                e.name,
                e.attributes->'description' as description,
                t.competition_year,
                t.logo_url,
                t.institution_id,
                t.created_at,
                t.updated_at
            FROM 
                teams t
            JOIN
                idp_entities e ON t.entity_id = e.id
            WHERE 
                t.id = $1
            "#,
            team_id
        )
        .fetch_one(&mut **tx)
        .await
        .context("Failed to fetch complete team data")?;

        // Convert to the CompleteTeam struct
        let description = team
            .description
            .and_then(|v| v.as_str().map(|s| s.to_string()));

        Ok(CompleteTeam {
            id: team.id,
            name: team.name,
            description,
            competition_year: team.competition_year,
            logo_url: team.logo_url,
            institution_id: team.institution_id,
            created_at: team.created_at,
            updated_at: team.updated_at,
        })
    }

    /// Update team cache selectively
    async fn update_team_cache(&self, team: CompleteTeam) -> bool {
        let id = team.id;
        let existing = self.teams.get(&id).await;
        
        // Convert team to Arc for storage and comparison
        let team_arc = Arc::new(team);
        
        match existing {
            Some(cached) => {
                // We need to compare the contents to see if they're different
                if !are_teams_equal(&cached, &team_arc) {
                    // Update cache if different
                    self.teams.insert(id, team_arc).await;
                    true
                } else {
                    // No change needed
                    false
                }
            },
            None => {
                // No existing entry, always insert
                self.teams.insert(id, team_arc).await;
                true
            }
        }
    }

    pub async fn get_team(&self, id: Uuid) -> Option<Arc<CompleteTeam>> {
        self.teams.get(&id).await
    }

    pub async fn all_teams(&self) -> Vec<Arc<CompleteTeam>> {
        self.teams.iter().map(|(_, v)| v).collect()
    }
}

fn are_teams_equal(a: &Arc<CompleteTeam>, b: &Arc<CompleteTeam>) -> bool {
    a.id == b.id &&
    a.name == b.name &&
    a.description == b.description &&
    a.competition_year == b.competition_year &&
    a.logo_url == b.logo_url &&
    a.institution_id == b.institution_id
}

#[cfg(test)]
mod tests {
    use crate::AiclIdentifier;
    use sqlx::PgPool;
    
    #[sqlx::test]
    async fn test_sync_teams(pool: PgPool) -> anyhow::Result<()> {
        // Get the IdpAdmin from the environment
        let identifier = AiclIdentifier::from_env(pool).await?;
        let sync_service = identifier.db.clone();
        
        // Run the team sync
        let count = sync_service.sync_all_teams().await?;
        let teams = sync_service.all_teams().await;
        assert_eq!(count, teams.len());
        // Verify some data was synced
        assert!(!teams.is_empty(), "No teams were synced");
        
        // Check specific teams
        let team1 = teams.iter().find(|t| t.name == "Team1");
        assert!(team1.is_some(), "Team1 not found in sync results");
        
        if let Some(team1) = team1 {
            assert!(team1.institution_id.is_none(), "Team1 should be associated with an institution_id");
        }
        let count = sync_service.sync_all_teams().await?;
        assert_eq!(count, 0);
        Ok(())
    }
}
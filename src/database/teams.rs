use anyhow::Context;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use crate::idp::ext::IdpGroup;

use super::{institutions::CompleteInstitution, IdpSyncService};

/// Complete team entity with all related information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteTeam {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub competition_year: Option<i32>,
    pub logo_url: Option<String>,
    pub institution: Option<CompleteInstitution>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}


impl IdpSyncService {
    /// Synchronize all teams from Keycloak
    #[instrument(skip(self), level = "info")]
    pub async fn sync_all_teams(&self) -> anyhow::Result<Vec<CompleteTeam>> {
        info!("Starting synchronization of all teams from Keycloak");
        
        // Start a transaction
        let mut tx = self.db.begin().await.context("Failed to begin transaction")?;
        
        // Get all teams from Keycloak
        // First, get the parent "Teams" group
        let idp_teams = self.idp_admin.get_teams().await
            .context("Failed to get groups from Keycloak")?;
        
        info!(count = idp_teams.len(), "Found teams in Keycloak");
        
        // Process each team
        let mut teams = Vec::with_capacity(idp_teams.len());
        for team_header in &idp_teams {
            let idp_group = self.idp_admin.get_group(team_header.id).await
                .context("Failed to get group by ID from Keycloak")?;
            if let Ok(team) = self.sync_team(&mut tx, &idp_group).await {
                teams.push(team);
            }
        }
        
        // Commit the transaction
        tx.commit().await.context("Failed to commit transaction")?;
        
        info!(synced = teams.len(), "Successfully synchronized teams");
        
        Ok(teams)
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

        // Determine the institution_id if the team belongs to an institution
        // We need to find if team members belong to an institution
        let members = self.idp_admin.get_group_members(idp_team.id).await
            .context("Failed to get team members")?;
        
        let mut institution_id = None;

        // For the first team member that has an institution, use that institution
        if !members.is_empty() {
            // Try to get the institution for the first member
            for member in &members {
                if let Ok(identity) = self.idp_admin.to_domain_user(member).await {
                    if let Some(inst) = identity.institution {
                        // Find the institution ID in the database
                        let db_institution = sqlx::query!(
                            r#"
                            SELECT i.id 
                            FROM institutions i
                            JOIN idp_entities e ON i.entity_id = e.id
                            WHERE e.id = $1
                            "#,
                            inst.id
                        )
                        .fetch_optional(&mut **tx)
                        .await
                        .context("Failed to query institution")?;
                        
                        if let Some(record) = db_institution {
                            institution_id = Some(record.id);
                            break;
                        }
                    }
                }
            }
        }

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
                
                if record.institution_id != institution_id {
                    debug!("Updating team's institution: {}", idp_team.name);
                    sqlx::query!(
                        r#"
                        UPDATE teams 
                        SET institution_id = $1
                        WHERE id = $2
                        "#,
                        institution_id,
                        record.id
                    )
                    .execute(&mut **tx)
                    .await
                    .context("Failed to update team's institution")?;
                }
                
                record.id
            },
            None => {
                // Create new team entry
                debug!("Creating new team entry: {}", idp_team.name);
                
                sqlx::query!(
                    r#"
                    INSERT INTO teams (entity_id, institution_id)
                    VALUES ($1, $2)
                    RETURNING id
                    "#,
                    entity_id,
                    institution_id
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

        // If there's an institution, fetch its details
        let institution = if let Some(inst_id) = team.institution_id {
            let inst_data = sqlx::query!(
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
                inst_id
            )
            .fetch_optional(&mut **tx)
            .await
            .context("Failed to fetch institution data")?;
            
            inst_data.map(|i| {
                CompleteInstitution {
                    id: i.id,
                    name: i.name,
                    domain: i.domain,
                    description: i.description.and_then(|v| v.as_str().map(|s| s.to_string())),
                    website_url: i.website_url,
                    logo_url: i.logo_url,
                    created_at: i.created_at,
                    updated_at: i.updated_at,
                }
            })
        } else {
            None
        };

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
            institution,
            created_at: team.created_at,
            updated_at: team.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AiclIdentifier;
    use sqlx::PgPool;
    
    #[sqlx::test]
    async fn test_sync_teams(pool: PgPool) -> anyhow::Result<()> {
        // Get the IdpAdmin from the environment
        let identifier = AiclIdentifier::from_env().await?;
        
        // Create the sync service
        let sync_service = IdpSyncService::new(pool, identifier.idp.clone());
        
        // Run the team sync
        let teams = sync_service.sync_all_teams().await?;
        
        // Verify some data was synced
        assert!(!teams.is_empty(), "No teams were synced");
        
        // Check specific teams
        let team1 = teams.iter().find(|t| t.name == "Team1");
        assert!(team1.is_some(), "Team1 not found in sync results");
        
        if let Some(team1) = team1 {
            assert!(team1.institution.is_some(), "Team1 should be associated with an institution");
            if let Some(inst) = &team1.institution {
                assert_eq!(inst.name, "School1", "Team1 should be associated with School1");
            }
        }
        
        Ok(())
    }
}
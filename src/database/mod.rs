use std::{sync::Arc, time::Duration};

use institutions::CompleteInstitution;
use moka::future::{Cache, CacheBuilder};
use sqlx::PgPool;
use teams::CompleteTeam;
use tracing::info;
use users::CompleteUser;
use uuid::Uuid;

use crate::idp::admin::IdpAdmin;

pub mod users;
pub mod teams;
pub mod institutions;

/// Service for synchronizing IdP data with the database
pub struct IdpSyncService {
    db: PgPool,
    idp_admin: Arc<IdpAdmin>,
    teams: Cache<Uuid, Arc<CompleteTeam>>,
    users: Cache<Uuid, Arc<CompleteUser>>,
    institutions: Cache<Uuid, Arc<CompleteInstitution>>,
}

impl IdpSyncService {
    /// Create a new IdpSyncService
    pub fn new(db: PgPool, idp_admin: Arc<IdpAdmin>) -> Self {
        let ttl = Duration::from_secs(30);
        let teams = CacheBuilder::new(1000)
                .time_to_idle(ttl)
                .build();
        let users = CacheBuilder::new(500)
                .time_to_idle(ttl)
                .build();
        let institutions = CacheBuilder::new(500)
                .time_to_idle(ttl)
                .build();
        Self { db, idp_admin, teams, users, institutions }
    }

    pub async fn sync_all(&self) -> anyhow::Result<()> {        
        // Sync in the correct order to respect relationships:
        // 1. First sync institutions (they don't depend on anything)
        info!("Starting full sync of Keycloak entities to database");
        
        // 1. Sync institutions first
        let institution_updates = self.sync_all_institutions().await?;
        info!("Synced {} institutions", institution_updates);
        
        // 2. Sync teams (they may depend on institutions)
        let team_updates = self.sync_all_teams().await?;
        info!("Synced {} teams", team_updates);
        
        // 3. Finally sync users (they may depend on both teams and institutions)
        let user_updates = self.sync_all_users().await?;
        info!("Synced {} users", user_updates);
        
        info!("Completed full sync of Keycloak entities to database");
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::AiclIdentifier;
    use sqlx::PgPool;
    
    #[tracing_test::traced_test]
    #[sqlx::test]
    async fn test_full_sync(pool: PgPool) -> anyhow::Result<()> {
        // Get the IdpAdmin from the environment
        let identifier = AiclIdentifier::from_env(pool).await?;
        let sync_service = identifier.db.clone();
        
        // Run the full sync
        sync_service.sync_all().await?;
        
        // Verify data in each table
        let institutions_count = sqlx::query!("SELECT COUNT(*) as count FROM institutions")
            .fetch_one(&sync_service.db)
            .await?
            .count
            .unwrap_or(0);
            
        let teams_count = sqlx::query!("SELECT COUNT(*) as count FROM teams")
            .fetch_one(&sync_service.db)
            .await?
            .count
            .unwrap_or(0);
            
        let users_count = sqlx::query!("SELECT COUNT(*) as count FROM users")
            .fetch_one(&sync_service.db)
            .await?
            .count
            .unwrap_or(0);
            
        let entities_count = sqlx::query!("SELECT COUNT(*) as count FROM idp_entities")
            .fetch_one(&sync_service.db)
            .await?
            .count
            .unwrap_or(0);
            
        // Check that data was synced
        assert!(institutions_count >= 2, "Should have at least 2 institutions");
        assert!(teams_count >= 3, "Should have at least 3 teams");
        assert!(users_count > 0, "Should have synced users");
        assert!(entities_count > 0, "Should have synced entities");
        
        // Validate correctness of relationships
        
        // 1. Verify Team1 is connected to School1
        let team1_institution = sqlx::query!(
            r#"
            SELECT i.id, ie.name as institution_name 
            FROM teams t
            JOIN idp_entities te ON t.entity_id = te.id
            JOIN institutions i ON t.institution_id = i.id
            JOIN idp_entities ie ON i.entity_id = ie.id
            WHERE te.name = 'Team1'
            "#
        )
        .fetch_optional(&sync_service.db)
        .await?;
        
        assert!(team1_institution.is_some(), "Team1 should be connected to an institution");
        assert_eq!(
            team1_institution.unwrap().institution_name, 
            "School1", 
            "Team1 should be connected to School1"
        );
        
        // 2. Verify captain1 has the correct role and team
        let captain1 = sqlx::query!(
            r#"
            SELECT u.role, te.name as team_name
            FROM users u
            JOIN teams t ON u.team_id = t.id
            JOIN idp_entities te ON t.entity_id = te.id
            WHERE u.username = 'captain1'
            "#
        )
        .fetch_optional(&sync_service.db)
        .await?;
        
        assert!(captain1.is_some(), "captain1 should exist in the database");
        let captain1 = captain1.unwrap();
        assert_eq!(captain1.role, "captain", "captain1 should have the 'captain' role");
        assert_eq!(captain1.team_name, "Team1", "captain1 should be in Team1");
        
        // 3. Verify advisor1 has the correct role and institution
        let advisor1 = sqlx::query!(
            r#"
            SELECT u.role, ie.name as institution_name
            FROM users u
            JOIN institutions i ON u.institution_id = i.id
            JOIN idp_entities ie ON i.entity_id = ie.id
            WHERE u.username = 'advisor1'
            "#
        )
        .fetch_optional(&sync_service.db)
        .await?;
        
        assert!(advisor1.is_some(), "advisor1 should exist in the database");
        let advisor1 = advisor1.unwrap();
        assert_eq!(advisor1.role, "advisor", "advisor1 should have the 'advisor' role");
        assert_eq!(advisor1.institution_name, "School1", "advisor1 should be in School1");
        
        // 4. Test the team_members_view
        let team1_members = sqlx::query!(
            r#"
            SELECT username, role
            FROM team_members_view
            WHERE team_name = 'Team1'
            "#
        )
        .fetch_all(&sync_service.db)
        .await?;
        
        assert!(!team1_members.is_empty(), "Team1 should have members in the view");
        
        // Check if we have all the expected roles for Team1
        let has_captain = team1_members.iter().any(|m| 
            m.role.as_deref() == Some("captain")
        );
        let has_student = team1_members.iter().any(|m| 
            m.role.as_deref() == Some("student")
        );
        let has_spectator = team1_members.iter().any(|m| 
            m.role.as_deref() == Some("spectator")
        );
        
        assert!(has_captain, "Team1 should have a captain in the view");
        assert!(has_student, "Team1 should have a student in the view");
        assert!(has_spectator, "Team1 should have a spectator in the view");
        
        // 5. Test the institution_members_view
        let school1_members = sqlx::query!(
            r#"
            SELECT username, role
            FROM institution_members_view
            WHERE institution_name = 'School1'
            "#
        )
        .fetch_all(&sync_service.db)
        .await?;
        
        assert!(!school1_members.is_empty(), "School1 should have members in the view");
        
        // Check if we have advisors in School1
        let has_advisor = school1_members.iter().any(|m| 
            m.role.as_deref() == Some("advisor")
        );
        
        assert!(has_advisor, "School1 should have an advisor in the view");
        
        // 6. Test the teams_with_institutions_view
        let teams = sqlx::query!(
            r#"
            SELECT 
                team_name, 
                institution_name, 
                member_count,
                captain_count
            FROM teams_with_institutions_view
            "#
        )
        .fetch_all(&sync_service.db)
        .await?;
        
        assert!(!teams.is_empty(), "Should have teams in the view");
        
        // Find Team1 in the results
        let team1 = teams.iter().find(|t| 
            t.team_name.as_deref() == Some("Team1")
        );
        
        assert!(team1.is_some(), "Team1 should be in the view");
        let team1 = team1.unwrap();
        
        assert_eq!(team1.institution_name.as_deref(), Some("School1"), 
            "Team1 should be linked to School1 in the view");
        assert!(team1.member_count.unwrap_or(0) >= 3, 
            "Team1 should have at least 3 members in the view");
        assert_eq!(team1.captain_count.unwrap_or(0), 1, 
            "Team1 should have 1 captain in the view");
        
        Ok(())
    }
}
mod harness;
use aicl_oidc::{test_utils::{AuthSession, AuthTestUtils}, AiclIdentifier, Role};
use std::collections::HashMap;
use harness::initialize_test_service;

// Helper function to authenticate all test users and return a map by role
async fn authenticate_users_by_role(auth_utils: &AuthTestUtils) -> HashMap<Role, AuthSession> {
    let test_users = AuthTestUtils::create_test_users();
    
    let sessions = auth_utils.authenticate_users(&test_users).await;
    
    let mut role_map: HashMap<Role, AuthSession> = HashMap::new();
    
    for (i, session_result) in sessions.into_iter().enumerate() {
        if let Ok(session) = session_result {
            // Only keep one session per role (first encountered)
            if !role_map.contains_key(&session.identity.role) {
                role_map.insert(session.identity.role, session);
            }
        } else {
            panic!("Failed to authenticate user {}: {:?}", 
                   test_users[i].username, 
                   session_result.err());
        }
    }
    
    role_map
}

// Test endpoints with specific permissions for this example
// In a real application, you would test actual endpoints
enum TestEndpoint {
    PublicInfo,
    TeamView,
    TeamEdit,
    AdminOnly,
    AdvisorOnly,
}

impl TestEndpoint {
    fn url(&self, app_url: &str) -> String {
        let path = match self {
            Self::PublicInfo => "/api/public",
            Self::TeamView => "/api/teams/view",
            Self::TeamEdit => "/api/teams/edit",
            Self::AdminOnly => "/api/admin",
            Self::AdvisorOnly => "/api/advisors",
        };
        
        format!("{}{}", app_url, path)
    }
    
    fn allowed_roles(&self) -> Vec<Role> {
        match self {
            Self::PublicInfo => vec![
                Role::Admin, Role::Advisor, Role::Captain, Role::Student, Role::Spectator
            ],
            Self::TeamView => vec![
                Role::Admin, Role::Advisor, Role::Captain, Role::Student, Role::Spectator
            ],
            Self::TeamEdit => vec![
                Role::Admin, Role::Captain
            ],
            Self::AdminOnly => vec![
                Role::Admin
            ],
            Self::AdvisorOnly => vec![
                Role::Admin, Role::Advisor
            ],
        }
    }
}

// Helper function to test if a session can access an endpoint
async fn test_endpoint_access(
    session: &AuthSession, 
    endpoint: &TestEndpoint,
    app_url: &str,
    expected_access: bool
) {
    let url = endpoint.url(app_url);
    let response = session.get(&url).await.expect("Request failed");
    
    let has_access = response.status().is_success();
    
    assert_eq!(
        has_access, 
        expected_access,
        "User {} with role {:?} {} access to {}, but access was {}",
        session.identity.username,
        session.identity.role,
        if expected_access { "should have" } else { "should NOT have" },
        url,
        if has_access { "granted" } else { "denied" }
    );
}

#[tokio::test]
async fn test_role_based_permissions() {
    let (app_url, _guard) = initialize_test_service().await;
    let aicl_identifier = AiclIdentifier::from_env().await.expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;
    
    // Get sessions for all roles
    let sessions_by_role = authenticate_users_by_role(&auth_utils).await;
    
    // Define the endpoints to test
    let endpoints = [
        TestEndpoint::PublicInfo,
        TestEndpoint::TeamView,
        TestEndpoint::TeamEdit,
        TestEndpoint::AdminOnly,
        TestEndpoint::AdvisorOnly,
    ];
    
    // Test each endpoint with each role
    for endpoint in &endpoints {
        let allowed_roles = endpoint.allowed_roles();
        
        for (role, session) in &sessions_by_role {
            let should_have_access = allowed_roles.contains(role);
            
            test_endpoint_access(
                session, 
                endpoint, 
                &app_url, 
                should_have_access
            ).await;
        }
    }
}

#[tokio::test]
async fn test_team_isolation() {
    let (app_url, _guard) = initialize_test_service().await;
    let aicl_identifier = AiclIdentifier::from_env().await.expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;
    
    // Authenticate captains from two different teams
    let captain1 = auth_utils.create_session_with_api_token("captain1", "captain")
        .await
        .expect("Failed to authenticate captain1");
        
    let captain2 = auth_utils.create_session_with_api_token("captain2", "captain")
        .await
        .expect("Failed to authenticate captain2");
    
    // Test Team1 resources
    let team1_url = format!("{}/api/teams/Team1/resources", app_url);
    let team2_url = format!("{}/api/teams/Team2/resources", app_url);
    
    // Captain1 should have access to Team1 resources
    let response = captain1.get(&team1_url).await.expect("Request failed");
    assert!(
        response.status().is_success(),
        "Captain1 should have access to Team1 resources"
    );
    
    // Captain1 should NOT have access to Team2 resources
    let response = captain1.get(&team2_url).await.expect("Request failed");
    assert!(
        !response.status().is_success(),
        "Captain1 should NOT have access to Team2 resources"
    );
    
    // Captain2 should have access to Team2 resources
    let response = captain2.get(&team2_url).await.expect("Request failed");
    assert!(
        response.status().is_success(),
        "Captain2 should have access to Team2 resources"
    );
    
    // Captain2 should NOT have access to Team1 resources
    let response = captain2.get(&team1_url).await.expect("Request failed");
    assert!(
        !response.status().is_success(),
        "Captain2 should NOT have access to Team1 resources"
    );
}

#[tokio::test]
async fn test_institution_isolation() {
    let (app_url, _guard) = initialize_test_service().await;
    let aicl_identifier = AiclIdentifier::from_env().await.expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;
    
    // Authenticate advisors from different institutions
    let advisor1 = auth_utils.create_session_with_api_token("advisor1", "admin")
        .await
        .expect("Failed to authenticate advisor1");
        
    let advisor2 = auth_utils.create_session_with_api_token("advisor2", "admin")
        .await
        .expect("Failed to authenticate advisor2");
    
    // Test institution resources
    let school1_url = format!("{}/api/institutions/School1/resources", app_url);
    let school2_url = format!("{}/api/institutions/School2/resources", app_url);
    
    // Advisor1 should have access to School1 resources
    let response = advisor1.get(&school1_url).await.expect("Request failed");
    assert!(
        response.status().is_success(),
        "Advisor1 should have access to School1 resources"
    );
    
    // Advisor1 should NOT have access to School2 resources
    let response = advisor1.get(&school2_url).await.expect("Request failed");
    assert!(
        !response.status().is_success(),
        "Advisor1 should NOT have access to School2 resources"
    );
    
    // Advisor2 should have access to School2 resources
    let response = advisor2.get(&school2_url).await.expect("Request failed");
    assert!(
        response.status().is_success(),
        "Advisor2 should have access to School2 resources"
    );
    
    // Advisor2 should NOT have access to School1 resources
    let response = advisor2.get(&school1_url).await.expect("Request failed");
    assert!(
        !response.status().is_success(),
        "Advisor2 should NOT have access to School1 resources"
    );
}

#[tokio::test]
async fn test_admin_override() {
    let (app_url, _guard) = initialize_test_service().await;
    let aicl_identifier = AiclIdentifier::from_env().await.expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;
    
    // Authenticate as admin
    let admin = auth_utils.create_session_with_api_token("admin", "admin")
        .await
        .expect("Failed to authenticate admin");
    
    // Admin should have access to all team and institution resources
    let urls = [
        format!("{}/api/teams/Team1/resources", app_url),
        format!("{}/api/teams/Team2/resources", app_url),
        format!("{}/api/institutions/School1/resources", app_url),
        format!("{}/api/institutions/School2/resources", app_url),
    ];
    
    for url in &urls {
        let response = admin.get(url).await.expect("Request failed");
        assert!(
            response.status().is_success(),
            "Admin should have access to {}", url
        );
    }
}
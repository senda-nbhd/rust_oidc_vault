use aicl_oidc::test_utils::{AuthTestUtils, TestUser};
use tokio::sync::OnceCell;

// Use OnceCell to initialize the test service once per test session
static TEST_HARNESS: OnceCell<String> = OnceCell::const_new();

async fn initialize_test_service() -> &'static str {
    TEST_HARNESS.get_or_init(|| async {
        // In a real test, you would initialize your test service here
        // For this example, we'll just use a hardcoded URL
        "http://localhost:4040".to_string()
    }).await
}

#[tokio::test]
async fn test_authenticate_captain() {
    let app_url = initialize_test_service().await;
    
    let auth_utils = AuthTestUtils::new(app_url)
        .with_client_id("rust-app")
        .with_client_secret(Some("test-client-secret".to_string()));
    
    let captain_user = TestUser {
        username: "captain1".to_string(),
        password: "captain".to_string(),
        expected_team: Some("Team1".to_string()),
        expected_role: "captain",
    };
    
    // Authenticate the user
    let session = auth_utils.authenticate_user(&captain_user).await
        .expect("Failed to authenticate captain");
    
    // Verify identity information
    assert_eq!(session.identity.username, "captain1");
    assert_eq!(session.identity.role.as_str(), "captain");
    assert!(session.identity.team.is_some());
    assert_eq!(session.identity.team.as_ref().unwrap().name, "Team1");
    
    // Verify we have an API token
    assert!(session.api_token.is_some());
    
    // Make a request to a protected endpoint
    let response = session.get(&format!("{}/api/protected", app_url)).await
        .expect("Request failed");
    
    assert!(response.status().is_success(), 
        "API request should succeed, got: {}", response.status());
}

#[tokio::test]
async fn test_authenticate_student() {
    let app_url = initialize_test_service().await;
    
    let auth_utils = AuthTestUtils::new(app_url);
    
    let student_user = TestUser {
        username: "member1".to_string(),
        password: "member".to_string(),
        expected_team: Some("Team1".to_string()),
        expected_role: "student",
    };
    
    // Authenticate the student
    let session = auth_utils.authenticate_user(&student_user).await
        .expect("Failed to authenticate student");
    
    // Verify identity information
    assert_eq!(session.identity.username, "member1");
    assert_eq!(session.identity.role.as_str(), "student");
    assert!(session.identity.team.is_some());
    assert_eq!(session.identity.team.as_ref().unwrap().name, "Team1");
    
    // Verify we have an API token
    assert!(session.api_token.is_some());
}

#[tokio::test]
async fn test_authenticate_advisor() {
    let app_url = initialize_test_service().await;
    
    let auth_utils = AuthTestUtils::new(app_url);
    
    let advisor_user = TestUser {
        username: "advisor1".to_string(),
        password: "admin".to_string(),
        expected_team: None,
        expected_role: "advisor",
    };
    
    // Authenticate the advisor
    let session = auth_utils.authenticate_user(&advisor_user).await
        .expect("Failed to authenticate advisor");
    
    // Verify identity information
    assert_eq!(session.identity.username, "advisor1");
    assert_eq!(session.identity.role.as_str(), "advisor");
    assert!(session.identity.institution.is_some());
    assert_eq!(session.identity.institution.as_ref().unwrap().name, "School1");
    
    // Verify we have an API token
    assert!(session.api_token.is_some());
}

#[tokio::test]
async fn test_authenticate_admin() {
    let app_url = initialize_test_service().await;
    
    let auth_utils = AuthTestUtils::new(app_url);
    
    let admin_user = TestUser {
        username: "admin".to_string(),
        password: "admin".to_string(),
        expected_team: None,
        expected_role: "admin",
    };
    
    // Authenticate the admin
    let session = auth_utils.authenticate_user(&admin_user).await
        .expect("Failed to authenticate admin");
    
    // Verify identity information
    assert_eq!(session.identity.username, "admin");
    assert_eq!(session.identity.role.as_str(), "admin");
    
    // Verify we have an API token
    assert!(session.api_token.is_some());
}

#[tokio::test]
async fn test_get_api_token_direct() {
    let app_url = initialize_test_service().await;
    
    let auth_utils = AuthTestUtils::new(app_url);
    
    // Get an API token directly
    let api_token = auth_utils.get_api_token_direct("captain1", "captain")
        .await
        .expect("Failed to get API token");
    
    // Verify token properties
    assert!(!api_token.client_token.is_empty());
    assert!(api_token.expires_at > 0);
    assert!(!api_token.policies.is_empty());
}

#[tokio::test]
async fn test_authenticate_multiple_users() {
    let app_url = initialize_test_service().await;
    
    let auth_utils = AuthTestUtils::new(app_url);
    
    // Define multiple test users
    let test_users = vec![
        TestUser {
            username: "captain1".to_string(),
            password: "captain".to_string(),
            expected_team: Some("Team1".to_string()),
            expected_role: "captain",
        },
        TestUser {
            username: "admin".to_string(),
            password: "admin".to_string(),
            expected_team: None,
            expected_role: "admin",
        },
    ];
    
    // Authenticate all users in parallel
    let sessions = auth_utils.authenticate_users(&test_users).await;
    
    // Verify all authentications succeeded
    assert_eq!(sessions.len(), 2);
    
    for (i, session_result) in sessions.iter().enumerate() {
        assert!(session_result.is_ok(), 
            "Authentication failed for user {}: {:?}", 
            test_users[i].username, 
            session_result.as_ref().err());
        
        let session = session_result.as_ref().unwrap();
        assert_eq!(session.identity.username, test_users[i].username);
        assert_eq!(session.identity.role.as_str(), test_users[i].expected_role);
    }
}
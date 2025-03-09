use axum_test::TestServer;

use crate::{test_utils::TestUser, AiclIdentifier};

#[tracing_test::traced_test]
#[tokio::test]
async fn test_authenticate_captain() {
    let aicl_identifier = AiclIdentifier::from_env()
        .await
        .expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;

    let captain_user = TestUser {
        username: "captain1".to_string(),
        password: "captain".to_string(),
        expected_team: Some("Team1".to_string()),
        expected_role: "captain",
    };

    // Authenticate the user
    let session = auth_utils
        .authenticate_user(&captain_user)
        .await
        .expect("Failed to authenticate captain");

    // Verify identity information
    assert_eq!(session.identity.username, "captain1");
    assert_eq!(session.identity.role.as_str(), "captain");
    assert!(session.identity.team.is_some());
    assert_eq!(session.identity.team.as_ref().unwrap().name, "Team1");

    // Verify we have an API token
    assert!(session.api_token.is_some());
    let router = super::router(aicl_identifier).await;
    let server = TestServer::new(router).unwrap();

    // Make a request to a protected endpoint
    let response = server
        .get("/api/protected")
        .add_header(
            "Authorization",
            format!("Bearer {}", session.api_token.unwrap().client_token),
        )
        .await;
    assert_eq!(response.status_code(), 200);
}

#[tracing_test::traced_test]
#[tokio::test]
async fn test_authenticate_student() {
    let aicl_identifier = AiclIdentifier::from_env()
        .await
        .expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;

    let student_user = TestUser {
        username: "member1".to_string(),
        password: "member".to_string(),
        expected_team: Some("Team1".to_string()),
        expected_role: "student",
    };

    // Authenticate the student
    let session = auth_utils
        .authenticate_user(&student_user)
        .await
        .expect("Failed to authenticate student");

    // Verify identity information
    assert_eq!(session.identity.username, "member1");
    assert_eq!(session.identity.role.as_str(), "student");
    assert!(session.identity.team.is_some());
    assert_eq!(session.identity.team.as_ref().unwrap().name, "Team1");

    // Verify we have an API token
    assert!(session.api_token.is_none());
}

#[tracing_test::traced_test]
#[tokio::test]
async fn test_authenticate_advisor() {
    let aicl_identifier = AiclIdentifier::from_env()
        .await
        .expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;

    let advisor_user = TestUser {
        username: "advisor1".to_string(),
        password: "admin".to_string(),
        expected_team: None,
        expected_role: "advisor",
    };

    // Authenticate the advisor
    let session = auth_utils
        .authenticate_user(&advisor_user)
        .await
        .expect("Failed to authenticate advisor");

    // Verify identity information
    assert_eq!(session.identity.username, "advisor1");
    assert_eq!(session.identity.role.as_str(), "advisor");
    assert!(session.identity.institution.is_some());
    assert_eq!(
        session.identity.institution.as_ref().unwrap().name,
        "School1"
    );

    // Verify we have an API token
    assert!(session.api_token.is_none());
}

#[tracing_test::traced_test]
#[tokio::test]
async fn test_authenticate_admin() {
    let aicl_identifier = AiclIdentifier::from_env()
        .await
        .expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;

    let admin_user = TestUser {
        username: "admin".to_string(),
        password: "admin".to_string(),
        expected_team: None,
        expected_role: "admin",
    };

    // Authenticate the admin
    let session = auth_utils
        .authenticate_user(&admin_user)
        .await
        .expect("Failed to authenticate admin");

    // Verify identity information
    assert_eq!(session.identity.username, "admin");
    assert_eq!(session.identity.role.as_str(), "admin");

    // Verify we have an API token
    assert!(session.api_token.is_some());
}

#[tracing_test::traced_test]
#[tokio::test]
async fn test_get_api_token_direct() {
    let aicl_identifier = AiclIdentifier::from_env()
        .await
        .expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;

    // Get an API token directly
    let api_token = auth_utils
        .get_api_token_direct("captain1", "captain")
        .await
        .expect("Failed to get API token");

    // Verify token properties
    assert!(!api_token.client_token.is_empty());
    assert!(api_token.expires_at > 0);
    assert!(!api_token.policies.is_empty());
}

#[tracing_test::traced_test]
#[tokio::test]
async fn test_authenticate_multiple_users() {
    let aicl_identifier = AiclIdentifier::from_env()
        .await
        .expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;

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
        assert!(
            session_result.is_ok(),
            "Authentication failed for user {}: {:?}",
            test_users[i].username,
            session_result.as_ref().err()
        );

        let session = session_result.as_ref().unwrap();
        assert_eq!(session.identity.username, test_users[i].username);
        assert_eq!(session.identity.role.as_str(), test_users[i].expected_role);
    }
}

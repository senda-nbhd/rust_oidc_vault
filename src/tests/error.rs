use axum_test::TestServer;
use sqlx::PgPool;

use crate::{test_utils::TestUser, AiclIdentifier};

#[tracing_test::traced_test]
#[sqlx::test]
async fn test_invalid_credentials(pool: PgPool) {
    let aicl_identifier = AiclIdentifier::from_env(pool).await.expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;
    
    let invalid_user = TestUser {
        username: "nonexistent".to_string(),
        password: "wrongpassword".to_string(),
        expected_team: None,
        expected_role: "",
    };
    
    // Try to authenticate with invalid credentials
    let result = auth_utils.authenticate_user(&invalid_user).await;
    
    // Authentication should fail
    assert!(result.is_err(), "Authentication should fail with invalid credentials");
    
    // Verify the error message
    let error = result.unwrap_err();
    assert!(
        error.to_string().contains("Authentication") || 
        error.to_string().contains("Failed") || 
        error.to_string().contains("Invalid"),
        "Error should indicate authentication failure, got: {}", error
    );
}

#[tracing_test::traced_test]
#[sqlx::test]
async fn test_role_expectation_mismatch(pool: PgPool) {
    let aicl_identifier = AiclIdentifier::from_env(pool).await.expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;
    
    // User with incorrect role expectation
    let user_with_wrong_role = TestUser {
        username: "captain1".to_string(),
        password: "captain".to_string(),
        expected_team: Some("Team1".to_string()),
        expected_role: "admin",  // Wrong role, captain1 is a captain
    };
    
    // Try to authenticate
    let result = auth_utils.authenticate_user(&user_with_wrong_role).await;
    
    // Should fail due to role mismatch
    assert!(result.is_err(), "Authentication should fail due to role mismatch");
    assert!(
        result.unwrap_err().to_string().contains("Role mismatch"),
        "Error should indicate role mismatch"
    );
}

#[tracing_test::traced_test]
#[sqlx::test]
async fn test_team_expectation_mismatch(pool: PgPool) {
    let aicl_identifier = AiclIdentifier::from_env(pool).await.expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;
    
    // User with incorrect team expectation
    let user_with_wrong_team = TestUser {
        username: "captain1".to_string(),
        password: "captain".to_string(),
        expected_team: Some("Team2".to_string()),  // Wrong team, captain1 is in Team1
        expected_role: "captain",
    };
    
    // Try to authenticate
    let result = auth_utils.authenticate_user(&user_with_wrong_team).await;
    
    // Should fail due to team mismatch
    assert!(result.is_err(), "Authentication should fail due to team mismatch");
    assert!(
        result.unwrap_err().to_string().contains("Team mismatch"),
        "Error should indicate team mismatch"
    );
}

#[tracing_test::traced_test]
#[sqlx::test]
async fn test_token_revocation(pool: PgPool) {
    let aicl_identifier = AiclIdentifier::from_env(pool).await.expect("Failed to get AiclIdentifier from env");
    let auth_utils = aicl_identifier.test_utils().await;
    
    // Get a session
    let session = auth_utils.create_session_with_api_token("captain1", "captain")
        .await
        .expect("Failed to authenticate");
    
    let router = super::router(aicl_identifier).await;
    let server = TestServer::new(router).unwrap();

    // Use the token to access a protected endpoint
    let response = server.get("/api/protected")
        .add_header(
            "Authorization",
            format!("Bearer {}", session.api_token.clone().unwrap().client_token),
        )
        .await;
    
    assert!(response.status_code().is_success(), "Initial request should succeed");
    
    // In a real test, you would revoke the token here
    // This would typically call a function like:
    auth_utils.revoke_token(&session.api_token.clone().unwrap().client_token).await.expect("Token revocation failed");
    
    // Then try to use the revoked token (would fail in a real implementation)
    let response = server.get("/api/protected")
    .add_header(
        "Authorization",
        format!("Bearer {}", session.api_token.clone().unwrap().client_token),
    )
    .await;
    assert!(!response.status_code().is_success(), "Request with revoked token should fail");
}
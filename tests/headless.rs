mod harness;

use aicl_oidc::vault::ApiToken;
use headless_chrome::{Browser, Tab};
use reqwest::{header::{HeaderMap, AUTHORIZATION}, Client};
pub const APP_URL: &str = "http://localhost:4040";

// Separate tests for each authentication flow scenario
#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_end_to_end_access() {
    // Initialize service and get guard that will decrement reference count when dropped
    let (_, _guard) = harness::initialize_test_service().await;

    let browser = Browser::default().expect("Failed to create browser");
    let tab = browser.new_tab().expect("Failed to open tab");
    tracing::info!("Opening browser and navigating to {}/bar", APP_URL);
    // Navigate to the maybe_authenticated endpoint
    tab.navigate_to(&format!("{}/bar", APP_URL))
        .expect("Failed to navigate to /bar");

    // Wait for the response and verify content
    let body = tab.wait_for_element("body").expect("Element not found");
    let body = body.get_inner_text().expect("Failed to get inner text");
    assert_eq!(body, "Hello anon!");

    tracing::info!("✅ Unauthenticated access test passed");

    // Navigate to the authenticated endpoint
    tab.navigate_to(&format!("{}/foo", APP_URL))
        .expect("Failed to navigate to /foo");

    // Wait for redirect to Keycloak login page
    tab.wait_for_element("#kc-form-login")
        .expect("Keycloak login form not found");

    // Fill in login credentials
    tab.find_element("#username")
        .expect("Failed to find username field")
        .type_into("captain1")
        .expect("Failed to input username field");
    tab.find_element("#password")
        .expect("Failed to find password field")
        .type_into("captain")
        .expect("Failed to input password field");

    // Submit the login form
    tab.find_element("#kc-login")
        .expect("Failed to find login button")
        .click()
        .expect("Failed to click login button");

    // Wait for redirect back to application
    tab.wait_until_navigated()
        .expect("Failed to navigate back to application");

    // Verify the response contains the authenticated user info
    let body = tab
        .wait_for_element("body")
        .expect("Element not found")
        .get_inner_text()
        .expect("Failed to get inner text");

    assert!(body.contains("captain1"), "Response should contain username");
    assert!(body.contains("Team1"), "Response should contain team info");

    // Test accessing maybe_authenticated endpoint while authenticated
    tab.navigate_to(&format!("{}/bar", APP_URL))
        .expect("Failed to navigate to /bar");

    // Wait for the response and verify content
    let body = tab
        .wait_for_element("body")
        .expect("Element not found")
        .get_inner_text()
        .expect("Failed to get inner text");

    assert!(
        body.contains("Hello captain1! You are already logged in."),
        "Response should indicate user is logged in"
    );

    // Logout
    tab.navigate_to(&format!("{}/logout", APP_URL))
        .expect("Failed to navigate to /logout");

    // Wait for redirect to complete
    tab.wait_until_navigated()
        .expect("Failed to navigate after logout");

    tracing::info!("✅ OIDC session authentication test passed");
    
    // Navigate to the authenticated endpoint
    tab.navigate_to(&format!("{}/token", APP_URL))
        .expect("Failed to navigate to /token");

    // Wait for redirect to Keycloak login page
    tab.wait_for_element("#kc-form-login")
        .expect("Keycloak login form not found");

    // Fill in login credentials
    tab.find_element("#username")
        .expect("Failed to find username field")
        .type_into("captain1")
        .expect("Failed to input username field");
    tab.find_element("#password")
        .expect("Failed to find password field")
        .type_into("captain")
        .expect("Failed to input password field");

    // Submit the login form
    tab.find_element("#kc-login")
        .expect("Failed to find login button")
        .click()
        .expect("Failed to click login button");

    // Wait for redirect back to application
    tab.wait_until_navigated()
        .expect("Failed to navigate back to application");
    let body = tab
        .wait_for_element("body")
        .expect("Element not found")
        .get_inner_text()
        .expect("Failed to get inner text");
    tracing::info!(body, "Successfully logged in with username: captain1");
    let token = serde_json::from_str::<ApiToken>(&body)
        .expect("Failed to parse claims from response");
    // Parse the token from the response
    
    tracing::info!("Successfully created API token: {}", token.client_token);
    
    
    // Step 2: Use the token to access a protected endpoint
    // Create a new HTTP client for token authentication (no cookies needed)
    let api_client = Client::new();
    let api_response = api_client
        .get(format!("{}/api/protected", APP_URL))
        .header(AUTHORIZATION, format!("Bearer {}", token.client_token))
        .send()
        .await
        .expect("Failed to send API request");
    
    // Check the response is successful
    assert!(
        api_response.status().is_success(),
        "API request with token should succeed, got: {}", api_response.status()
    );
    
    // Check the response body contains the expected content
    let body = api_response.text().await.expect("Failed to get response body");
    assert!(
        body.contains("API access granted for captain1"),
        "Response should indicate successful API access, got: {}", body
    );
    
    tracing::info!("✅ Token authentication test passed");
    // Guard will be dropped here, decrementing the reference count
}

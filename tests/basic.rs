mod service;

use aicl_oidc::{idp::admin::IdpAdmin, vault::VaultService};
use headless_chrome::{Browser, Tab};
use tokio::task::JoinHandle;

// This test simulates a real user flow through the entire authentication process
// It spins up the application and uses a headless browser to login through Keycloak
#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread")]
async fn test_oidc_authentication_flow() {
    // Start the application
    let app_url = "http://localhost:4040";
    let app_process = start_application().await;

    // Run browser tests
    let browser_result = test_browser_flow(app_url).await;

    app_process.abort();

    // Assert test results
    assert!(
        browser_result.is_ok(),
        "Browser test failed: {:?}",
        browser_result.err()
    );
}

// Start the application in a separate process
async fn start_application() -> JoinHandle<()> {
    dotenvy::dotenv().ok();

    // Log application startup
    tracing::info!("Starting OIDC application");
    let vault = VaultService::from_env()
        .await
        .expect("Vault service initialization failed");
    let idp_config = vault
        .get_idp_config_from_vault()
        .await
        .expect("Failed to get IDP config from Vault");
    let idp_admin = IdpAdmin::new(idp_config)
        .await
        .expect("IDP admin initialization failed");
    tokio::spawn(service::run(idp_admin))
}

// Tests the authentication flow using a headless browser
async fn test_browser_flow(app_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Launch a headless Chrome browser
    let browser = Browser::default()?;
    let tab = browser.new_tab()?;

    // Test unauthenticated access to /bar endpoint
    test_unauthenticated_access(&tab, app_url);

    // Test authentication and access to protected endpoint
    test_authentication(&tab, app_url);

    // Test accessing maybe_authenticated endpoint while authenticated
    test_authenticated_maybe_endpoint(&tab, app_url)?;

    // Test logout
    test_logout(&tab, app_url)?;

    // Close the browser tab
    tab.close(true)?;

    Ok(())
}

// Test accessing the maybe_authenticated endpoint without authentication
fn test_unauthenticated_access(tab: &Tab, app_url: &str) {
    // Navigate to the maybe_authenticated endpoint
    tab.navigate_to(&format!("{}/bar", app_url))
        .expect("Failed to navigate to /bar");

    // Wait for the response and verify content
    let body = tab.wait_for_element("body").expect("Element not found");
    let body = body.get_inner_text().expect("Failed to get inner text");
    assert_eq!(body, "Hello anon!");

    println!("✅ Unauthenticated access test passed");
}

// Test authentication and access to protected endpoint
fn test_authentication(tab: &Tab, app_url: &str) {
    // Navigate to the authenticated endpoint
    tab.navigate_to(&format!("{}/foo", app_url))
        .expect("Failed to navigate to /foo");

    // Wait for redirect to Keycloak login page
    tab.wait_for_element("#kc-form-login")
        .expect("Keycloak login form not found");

    // Fill in login credentials
    tab.find_element("#username")
        .expect("Failed to find username field")
        .type_into("admin1")
        .expect("Failed to input username field");
    tab.find_element("#password")
        .expect("Failed to find password field")
        .type_into("admin")
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
    tracing::info!(body, "Response");
    assert!(body.contains("admin1"), "Response should contain username");
    assert!(body.contains("Team1"), "Response should contain team info");

    println!("✅ Authentication test passed");
}

// Test accessing the maybe_authenticated endpoint while authenticated
fn test_authenticated_maybe_endpoint(
    tab: &Tab,
    app_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Navigate to the maybe_authenticated endpoint
    tab.navigate_to(&format!("{}/bar", app_url))?;

    // Wait for the response and verify content
    let body = tab.wait_for_element("body")?.get_inner_text()?;
    assert!(
        body.contains("Hello admin1! You are already logged in."),
        "Response should indicate user is logged in"
    );

    println!("✅ Authenticated maybe_endpoint test passed");
    Ok(())
}

// Test logout functionality
fn test_logout(tab: &Tab, app_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Navigate to the logout endpoint
    tab.navigate_to(&format!("{}/logout", app_url))?;

    // Wait for redirect to complete
    tab.wait_until_navigated()?;

    // Navigate to the maybe_authenticated endpoint to verify logout
    tab.navigate_to(&format!("{}/bar", app_url))?;

    // Verify the response shows unauthenticated state
    let body = tab.wait_for_element("body")?.get_inner_text()?;
    assert_eq!(
        body, "Hello anon!",
        "Response should show user is logged out"
    );

    // Try to access the authenticated endpoint
    tab.navigate_to(&format!("{}/foo", app_url))?;

    // Should be redirected to login page
    tab.wait_for_element("#kc-form-login")?;

    println!("✅ Logout test passed");
    Ok(())
}

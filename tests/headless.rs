use aicl_oidc::{errors::JsonErrorHandler, oidc::keycloak::{KeyCloakToken, TOKEN_KEY}, vault::ApiToken, AiclIdentifier, AiclIdentity, AppErrorHandler, OptionalIdentity};
use axum::{response::IntoResponse, routing::get, Json, Router};
use dotenvy::dotenv;
use headless_chrome::Browser;
use reqwest::{header::AUTHORIZATION, Client, StatusCode};
use sqlx::postgres::PgPoolOptions;
use tokio::{net::TcpListener, task::JoinHandle};
use tower_sessions::{cookie::{time::Duration, SameSite}, Expiry, MemoryStore, Session, SessionManagerLayer};
pub const APP_URL: &str = "http://localhost:4040";

pub async fn run(identifier: AiclIdentifier) {
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(Duration::hours(1)));
    let error_handler = AppErrorHandler::new(JsonErrorHandler::default());

    let app = Router::new()
        .merge(
            Router::new()
                .route("/foo", get(authenticated))
                .route_service("/logout", identifier.logout_service())
                .route("/token", get(create_token))
                .layer(identifier.login_layer())
                .route("/bar", get(maybe_authenticated))
                .layer(identifier.authenticate_layer())
                .layer(session_layer)
                .layer(identifier.identifier_layer())
                .layer(error_handler.layer()),
        )
        .nest(
            "/api",
            Router::new()
                .route("/protected", get(token_authenticated))
                .layer(identifier.api_token_layer())
                .layer(error_handler.layer()),
        );

    let listener = TcpListener::bind("0.0.0.0:4040").await.unwrap();
    tracing::info!("Router built, launcing");
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

async fn authenticated(claims: AiclIdentity) -> impl IntoResponse {
    format!("Hello {}", serde_json::to_string_pretty(&claims).unwrap())
}

#[axum::debug_handler]
async fn maybe_authenticated(OptionalIdentity(maybe_user): OptionalIdentity) -> impl IntoResponse {
    match maybe_user {
        Some(identity) => {
            format!("Hello {}! You are already logged in.", identity.username)
        }
        None => {
            format!("Hello anon!")
        }
    }
}

// Endpoint for creating API tokens
async fn create_token(
    identity: AiclIdentity,
    session: Session,
    identifier: AiclIdentifier,
) -> Result<Json<ApiToken>, (StatusCode, String)> {
    // Get the vault service from the identifier

    // Get the OIDC token from the session
    let oidc_token = session
        .get::<KeyCloakToken>(TOKEN_KEY)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Session error: {}", e),
            )
        })?
        .ok_or((StatusCode::UNAUTHORIZED, "No OIDC token found".to_string()))?;
    tracing::info!("Creating API token for user {}", identity.username);
    // Create a token
    let token = identifier
        .vault
        .create_api_token_with_oidc(&identity, &oidc_token)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create token: {}", e),
            )
        })?;
    tracing::info!("Created API token for user {}", identity.username);
    Ok(Json(token))
}

// Endpoint that requires token authentication
async fn token_authenticated(identity: AiclIdentity) -> impl IntoResponse {
    format!("API access granted for {}!", identity.username)
}

// Start the service and return its JoinHandle
async fn start_service() -> JoinHandle<()> {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").ok().unwrap();
    let pool = PgPoolOptions::new()
            .connect(&database_url)
            .await.expect("Can't connect to the database");

    tracing::info!("Starting OIDC application for tests");
    let identifier = AiclIdentifier::from_env(pool)
        .await
        .expect("Failed to initialize AiclIdentifier");

    // Start the service in a background task
    tokio::spawn(run(identifier))
}

// Separate tests for each authentication flow scenario
#[tracing_test::traced_test]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_end_to_end_access() {
    // Initialize service and get guard that will decrement reference count when dropped
    let service = start_service().await;

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

    assert!(
        body.contains("captain1"),
        "Response should contain username"
    );
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
    let token =
        serde_json::from_str::<ApiToken>(&body).expect("Failed to parse claims from response");
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
        "API request with token should succeed, got: {}",
        api_response.status()
    );

    // Check the response body contains the expected content
    let body = api_response
        .text()
        .await
        .expect("Failed to get response body");
    assert!(
        body.contains("API access granted for captain1"),
        "Response should indicate successful API access, got: {}",
        body
    );

    tracing::info!("✅ Token authentication test passed");

    service.abort();
}

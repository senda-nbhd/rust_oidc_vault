use crate::{
    oidc::keycloak::{KeyCloakToken, TOKEN_KEY},
    vault::ApiToken,
    AiclIdentity
};
use futures_util::future::join_all;
use openidconnect::{
    ClientId, ClientSecret,
    IssuerUrl, OAuth2TokenResponse, ResourceOwnerPassword, ResourceOwnerUsername, 
    TokenResponse,
};
use reqwest::{Client, header::AUTHORIZATION};
use serde::Serialize;
use tracing::info;

use crate::oidc::keycloak::{KeycloakMetadata, KeycloakOidcClient};

/// User credentials for testing
#[derive(Debug, Clone)]
pub struct TestUser {
    pub username: String,
    pub password: String,
    pub expected_team: Option<String>,
    pub expected_role: &'static str,
}

/// Represents authenticated session information
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub identity: AiclIdentity,
    pub api_token: Option<ApiToken>,
    pub client: Client,
    //pub token: Option<KeyCloakToken>,
}

impl AuthSession {
    /// Create a new HTTP request with the API token
    pub fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.client.request(method, url);
        
        if let Some(token) = &self.api_token {
            req = req.header(AUTHORIZATION, format!("Bearer {}", token.client_token));
        }
        
        req
    }

    /// Perform a GET request with authentication
    pub async fn get(&self, url: &str) -> reqwest::Result<reqwest::Response> {
        self.request(reqwest::Method::GET, url).send().await
    }

    /// Perform a POST request with authentication
    pub async fn post(&self, url: &str, json: Option<impl Serialize>) -> reqwest::Result<reqwest::Response> {
        let req = self.request(reqwest::Method::POST, url);
        
        if let Some(body) = json {
            req.json(&body).send().await
        } else {
            req.send().await
        }
    }
}

/// Authentication test utilities
pub struct AuthTestUtils {
    app_url: String,
    keycloak_url: String,
    client_id: String,
    client_secret: Option<String>,
    realm: String,
}

impl AuthTestUtils {
    /// Create a new instance of AuthTestUtils
    pub fn new(app_url: &str) -> Self {
        Self {
            app_url: app_url.to_string(),
            keycloak_url: "http://localhost:8080".to_string(),
            client_id: "rust-app".to_string(),
            client_secret: Some("test-client-secret".to_string()),
            realm: "app-realm".to_string(),
        }
    }
    
    /// Customize the Keycloak URL
    pub fn with_keycloak_url(mut self, url: &str) -> Self {
        self.keycloak_url = url.to_string();
        self
    }
    
    /// Customize the client ID
    pub fn with_client_id(mut self, client_id: &str) -> Self {
        self.client_id = client_id.to_string();
        self
    }
    
    /// Customize the client secret
    pub fn with_client_secret(mut self, client_secret: Option<String>) -> Self {
        self.client_secret = client_secret;
        self
    }
    
    /// Customize the realm
    pub fn with_realm(mut self, realm: &str) -> Self {
        self.realm = realm.to_string();
        self
    }
    
    /// Get OIDC client for direct authentication
    async fn get_oidc_client(&self) -> Result<KeycloakOidcClient, anyhow::Error> {
        let async_http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        // Create the OpenID Connect client
        let issuer_url = IssuerUrl::new(
            format!("{}/realms/{}", self.keycloak_url, self.realm)
        )?;
        
        // Discover the provider metadata
        let provider_metadata = KeycloakMetadata::discover_async(
            issuer_url.clone(), &async_http_client
        ).await?;
        
        // Set up the client
        let client = KeycloakOidcClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.client_id.clone()),
            self.client_secret.as_ref().map(|s| ClientSecret::new(s.clone()))
        );
        
        Ok(client)
    }
    
    /// Authenticate a user using the OIDC Resource Owner Password flow
    pub async fn authenticate_user(&self, user: &TestUser) -> Result<AuthSession, anyhow::Error> {
        info!("Authenticating user: {}", user.username);
        
        // Step 1: Get OIDC client
        let client = self.get_oidc_client().await?;
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        // Step 2: Perform Resource Owner Password Credentials flow
        let token_response = client
            .exchange_password(
                &ResourceOwnerUsername::new(user.username.clone()),
                &ResourceOwnerPassword::new(user.password.clone())
            )?
            .request_async(&http_client)
            .await?;
        // Create the KeyCloakToken from the token response
        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow::anyhow!("No ID token in response"))?
            .clone();
            
        let access_token = token_response.access_token().clone();
        
        let keycloak_token = KeyCloakToken {
            id_token,
            access_token,
        };
            
        // Step 4: Get the user identity from the application
        // First, we need to set up a client that includes the tokens
        let identity_url = format!("{}/foo", self.app_url);
        let mut req = http_client.get(&identity_url);
        
        // Add the ID token as a cookie (this would normally be done by the login flow)
        req = req.header(
            "Cookie", 
            format!("{}={}; Path=/; HttpOnly", TOKEN_KEY, serde_json::to_string(&keycloak_token)?)
        );
        
        // Execute the request
        let identity_response = req.send().await?;
        
        if !identity_response.status().is_success() {
            let error_text = identity_response.text().await?;
            return Err(anyhow::anyhow!("Failed to get identity info: {}", error_text));
        }
        
        // Parse the identity from the response
        let identity: AiclIdentity = identity_response.json().await?;
        
        // Step 5: Validate identity against expectations
        if let Some(expected_team) = &user.expected_team {
            if let Some(team) = &identity.team {
                if &team.name != expected_team {
                    return Err(anyhow::anyhow!(
                        "Team mismatch: expected {}, got {}", 
                        expected_team, 
                        team.name
                    ));
                }
            } else if !expected_team.is_empty() {
                return Err(anyhow::anyhow!("Expected team not found in identity"));
            }
        }
        
        if !user.expected_role.is_empty() && identity.role.as_str() != user.expected_role {
            return Err(anyhow::anyhow!(
                "Role mismatch: expected {}, got {}", 
                user.expected_role, 
                identity.role.as_str()
            ));
        }
        
        // Step 6: Get an API token
        let mut token_req = http_client.get(&format!("{}/token", self.app_url));
        
        // Add the ID token as a cookie
        token_req = token_req.header(
            "Cookie", 
            format!("{}={}; Path=/; HttpOnly", TOKEN_KEY, serde_json::to_string(&keycloak_token)?)
        );
        
        let token_response = token_req.send().await?;
        
        if !token_response.status().is_success() {
            let error_text = token_response.text().await?;
            return Err(anyhow::anyhow!("Failed to get API token: {}", error_text));
        }
        
        let api_token: ApiToken = token_response.json().await?;
        info!("Successfully acquired API token for user {}", user.username);
        
        Ok(AuthSession {
            identity,
            api_token: Some(api_token),
            client: http_client,
            //token: Some(keycloak_token),
        })
    }
    
    /// Create authenticated sessions for multiple users in parallel
    pub async fn authenticate_users(&self, users: &[TestUser]) -> Vec<Result<AuthSession, anyhow::Error>> {
        
        let futures = users.iter()
            .map(|user| self.authenticate_user(user))
            .collect::<Vec<_>>();
            
        join_all(futures).await
    }
    
    /// Create an authenticated session with API token for a specific user
    pub async fn create_session_with_api_token(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthSession, anyhow::Error> {
        let user = TestUser {
            username: username.to_string(),
            password: password.to_string(),
            expected_team: None,
            expected_role: "",
        };
        
        self.authenticate_user(&user).await
    }
    
    /// Create test users for different roles
    pub fn create_test_users() -> Vec<TestUser> {
        vec![
            // Team 1
            TestUser {
                username: "captain1".to_string(),
                password: "captain".to_string(),
                expected_team: Some("Team1".to_string()),
                expected_role: "captain",
            },
            TestUser {
                username: "member1".to_string(),
                password: "member".to_string(),
                expected_team: Some("Team1".to_string()),
                expected_role: "student",
            },
            TestUser {
                username: "viewer1".to_string(),
                password: "viewer".to_string(),
                expected_team: Some("Team1".to_string()),
                expected_role: "spectator",
            },
            
            // Team 2
            TestUser {
                username: "captain2".to_string(),
                password: "captain".to_string(),
                expected_team: Some("Team2".to_string()),
                expected_role: "captain",
            },
            
            // Advisors
            TestUser {
                username: "advisor1".to_string(),
                password: "admin".to_string(),
                expected_team: None,
                expected_role: "advisor",
            },
            
            // Admin
            TestUser {
                username: "admin".to_string(),
                password: "admin".to_string(),
                expected_team: None,
                expected_role: "admin",
            },
        ]
    }
    
    /// Get an API token directly without needing the complete session flow
    pub async fn get_api_token_direct(
        &self,
        username: &str,
        password: &str,
    ) -> Result<ApiToken, anyhow::Error> {
        // First, authenticate with OIDC
        let session = self.create_session_with_api_token(username, password).await?;
        
        // Return the API token
        session.api_token.ok_or_else(|| anyhow::anyhow!("No API token found in session"))
    }

    pub async fn revoke_token(&self, _token: &str) -> Result<(), anyhow::Error> {
        // To do: make this revoke
        Ok(())
    }
}

/// Programmatic API client for the test application that uses API tokens
pub struct TestApiClient {
    client: Client,
    base_url: String,
    auth_token: Option<String>,
}

impl TestApiClient {
    /// Create a new TestApiClient
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
            auth_token: None,
        }
    }
    
    /// Set the authentication token
    pub fn with_token(mut self, token: &str) -> Self {
        self.auth_token = Some(token.to_string());
        self
    }
    
    /// Make a request with optional authentication
    pub async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<impl Serialize>,
    ) -> reqwest::Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.request(method, &url);
        
        if let Some(token) = &self.auth_token {
            req = req.header(AUTHORIZATION, format!("Bearer {}", token));
        }
        
        if let Some(json_body) = body {
            req = req.json(&json_body);
        }
        
        req.send().await
    }
    
    /// Perform a GET request
    pub async fn get(&self, path: &str) -> reqwest::Result<reqwest::Response> {
        self.request(reqwest::Method::GET, path, None::<()>).await
    }
    
    /// Perform a POST request with JSON body
    pub async fn post<T: Serialize>(&self, path: &str, body: T) -> reqwest::Result<reqwest::Response> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }
}
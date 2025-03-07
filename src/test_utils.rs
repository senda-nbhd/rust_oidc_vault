use std::sync::Arc;

use crate::{
    idp::admin::IdpAdmin, oidc::keycloak::{KeyCloakToken, TOKEN_KEY}, vault::{ApiToken, VaultService}, AiclIdentity
};

use anyhow::Context;
use futures_util::future::join_all;
use openidconnect::{
    ClientId, ClientSecret,
    IssuerUrl, OAuth2TokenResponse, ResourceOwnerPassword, ResourceOwnerUsername, 
    TokenResponse,
};
use reqwest::{Client, header::AUTHORIZATION, cookie::Jar};
use serde::{Deserialize, Serialize};
use tracing::info;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use url::Url;
use uuid::Uuid;

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
#[derive(Debug)]
pub struct AuthSession {
    pub identity: AiclIdentity,
    pub api_token: Option<ApiToken>,
    pub client: Client,
    pub token: Option<KeyCloakToken>,
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
    pub app_url: String,
    pub keycloak_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub realm: String,
    pub idp: Arc<IdpAdmin>,
    pub vault: Arc<VaultService>,
}

impl AuthTestUtils {
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
        
        let cookie_provider = Arc::new(Jar::default());
        // Step 1: Get OIDC client
        let client = self.get_oidc_client().await?;
        let http_client = reqwest::ClientBuilder::new()
            .cookie_provider(cookie_provider.clone())
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .unwrap();
        // Step 2: Perform Resource Owner Password Credentials flow
        let token_response = client
            .exchange_password(
                &ResourceOwnerUsername::new(user.username.clone()),
                &ResourceOwnerPassword::new(user.password.clone())
            )?
            .add_scope(openidconnect::Scope::new("openid".to_string()))
            // Add additional scopes if needed
            .add_scope(openidconnect::Scope::new("profile".to_string()))
            .add_scope(openidconnect::Scope::new("email".to_string()))
            .request_async(&http_client)
            .await.with_context(|| "Failed to request token")?;
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

        let user_id = decode_token_claims(&keycloak_token.id_token.to_string()).with_context(|| "unable to decode the sub claim")?;
        // Step 4: Fetch the user's identity from KeyCloak
        let identity = self.idp.get_domain_user(user_id).await.with_context(|| "Failed to fetch user identity from KeyCloak")?;
        
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
        let api_token = match identity.role {
            crate::Role::Admin => Some(self.vault.create_api_token_with_oidc(&identity, &keycloak_token).await?),
            crate::Role::Captain => Some(self.vault.create_api_token_with_oidc(&identity, &keycloak_token).await?),
            crate::Role::Advisor => None,
            crate::Role::Student => None,
            crate::Role::Spectator => None,
        };

        Ok(AuthSession {
            identity,
            api_token,
            client: http_client,
            token: Some(keycloak_token),
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

#[derive(Debug, Clone, Deserialize)]
struct Claims {
    sub: Uuid,
}

fn decode_token_claims(id_token_str: &str) -> Result<Uuid, anyhow::Error> {
    // Split the token into parts
    let parts: Vec<&str> = id_token_str.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!("Invalid JWT format"));
    }
    
    // Decode the base64
    let claims: Claims = match base64_decode(parts[1]) {
        Ok(p) => serde_json::from_str(&p).unwrap(),
        Err(_) => anyhow::bail!("Failed to decode payload")
    };

    Ok(claims.sub)
}

fn base64_decode(input: &str) -> Result<String, String> {
    let padded = match input.len() % 4 {
        0 => input.to_string(),
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };
    
    let decoded = URL_SAFE.decode(&padded)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    
    String::from_utf8(decoded)
        .map_err(|e| format!("UTF-8 decode error: {}", e))
}
use std::{borrow::Cow, sync::Arc};

use axum::http::{request, Uri};
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClientAuthMethod,
        CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm,
        CoreResponseMode, CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
        CoreSubjectIdentifierType, CoreTokenIntrospectionResponse, CoreTokenType,
    }, AccessToken, Client, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims, EmptyAdditionalProviderMetadata, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdToken, IdTokenFields, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeVerifier, ProviderMetadata, RedirectUrl, RefreshToken, StandardErrorResponse, StandardTokenResponse, TokenResponse
};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use url::Url;
use uuid::Uuid;

use crate::idp::{admin::IdpAdmin, keycloak::KeycloakProvider};

use super::ext::OidcError;

pub type KeycloakMetadata = ProviderMetadata<
    EmptyAdditionalProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

pub type KeycloakTokenResponse = StandardTokenResponse<
    IdTokenFields<
        EmptyAdditionalClaims,
        EmptyExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    CoreTokenType,
>;

pub type KeycloakOidcClient = Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    KeycloakTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub type KeycloakToken = IdToken<
    EmptyAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

#[derive(Serialize, Deserialize, Debug)]
pub struct AiclOidcSession {
    nonce: Nonce,
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyCloakToken {
    id_token: IdToken<
        EmptyAdditionalClaims,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    access_token: AccessToken,
}

pub const SESSION_KEY: &str = "aicl-oidc-keycloak-session";
pub const TOKEN_KEY: &str = "aicl-oidc-keycloak-token";
pub const REFRESH_KEY: &str = "aicl-oidc-keycloak-refresh";

pub struct KeycloakOidcBuilder {
    application_base_url: String,
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    scopes: Vec<String>,
    keycloak_idp: Arc<IdpAdmin<KeycloakProvider>>,
}

impl KeycloakOidcBuilder {
    pub fn new(
        keycloak_idp: Arc<IdpAdmin<KeycloakProvider>>,
        application_base_url: String, issuer: String, client_id: String) -> Self {
        Self {
            application_base_url,
            issuer,
            client_id,
            client_secret: None,
            scopes: Vec::new(),
            keycloak_idp,
        }
    }

    pub fn with_client_secret(mut self, client_secret: Option<String>) -> Self {
        self.client_secret = client_secret;
        self
    }
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    pub async fn build(self) -> anyhow::Result<KeycloakOidcProvider> {
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let issuer_url = IssuerUrl::new(self.issuer)?;
        let provider_metadata = KeycloakMetadata::discover_async(issuer_url, &http_client).await?;
        let client_id = ClientId::new(self.client_id.clone());
        let client_secret = self.client_secret.map(ClientSecret::new);
        let oidc_client =
            KeycloakOidcClient::from_provider_metadata(provider_metadata, client_id, client_secret);
        let application_base_url = Url::parse(&self.application_base_url)?;
        Ok(KeycloakOidcProvider {
            application_base_url,
            http_client,
            oidc_client,
            scopes: self.scopes,
            keycloak_idp: self.keycloak_idp,
        })
    }
}

pub struct KeycloakOidcProvider {
    application_base_url: Url,
    oidc_client: KeycloakOidcClient,
    http_client: reqwest::Client,
    scopes: Vec<String>,
    keycloak_idp: Arc<IdpAdmin<KeycloakProvider>>,
}

impl KeycloakOidcProvider {
    pub fn uri_to_url(&self, uri: &Uri) -> Result<Url, url::ParseError> {
        // Check if the URI has a scheme
        if uri.scheme().is_some() {
            // Already absolute, convert directly
            Url::parse(&uri.to_string())
        } else {        
            // If the URI has an authority part but no scheme, add the scheme
            if uri.authority().is_some() {
                // It has authority but no scheme, add scheme and parse
                let uri_str = format!("http://{}", uri.to_string());
                Url::parse(&uri_str)
            } else {
                // Fully relative, join with base URL
                let path_and_query = match uri.path_and_query() {
                    Some(pq) => pq.as_str(),
                    None => "/", // Default to root path if not specified
                };
                
                self.application_base_url.join(path_and_query)
            }
        }
    }

    pub async fn authenticate(&self, parts: &mut request::Parts, session: &Session) -> Result<(), OidcError> {

        let login_session: Option<AiclOidcSession> = session.get(SESSION_KEY).await.map_err(|e| {
            OidcError::SessionError(format!("Failed to get login session from session store: {}", e))
        })?;
    
        let oidc_token: Option<KeyCloakToken> = session.get(TOKEN_KEY).await.map_err(|e| {
            OidcError::SessionError(format!("Failed to get token from session store: {}", e))
        })?;

        let oidc_refresh: Option<RefreshToken> = session.get(REFRESH_KEY).await.map_err(|e| {
            OidcError::SessionError(format!("Failed to get token from session store: {}", e))
        })?;

        // Clone the client, change the redirect URL to the correct one and then insert it into the extensions

        match (login_session, oidc_token, oidc_refresh) {
            (None, _, _) => {
                tracing::debug!("We have no session, no identity, and no refresh token");
                // We have no session, so we can't do anything with the session.
            },
            (Some(_), None, None) => {
                tracing::debug!("We have a session, but no identity token or refresh token");
                // We have no identity token or refresh token, so we can't do anything with the session.
            },
            (Some(login_session), None, Some(refresh_token)) => {
                tracing::debug!("We have a session, no identity token, and a refresh token. Refreshing and aquireing a new token");
                todo!("Implement token refresh logic here")
            },
            (Some(login_session), Some(id_token), _) => {
                tracing::debug!("We have a session and identity token");
                let verified_claims = id_token
                    .id_token
                    .claims(&self.oidc_client.id_token_verifier(), &login_session.nonce)
                    .unwrap();
                
                let user_id = verified_claims.subject().parse::<Uuid>().map_err(|e| {
                    OidcError::ValidationError(format!("Invalid user ID in token: {}", e))
                })?;
                
                // Get user from IdpAdmin
                match self.keycloak_idp.get_domain_user(user_id).await {
                    Ok(identity) => {
                        // Insert the AiclIdentity into the request extensions
                        parts.extensions.insert(identity);
                    },
                    Err(e) => {
                        // Log the error but don't fail authentication - the OidcClaims are still valid
                        tracing::error!("Failed to get user from IdP: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn handle_callback(&self, 
        code: &str, 
        state: &str, 
        session: &Session, 
        redirect_uri: &Uri
    ) -> Result<(), OidcError> {
        // Get the stored OIDC session
        let oidc_session: Option<AiclOidcSession> = session.get(SESSION_KEY).await.map_err(|e| {
            OidcError::SessionError(format!("Failed to get session data: {}", e))
        })?;
        
        let oidc_session = match oidc_session {
            Some(session) => session,
            None => return Err(OidcError::AuthenticationError("No active authentication session".to_string())),
        };
        
        // Verify the CSRF token
        if state != oidc_session.csrf_token.secret() {
            return Err(OidcError::ValidationError("CSRF token mismatch".to_string()));
        }
        let redirect_url = self.uri_to_url(redirect_uri).unwrap();

        // Exchange the authorization code for tokens
        let token_response = self.oidc_client
            .exchange_code(openidconnect::AuthorizationCode::new(code.to_string())).unwrap()
            .set_redirect_uri(
                Cow::Owned(openidconnect::RedirectUrl::from_url(redirect_url))
            )
            .set_pkce_verifier(oidc_session.pkce_verifier)
            .request_async(&self.http_client)
            .await
            .map_err(|e| OidcError::AuthenticationError(format!("Token exchange failed: {}", e)))?;
        
        // Extract the tokens
        let id_token = token_response.id_token()
            .ok_or_else(|| OidcError::AuthenticationError("No ID token in response".to_string()))?
            .clone();
        
        let access_token = token_response.access_token().clone();
        
        // Store the tokens in the session
        let token = KeyCloakToken {
            id_token,
            access_token,
        };
        
        session.insert(TOKEN_KEY, token).await.map_err(|e| {
            OidcError::SessionError(format!("Failed to save token data: {}", e))
        })?;
        
        Ok(())
    }
    
    pub async fn start_auth(&self, session: &Session, redirect_uri: &Uri) -> Result<axum::http::Uri, OidcError> {
        // Generate PKCE code verifier and challenge
        let (pkce_challenge, pkce_verifier) = openidconnect::PkceCodeChallenge::new_random_sha256();
        
        // Calculate the redirect URI
        let redirect_uri = self.uri_to_url(redirect_uri).unwrap();
        // Build the authorization URI
        let auth_url = self.oidc_client
            .authorize_url(
                openidconnect::AuthenticationFlow::<CoreResponseType>::AuthorizationCode, 
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_redirect_uri(
                Cow::Owned(openidconnect::RedirectUrl::from_url(redirect_uri))
            )
            .set_pkce_challenge(pkce_challenge);
        
        // Add additional scopes if configured
        let auth_url = self.scopes.iter().fold(auth_url, |url, scope| {
            url.add_scope(openidconnect::Scope::new(scope.clone()))
        });
        
        // Build the final URL
        let (auth_url, csrf_token, nonce) = auth_url.url();
        
        // Store the CSRF token, nonce, and PKCE verifier in the session
        let oidc_session = AiclOidcSession {
            csrf_token,
            nonce,
            pkce_verifier,
        };
        
        session.insert(SESSION_KEY, oidc_session).await.map_err(|e| {
            OidcError::SessionError(format!("Failed to save session data: {}", e))
        })?;
        
        // Return the authorization URL
        Ok(axum::http::Uri::from_maybe_shared(auth_url.to_string())
            .map_err(|e| OidcError::Unknown(format!("Invalid auth URL: {}", e)))?)
    }

    pub async fn logout(&self, session: &Session) -> Result<axum::http::Uri, OidcError> {
        // Get token before removing it (we might need the ID token for backchannel logout)
        let token: Option<KeyCloakToken> = session.get(TOKEN_KEY).await.map_err(|e| {
            OidcError::SessionError(format!("Failed to get token from session: {}", e))
        })?;
        
        // Clear OIDC session data
        session.remove::<AiclOidcSession>(SESSION_KEY).await.map_err(|e| {
            OidcError::SessionError(format!("Failed to remove session data: {}", e))
        })?;
        
        session.remove::<KeyCloakToken>(TOKEN_KEY).await.map_err(|e| {
            OidcError::SessionError(format!("Failed to remove token data: {}", e))
        })?;
        
        // Create a redirect URL to the Keycloak end session endpoint if available
        if let Some(token) = token {
            // Build the end_session_endpoint URL with ID token hint and post_logout_redirect_uri
            todo!("The 'EmptyAdditionalProviderMetadata' should be replaced with metadata that indicates where the end_session_endpoint is located. This could be done by adding additional provider metadata in the KeycloakOidcProvider struct.");
        }
        
        // If we don't have a token or end_session_endpoint, just return to the application root
        Ok(axum::http::Uri::from_static("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_absolute_uri() {
        let uri: Uri = "https://example.com/path?query=value".parse().unwrap();
        let url = uri_to_url(&uri, None).unwrap();
        assert_eq!(url.as_str(), "https://example.com/path?query=value");
    }
    
    #[test]
    fn test_relative_uri_with_base() {
        let uri: Uri = "/path?query=value".parse().unwrap();
        let url = uri_to_url(&uri, Some("https://example.com")).unwrap();
        assert_eq!(url.as_str(), "https://example.com/path?query=value");
    }
    
    #[test]
    fn test_authority_only_uri() {
        let uri: Uri = "example.com/path".parse().unwrap();
        let url = uri_to_url(&uri, None).unwrap();
        assert_eq!(url.as_str(), "http://example.com/path");
    }
    
    #[test]
    fn test_path_only_uri() {
        let uri: Uri = "/some/path".parse().unwrap();
        let url = uri_to_url(&uri, Some("https://api.example.com")).unwrap();
        assert_eq!(url.as_str(), "https://api.example.com/some/path");
    }
    
    #[test]
    fn test_empty_uri() {
        let uri: Uri = "".parse().unwrap();
        let url = uri_to_url(&uri, Some("https://example.com")).unwrap();
        assert_eq!(url.as_str(), "https://example.com/");
    }
}
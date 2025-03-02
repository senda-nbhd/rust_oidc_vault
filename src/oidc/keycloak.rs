use std::collections::HashMap;

use async_trait::async_trait;
use axum::http::{request::{self, Parts}, response};
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClientAuthMethod,
        CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm,
        CoreResponseMode, CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
        CoreSubjectIdentifierType, CoreTokenIntrospectionResponse, CoreTokenType,
    },
    AccessToken, Client, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims,
    EmptyAdditionalProviderMetadata, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IdToken, IdTokenFields, IssuerUrl, Nonce, PkceCodeVerifier, ProviderMetadata,
    StandardErrorResponse, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

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

pub type KeycloakClient = Client<
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

pub struct KeycloakOidcBuilder {
    application_base_url: String,
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    scopes: Vec<String>,
}

pub struct KeycloakOidcClient {
    client: KeycloakClient,
}

impl KeycloakOidcBuilder {
    pub fn new(application_base_url: String, issuer: String, client_id: String) -> Self {
        Self {
            application_base_url,
            issuer,
            client_id,
            client_secret: None,
            scopes: Vec::new(),
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
        let client =
            KeycloakClient::from_provider_metadata(provider_metadata, client_id, client_secret);

        Ok(KeycloakOidcProvider {
            application_base_url: self.application_base_url,
            client,
            client_id: self.client_id,
            scopes: self.scopes,
        })
    }
}

pub struct KeycloakOidcProvider {
    application_base_url: String,
    client: KeycloakClient,
    client_id: String,
    scopes: Vec<String>,
}

impl KeycloakOidcProvider {
    async fn authenticate(&self, parts: &mut request::Parts, session: &Session) -> Result<(), OidcError> {
        let login_session: Option<AiclOidcSession> = session.get(SESSION_KEY).await.unwrap();

        // Clone the client, change the redirect URL to the correct one and then insert it into the extensions

        let oidc_token: Option<KeyCloakToken> = session.get(TOKEN_KEY).await.unwrap();
        match (login_session, oidc_token) {
            (None, _) => {}
            (Some(login_session), None) => {
                // Look for the refresh token in the session and then refresh the token.
            }
            (Some(login_session), Some(id_token)) => {
                let verified_claims = id_token
                    .id_token
                    .claims(&self.client.id_token_verifier(), &login_session.nonce)
                    .unwrap();
                
                // Covert to AICL identity and insert into the parts. 
            }
        }

        todo!()
    }

    async fn logout(&self, response: &mut response::Parts) -> Result<(), OidcError> {
        todo!("Delete the session tokens and logout")
    }
}

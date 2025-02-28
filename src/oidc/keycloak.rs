use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClientAuthMethod,
        CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm,
        CoreResponseMode, CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
        CoreSubjectIdentifierType, CoreTokenIntrospectionResponse, CoreTokenType,
    }, Client, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims, EmptyAdditionalProviderMetadata, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields, IssuerUrl, Nonce, PkceCodeVerifier, ProviderMetadata, StandardErrorResponse, StandardTokenResponse
};
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize, Debug)]
pub struct AiclOidcSession {
    nonce: Nonce,
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
}

pub const SESSION_KEY: &str = "aicl-oidc-keycloak";

pub struct KeycloakOidcBuilder {
    application_base_url: String,
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    scopes: Vec<String>,
}

pub struct KeycloakOidcClient {
    application_base_url: String,
    client: KeycloakClient,
}

impl KeycloakOidcBuilder {
    pub fn new(application_base_url: String, issuer: String, client_id: String) -> Self {
        Self {
            application_base_url,
            issuer,
            client_id,
            client_secret: None,
            scopes: vec!["openid".to_string()],
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

    pub async fn build(self) -> anyhow::Result<KeycloakOidcClient> {
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let issuer_url = IssuerUrl::new(self.issuer)?;
        let provider_metadata = KeycloakMetadata::discover_async(issuer_url, &http_client).await?;
        let client_id = ClientId::new(self.client_id);
        let client_secret = self.client_secret.map(ClientSecret::new); 
        let client = KeycloakClient::from_provider_metadata(provider_metadata, client_id, client_secret);

        Ok(KeycloakOidcClient { application_base_url: self.application_base_url, client })
    }
}

use std::sync::Arc;

use axum::{extract::{FromRef, FromRequestParts}, http::request::Parts};
use axum_oidc::{error::ExtractorError, EmptyAdditionalClaims, OidcClaims};
use reqwest::StatusCode;

use crate::{idp::admin::IdpAdmin, AiclIdentity};

/// Extractor for AiclIdentity
pub struct Identity(pub AiclIdentity);

impl<S> FromRequestParts<S> for Identity
where
    Arc<IdpAdmin>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {

        match parts.extensions.get::<Result<OidcClaims<EmptyAdditionalClaims>, ExtractorError>>() {
            Some(Ok(claims)) => {
                let idp_admin = Arc::from_ref(state);
                // Extract user ID from subject
                let user_id = claims.subject().parse()
                    .map_err(|e| {
                        tracing::error!("Failed to parse user id: {}", e);
                        (StatusCode::BAD_REQUEST, format!("Invalid user ID: {}", e))
                    })?;
                
                // Get user from IdpAdmin
                let user = idp_admin.get_user(user_id).await
                    .map_err(|e| {
                        tracing::error!("Failed to get user idp: {}", e);
                        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get user: {}", e))
                    })?;
                
                // Convert to AiclIdentity
                let identity = idp_admin.to_domain_user(&user).await
                    .map_err(|e| {
                        tracing::error!("Failed to convert user: {}", e);
                        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to convert user: {}", e))
                    })?;
                Ok(Identity(identity))
            },
            Some(Err(e)) => Err((StatusCode::UNAUTHORIZED, format!("Not authenticated: {}", e))),
            None => Err((StatusCode::UNAUTHORIZED, format!("Missing Authentication"))),
        }
        
    }
}

/// Optional AiclIdentity extractor that doesn't fail if user is not authenticated
pub struct OptionalIdentity(pub Option<AiclIdentity>);

impl<S> FromRequestParts<S> for OptionalIdentity
where
    Arc<IdpAdmin>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Try to extract OIDC claims, but don't fail if they're not there
        match parts.extensions.get::<Result<OidcClaims<EmptyAdditionalClaims>, ExtractorError>>() {
            Some(Ok(claims)) => {
                let idp_admin = Arc::from_ref(state);
                // Extract user ID from subject
                let user_id = match claims.subject().parse() {
                    Ok(id) => id,
                    Err(error) => {
                        tracing::error!("Failed to parse user id: {}", error);
                        return Ok(OptionalIdentity(None));
                    }
                };
                
                // Get user from IdpAdmin
                let user = match idp_admin.get_user(user_id).await {
                    Ok(user) => user,
                    Err(e) => {
                        tracing::error!("Failed to get user idp: {}", e);
                        return Ok(OptionalIdentity(None));
                    }
                };
                
                // Convert to AiclIdentity
                let identity = match idp_admin.to_domain_user(&user).await {
                    Ok(user) => user,
                    Err(e) => {
                        tracing::error!("Failed to convert user: {}", e);
                        return Ok(OptionalIdentity(None));
                    }
                };
                Ok(OptionalIdentity(Some(identity)))
            },
            Some(Err(_)) => Ok(OptionalIdentity(None)),
            None => Ok(OptionalIdentity(None)),
        }
    }
}

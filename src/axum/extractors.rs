use std::sync::Arc;

use axum::{extract::FromRequestParts, http::request::Parts};
use axum_oidc::{error::ExtractorError, EmptyAdditionalClaims, OidcClaims};
use reqwest::StatusCode;

use crate::{idp::admin::IdpAdmin, AiclIdentity};

impl<S> FromRequestParts<S> for AiclIdentity
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let idp_admin = parts.extensions.get::<Arc<IdpAdmin>>().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "IdpAdmin not found".to_string(),
        ))?;

        match parts.extensions.get::<OidcClaims<EmptyAdditionalClaims>>() {
            Some(claims) => {
                // Extract user ID from subject
                let user_id = claims.subject().parse().map_err(|e| {
                    tracing::error!("Failed to parse user id: {}", e);
                    (StatusCode::BAD_REQUEST, format!("Invalid user ID: {}", e))
                })?;

                // Get user from IdpAdmin
                let user = idp_admin.get_user(user_id).await.map_err(|e| {
                    tracing::error!("Failed to get user idp: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to get user: {}", e),
                    )
                })?;

                // Convert to AiclIdentity
                let identity = idp_admin.to_domain_user(&user).await.map_err(|e| {
                    tracing::error!("Failed to convert user: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to convert user: {}", e),
                    )
                })?;
                Ok(identity)
            }
            None => Err((StatusCode::UNAUTHORIZED, format!("Missing Authentication"))),
        }
    }
}

/// Optional AiclIdentity extractor that doesn't fail if user is not authenticated
pub struct OptionalIdentity(pub Option<AiclIdentity>);

impl<S> FromRequestParts<S> for OptionalIdentity
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let idp_admin = parts.extensions.get::<Arc<IdpAdmin>>().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "IdpAdmin not found".to_string(),
        ))?;
        // Try to extract OIDC claims, but don't fail if they're not there
        match parts.extensions.get::<OidcClaims<EmptyAdditionalClaims>>() {
            Some(claims) => {
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
            }
            None => Ok(OptionalIdentity(None)),
        }
    }
}

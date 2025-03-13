use axum::{extract::FromRequestParts, http::request::Parts};
use reqwest::StatusCode;

use crate::{AiclIdentifier, AiclIdentity};
//Comments here

impl<S> FromRequestParts<S> for AiclIdentity
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AiclIdentity>()
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "AiclIdentity not found".to_string(),
            ))
            .cloned()
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
        parts.extensions.get::<AiclIdentity>().map_or_else(
            || Ok(OptionalIdentity(None)),
            |id| Ok(OptionalIdentity(Some(id.clone()))),
        )
    }
}

impl<S> FromRequestParts<S> for AiclIdentifier
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AiclIdentifier>()
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "AiclIdentifier not found".to_string(),
            ))
            .cloned()
    }
}

use axum::{error_handling::HandleErrorLayer, http::Uri, response::IntoResponse};
use axum_oidc::{error::MiddlewareError, EmptyAdditionalClaims, OidcAuthLayer};
use openidconnect::RequestTokenError;
use serde_json::Value;
use tower::ServiceBuilder;



async fn oidc_auth_service(
    app_url: String,
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
) -> () {
    ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|e: MiddlewareError| async {
            match &e {
                MiddlewareError::RequestToken(RequestTokenError::Parse(error, payload)) => {
                    tracing::error!("Failed to parse request token: {:?}", error);
                    let payload_str: Value = serde_json::from_slice(&payload).unwrap();
                    tracing::error!(
                        "Request token payload: {}",
                        serde_json::to_string_pretty(&payload_str).unwrap()
                    );
                }
                err => {
                    tracing::error!("Unhandled error: {:?}", err);
                }
            }
            e.into_response()
        }))
        .layer(
            OidcAuthLayer::<EmptyAdditionalClaims>::discover_client(
                Uri::from_maybe_shared(app_url.clone()).expect("valid APP_URL"),
                issuer,
                client_id,
                client_secret,
                vec![],
            )
            .await
            .unwrap(),
        )
}
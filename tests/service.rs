use std::sync::Arc;

use aicl_oidc::{axum::extractors::OptionalIdentity, idp::admin::IdpAdmin, AiclIdentity};
use axum::{
    error_handling::HandleErrorLayer, http::Uri, response::IntoResponse, routing::get, Router,
};
use axum_oidc::{
    error::MiddlewareError, EmptyAdditionalClaims, OidcClaims, OidcLoginLayer,
    OidcRpInitiatedLogout,
};
use openidconnect::RequestTokenError;
use serde_json::Value;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tower_sessions::{
    cookie::{time::Duration, SameSite},
    Expiry, MemoryStore, SessionManagerLayer,
};

pub async fn run(idp: Arc<IdpAdmin>) {
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(Duration::seconds(120)));

    let oidc_login_service = ServiceBuilder::new()
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
        .layer(OidcLoginLayer::<EmptyAdditionalClaims>::new());

    let oidc_auth_service = ServiceBuilder::new()
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
            idp.oidc_auth_layer("http://localhost:4040".to_string())
                .await
                .expect("Admin idp built"),
        );

    let app: Router<()> = Router::new();

    let app = app
        .route("/foo", get(authenticated))
        .route("/logout", get(logout))
        .layer(oidc_login_service)
        .route("/bar", get(maybe_authenticated))
        .layer(oidc_auth_service)
        .layer(idp.layer())
        .layer(session_layer)
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind("0.0.0.0:4040").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[axum::debug_handler]
async fn authenticated(
    user: AiclIdentity,
    claims: OidcClaims<EmptyAdditionalClaims>,
) -> impl IntoResponse {
    format!(
        "Hello {}, {}",
        claims.subject().as_str(),
        serde_json::to_string_pretty(&user).unwrap()
    )
}

#[axum::debug_handler]
async fn maybe_authenticated(
    OptionalIdentity(maybe_user): OptionalIdentity,
    claims: Result<OidcClaims<EmptyAdditionalClaims>, axum_oidc::error::ExtractorError>,
) -> impl IntoResponse {
    match claims.map(|claims| (maybe_user, claims)) {
        Ok((Some(identity), _)) => {
            format!("Hello {}! You are already logged in.", identity.username)
        }
        Ok((None, claims)) => {
            format!(
                "Hello {}! You are already logged in, but your identity is misconfigured",
                claims.subject().as_str()
            )
        }
        Err(_) => "Hello anon!".to_string(),
    }
}

async fn logout(logout: OidcRpInitiatedLogout) -> impl IntoResponse {
    logout.with_post_logout_redirect(Uri::from_static("/"))
}

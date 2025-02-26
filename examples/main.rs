use axum::{
    error_handling::HandleErrorLayer, http::Uri, response::IntoResponse, routing::get, Router,
};
use axum_oidc::{
    error::MiddlewareError, EmptyAdditionalClaims, OidcAuthLayer, OidcClaims, OidcLoginLayer,
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

use serde::Deserialize;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use vaultrs::{
    client::{VaultClient, VaultClientSettingsBuilder},
    kv2,
};

#[derive(Deserialize, Debug)]
struct OidcConfig {
    app_url: String,
    issuer: String,
    client_id: String,
    client_secret: String,
}

async fn get_oidc_config_from_vault() -> Result<OidcConfig, Box<dyn std::error::Error>> {
    let address = std::env::var("VAULT_ADDR").ok().unwrap();
    let settings = VaultClientSettingsBuilder::default()
        .address(address)
        .build()
        .unwrap();
    let client = VaultClient::new(settings).unwrap();
    let key = "oidc/app-config";
    match kv2::read::<OidcConfig>(&client, "secret", key).await {
        Ok(secret) => {
            tracing::debug!("Got secret {}", key);
            Ok(secret)
        }
        Err(e) => {
            tracing::error!("Failed to get secret {}: {}", key, e);
            Err(e.into())
        }
    }
}

pub async fn run(
    app_url: String,
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
) {
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
            OidcAuthLayer::<EmptyAdditionalClaims>::discover_client(
                Uri::from_maybe_shared(app_url.clone()).expect("valid APP_URL"),
                issuer,
                client_id,
                client_secret,
                vec![],
            )
            .await
            .unwrap(),
        );

    let app = Router::new()
        .route("/foo", get(authenticated))
        .route("/logout", get(logout))
        .layer(oidc_login_service)
        .route("/bar", get(maybe_authenticated))
        .layer(oidc_auth_service)
        .layer(session_layer)
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind("0.0.0.0:4040").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

async fn authenticated(claims: OidcClaims<EmptyAdditionalClaims>) -> impl IntoResponse {
    format!(
        "Hello {}, {}",
        claims.subject().as_str(),
        serde_json::to_string_pretty(&claims.additional_claims()).unwrap()
    )
}

#[axum::debug_handler]
async fn maybe_authenticated(
    claims: Result<OidcClaims<EmptyAdditionalClaims>, axum_oidc::error::ExtractorError>,
) -> impl IntoResponse {
    match claims.map(|claims| (to_domain_user(&claims), claims)) {
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

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            // Default filter if RUST_LOG is not set
            // Set to info level for everything except hyper
            "trace,hyper=off".into()
        }))
        .init();

    // Log application startup
    tracing::info!("Starting OIDC application");
    let config = get_oidc_config_from_vault()
        .await
        .expect("Unable to get config from vault");
    run(
        config.app_url,
        config.issuer,
        config.client_id,
        Some(config.client_secret),
    )
    .await;
}

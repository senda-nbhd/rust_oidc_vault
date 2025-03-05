use aicl_oidc::{
    errors::JsonErrorHandler, oidc::keycloak::{KeyCloakToken, TOKEN_KEY}, vault::ApiToken, AiclIdentifier, AiclIdentity, AppErrorHandler, OptionalIdentity
};
use axum::{response::IntoResponse, routing::{get, post}, Json, Router};
use reqwest::StatusCode;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tower_sessions::{
    cookie::{time::Duration, SameSite}, Expiry, MemoryStore, Session, SessionManagerLayer
};

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub async fn run(identifier: AiclIdentifier, error_handler: AppErrorHandler) {
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(Duration::seconds(120)));

    let app: Router<()> = Router::new();

    let app = app
        .route("/foo", get(authenticated))
        .route_service("/logout", identifier.logout_service())
        .route("/token", get(create_token))
        .route("/api/protected", get(token_authenticated))
        .layer(identifier.login_layer())
        .route("/bar", get(maybe_authenticated))
        .layer(identifier.authenticate_layer())
        .layer(session_layer)
        .layer(identifier.api_token_layer())
        .layer(identifier.identifier_layer())
        .layer(error_handler.layer())
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind("0.0.0.0:4040").await.unwrap();
    tracing::info!("Router built, launcing");
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

async fn authenticated(claims: AiclIdentity) -> impl IntoResponse {
    format!("Hello {}", serde_json::to_string_pretty(&claims).unwrap())
}

#[axum::debug_handler]
async fn maybe_authenticated(OptionalIdentity(maybe_user): OptionalIdentity) -> impl IntoResponse {
    match maybe_user {
        Some(identity) => {
            format!("Hello {}! You are already logged in.", identity.username)
        }
        None => {
            format!("Hello anon!")
        }
    }
}

// Endpoint for creating API tokens
async fn create_token(
    identity: AiclIdentity,
    session: Session,
    identifier: AiclIdentifier,
) -> Result<Json<ApiToken>, (StatusCode, String)> {
    // Get the vault service from the identifier

    // Get the OIDC token from the session
    let oidc_token = session
        .get::<KeyCloakToken>(TOKEN_KEY)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Session error: {}", e),
            )
        })?
        .ok_or((StatusCode::UNAUTHORIZED, "No OIDC token found".to_string()))?;
    tracing::info!("Creating API token for user {}", identity.username);
    // Create a token
    let token = identifier
        .vault
        .create_api_token_with_oidc(&identity, &oidc_token)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create token: {}", e),
            )
        })?;
    tracing::info!("Created API token for user {}", identity.username);
    Ok(Json(token))
}

// Endpoint that requires token authentication
async fn token_authenticated(identity: AiclIdentity) -> impl IntoResponse {
    format!("API access granted for {}!", identity.username)
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
    let identifier = AiclIdentifier::from_env()
        .await
        .expect("Failed to initialize AiclIdentifier");
    let error_handler = AppErrorHandler::new(JsonErrorHandler::default());
    run(identifier, error_handler).await;
}

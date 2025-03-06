use aicl_oidc::{
    errors::JsonErrorHandler, oidc::keycloak::{KeyCloakToken, TOKEN_KEY}, vault::ApiToken, AiclIdentifier, AiclIdentity, AppErrorHandler, OptionalIdentity
};
use axum::{response::IntoResponse, routing::{get, post}, Json, Router};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use reqwest::StatusCode;
use serde_json::{json, Value};
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
        .route("/debug/token", get(debug_token_handler))
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

/// Handler that shows the full token with all claims for debugging purposes
pub async fn debug_token_handler(
    identity: AiclIdentity,
    session: Session,
) -> impl IntoResponse {
    // Get the OIDC token from the session
    let token_result = session.get::<KeyCloakToken>(TOKEN_KEY).await;

    match token_result {
        Ok(Some(token)) => {
            // Get the token string
            let id_token_str = token.id_token.to_string();
            
            // Parse JWT segments (without validation)
            let segments: Vec<&str> = id_token_str.split('.').collect();
            if segments.len() < 2 {
                return Json(json!({
                    "error": "Invalid token format"
                }));
            }
            
            // Decode base64 for header and payload
            let header = match base64_decode(segments[0]) {
                Ok(h) => parse_json(&h),
                Err(_) => json!({"error": "Failed to decode header"})
            };
            
            let payload = match base64_decode(segments[1]) {
                Ok(p) => parse_json(&p),
                Err(_) => json!({"error": "Failed to decode payload"})
            };
            
            // Return token information
            Json(json!({
                "user": {
                    "id": identity.id.to_string(),
                    "username": identity.username,
                    "email": identity.email,
                    "role": identity.role.as_str(),
                },
                "token": {
                    "header": header,
                    "payload": payload,
                    "raw": {
                        "id_token": id_token_str,
                        "access_token": token.access_token.secret()
                    }
                }
            }))
        },
        Ok(None) => Json(json!({
            "error": "No token found in session",
            "user": {
                "id": identity.id.to_string(),
                "username": identity.username,
                "email": identity.email,
                "role": identity.role.as_str(),
            }
        })),
        Err(e) => Json(json!({
            "error": format!("Session error: {}", e)
        }))
    }
}

// Helper function to decode base64 url-safe string
fn base64_decode(input: &str) -> Result<String, String> {
    let padded = match input.len() % 4 {
        0 => input.to_string(),
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };
    
    let decoded = URL_SAFE.decode(&padded)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    
    String::from_utf8(decoded)
        .map_err(|e| format!("UTF-8 decode error: {}", e))
}

// Helper function to parse JSON
fn parse_json(json_str: &str) -> Value {
    serde_json::from_str(json_str).unwrap_or_else(|_| {
        json!({"error": "Failed to parse JSON"})
    })
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

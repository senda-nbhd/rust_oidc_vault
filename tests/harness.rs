use aicl_oidc::{
    errors::JsonErrorHandler,
    oidc::keycloak::{KeyCloakToken, TOKEN_KEY},
    vault::ApiToken,
    AiclIdentifier, AiclIdentity, AppErrorHandler, OptionalIdentity,
};
use axum::{
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use dotenvy::dotenv;
use lazy_static::lazy_static;
use reqwest::StatusCode;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tokio::{net::TcpListener, task::JoinHandle};
use tower_http::trace::TraceLayer;
use tower_sessions::Session;
use tower_sessions::{
    cookie::{time::Duration, SameSite},
    Expiry, MemoryStore, SessionManagerLayer,
};

// Store the service state with reference counting
struct ServiceState {
    handle: Option<JoinHandle<()>>,
    ref_count: AtomicUsize,
}

impl ServiceState {
    fn new() -> Self {
        Self {
            handle: None,
            ref_count: AtomicUsize::new(0),
        }
    }

    fn increment_refs(&self) -> usize {
        self.ref_count.fetch_add(1, Ordering::SeqCst)
    }

    fn decrement_refs(&self) -> usize {
        self.ref_count.fetch_sub(1, Ordering::SeqCst)
    }

    fn get_ref_count(&self) -> usize {
        self.ref_count.load(Ordering::SeqCst)
    }
}

// We'll use this static variable to manage our service instance
lazy_static! {
    static ref SERVICE_STATE: Mutex<ServiceState> = Mutex::new(ServiceState::new());
}

// The base URL of our test application
pub const APP_URL: &str = "http://localhost:4040";

// A guard object that decrements the reference count when dropped
pub struct ServiceGuard;

impl Drop for ServiceGuard {
    fn drop(&mut self) {
        let mut state = SERVICE_STATE.lock().unwrap();
        let previous_count = state.decrement_refs();

        // If this was the last reference, clean up the service
        if previous_count == 1 {
            if let Some(handle) = state.handle.take() {
                handle.abort();
                tracing::info!("Test service stopped - no more references");
            }
        } else {
            tracing::debug!(
                "ServiceGuard dropped, {} references remaining",
                previous_count - 1
            );
        }
    }
}

// Initialize the test service and return a guard
pub async fn initialize_test_service() -> (String, ServiceGuard) {
    let mut state = SERVICE_STATE.lock().unwrap();
    state.increment_refs();
    if state.handle.is_none() {
        let handle = start_service().await;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        tracing::info!("Test service initialized at {}", APP_URL);
        state.handle = Some(handle);
    } else {
        tracing::info!(
            "Using existing test service at {}, reference count: {}",
            APP_URL,
            state.get_ref_count()
        );
    }

    (APP_URL.to_string(), ServiceGuard)
}

// Start the service and return its JoinHandle
async fn start_service() -> JoinHandle<()> {
    dotenv().ok();

    tracing::info!("Starting OIDC application for tests");
    let identifier = AiclIdentifier::from_env()
        .await
        .expect("Failed to initialize AiclIdentifier");
    let error_handler = AppErrorHandler::new(JsonErrorHandler::default());

    // Start the service in a background task
    tokio::spawn(run(identifier, error_handler))
}

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
) -> Result<String, (StatusCode, String)> {
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

    Ok(serde_json::to_string(&token).unwrap())
}

// Endpoint that requires token authentication
async fn token_authenticated(identity: AiclIdentity) -> impl IntoResponse {
    format!("API access granted for {}!", identity.username)
}

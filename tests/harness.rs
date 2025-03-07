use aicl_oidc::{
    errors::{AppError, JsonErrorHandler},
    oidc::keycloak::{KeyCloakToken, TOKEN_KEY},
    vault::ApiToken,
    AiclIdentifier, AiclIdentity, AppErrorHandler, OptionalIdentity,
    Role,
};
use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use dotenvy::dotenv;
use lazy_static::lazy_static;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
};
use tokio::{net::TcpListener, task::JoinHandle};
use tower_http::trace::TraceLayer;
use tower_sessions::Session;
use tower_sessions::{
    cookie::{time::Duration, SameSite},
    Expiry, MemoryStore, SessionManagerLayer,
};
use uuid::Uuid;

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

// Mock data store for our test resources
#[derive(Debug, Clone, Default)]
struct AppState {
    team_resources: Arc<RwLock<HashMap<String, TeamResource>>>,
    institution_resources: Arc<RwLock<HashMap<String, InstitutionResource>>>,
}

// Team resource model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamResource {
    id: String,
    team_id: String,
    name: String,
    description: String,
    content: String,
    created_by: String,
}

// Institution resource model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstitutionResource {
    id: String,
    institution_id: String,
    name: String,
    description: String,
    content: String,
    created_by: String,
}

// Request payloads
#[derive(Debug, Serialize, Deserialize)]
pub struct ResourcePayload {
    name: String,
    description: String,
    content: String,
}

pub async fn run(identifier: AiclIdentifier, error_handler: AppErrorHandler) {
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(Duration::seconds(120)));

    // Create app state with mock data
    let app_state = AppState::default();

    // Initialize with some sample data
    {
        let mut team_resources = app_state.team_resources.write().unwrap();
        team_resources.insert(
            "resource1".to_string(),
            TeamResource {
                id: "resource1".to_string(),
                team_id: "Team1".to_string(),
                name: "Team1 Resource".to_string(),
                description: "A pre-existing resource for Team1".to_string(),
                content: "This is some sample content".to_string(),
                created_by: "captain1".to_string(),
            },
        );

        let mut institution_resources = app_state.institution_resources.write().unwrap();
        institution_resources.insert(
            "institution1".to_string(),
            InstitutionResource {
                id: "institution1".to_string(),
                institution_id: "School1".to_string(),
                name: "School1 Resource".to_string(),
                description: "A pre-existing resource for School1".to_string(),
                content: "This is some sample content for the institution".to_string(),
                created_by: "advisor1".to_string(),
            },
        );
    }


    let app = Router::new()
        // Authentication endpoints
        .route("/foo", get(authenticated))
        .route_service("/logout", identifier.logout_service())
        .route("/token", get(create_token))
        .route("/api/protected", get(token_authenticated))

        // Public API
        .route("/api/public", get(public_info))

        // Team resources
        .route("/api/teams/view", get(view_teams))
        .route("/api/teams/edit", post(edit_teams))
        .route("/api/teams/{team_id}/resources", get(list_team_resources))
        .route("/api/teams/{team_id}/resources", post(create_team_resource))
        .route("/api/teams/{team_id}/resources/{resource_id}", get(get_team_resource))
        .route("/api/teams/{team_id}/resources/{resource_id}", post(update_team_resource))
        .route("/api/teams/{team_id}/resources/{resource_id}", delete(delete_team_resource))

        // Institution resources
        .route("/api/institutions/{institution_id}/resources", get(list_institution_resources))
        .route("/api/institutions/{institution_id}/resources", post(create_institution_resource))
        .route("/api/institutions/{institution_id}/resources/{resource_id}", get(get_institution_resource))
        .route("/api/institutions/{institution_id}/resources/{resource_id}", post(update_institution_resource))
        
        // Admin-only endpoints
        .route("/api/admin", get(admin_only))
        
        // Advisor-only endpoints
        .route("/api/advisors", get(advisor_only))

        // Authentication layers
        .layer(identifier.login_layer())
        .route("/bar", get(maybe_authenticated))
        .layer(identifier.authenticate_layer())
        .layer(session_layer)
        .layer(identifier.api_token_layer())
        .layer(identifier.identifier_layer())
        .layer(error_handler.layer())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let listener = TcpListener::bind("0.0.0.0:4040").await.unwrap();
    tracing::info!("Router built, launching");
    axum::serve(listener, app)
        .await
        .unwrap();
}

// Original authentication handlers
async fn authenticated(identity: AiclIdentity) -> impl IntoResponse {
    Json(identity)
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
    error_handler: AppErrorHandler,
    identity: AiclIdentity,
    session: Session,
    identifier: AiclIdentifier,
) -> Result<Json<ApiToken>, Response> {
    // Get the vault service from the identifier

    // Get the OIDC token from the session
    let oidc_token = session
        .get::<KeyCloakToken>(TOKEN_KEY)
        .await
        .map_err(|_| {
            error_handler.handle_error(AppError::internal_error("Error retrieving OIDC token from session"))
        })?
        .ok_or(error_handler.handle_error(AppError::forbidden("No OIDC token found in session")))?;
    tracing::info!("Creating API token for user {}", identity.username);
    // Create a token
    let token = identifier
        .vault
        .create_api_token_with_oidc(&identity, &oidc_token)
        .await
        .map_err(|e| {
            error_handler.handle_error(e)
        })?;
    tracing::info!("Created API token for user {}", identity.username);
    Ok(Json(token))
}

// Endpoint that requires token authentication
async fn token_authenticated(identity: AiclIdentity) -> impl IntoResponse {
    format!("API access granted for {}!", identity.username)
}

// ------------ New endpoints for testing -------------

// Public info - accessible by everyone
async fn public_info() -> impl IntoResponse {
    Json(serde_json::json!({
        "message": "This is public information accessible to all users."
    }))
}

// Team view - accessible by anyone
async fn view_teams() -> impl IntoResponse {
    Json(serde_json::json!({
        "teams": [
            {"id": "Team1", "name": "Team 1"},
            {"id": "Team2", "name": "Team 2"},
            {"id": "Team3", "name": "Team 3"}
        ]
    }))
}

// Team edit - requires captain or admin
async fn edit_teams(identity: AiclIdentity) -> impl IntoResponse {
    // Check role permissions
    if !matches!(identity.role, Role::Admin | Role::Captain) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Only captains and admins can edit teams"
            })),
        );
    }
    
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Team edit successful"
        })),
    )
}

// Admin-only endpoint
async fn admin_only(identity: AiclIdentity) -> impl IntoResponse {
    if identity.role != Role::Admin {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "This endpoint is restricted to admins only"
            })),
        );
    }
    
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Admin access granted",
            "sensitive_data": "This is sensitive admin-only information"
        })),
    )
}

// Advisor-only endpoint
async fn advisor_only(identity: AiclIdentity) -> impl IntoResponse {
    if !matches!(identity.role, Role::Admin | Role::Advisor) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "This endpoint is restricted to advisors and admins only"
            })),
        );
    }
    
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Advisor access granted",
            "institutions": [
                {"id": "School1", "name": "School 1"},
                {"id": "School2", "name": "School 2"}
            ]
        })),
    )
}

// ------------ Team resource endpoints -------------

// List team resources
async fn list_team_resources(
    error_handler: AppErrorHandler,
    Path(team_id): Path<String>,
    identity: AiclIdentity,
    State(state): State<AppState>,
) -> Result<Json<Vec<TeamResource>>, Response> {
    // Check team access
    let can_access = has_team_access(&identity, &team_id);
    if !can_access {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have access to this team's resources")));
    }
    
    // Get resources for this team
    let resources = state.team_resources.read().unwrap();
    let team_resources: Vec<_> = resources
        .values()
        .filter(|r| r.team_id == team_id)
        .cloned()
        .collect();
    
    Ok(Json(team_resources))
}

// Create team resource
async fn create_team_resource(
    error_handler: AppErrorHandler,
    Path(team_id): Path<String>,
    identity: AiclIdentity,
    State(state): State<AppState>,
    Json(payload): Json<ResourcePayload>,
) -> Result<Json<TeamResource>, Response> {
    // Check team access
    if !has_team_access(&identity, &team_id) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have access to this team's resources")));
    }
    
    // Check write permissions
    if !can_write_team_resource(&identity) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have write permissions for this team's resources")));
    }
    
    // Create the resource
    let resource_id = Uuid::new_v4().to_string();
    let new_resource = TeamResource {
        id: resource_id.clone(),
        team_id,
        name: payload.name,
        description: payload.description,
        content: payload.content,
        created_by: identity.username,
    };
    
    // Store the resource
    let mut resources = state.team_resources.write().unwrap();
    resources.insert(resource_id, new_resource.clone());
    
    Ok(Json(new_resource))
}

// Get team resource
async fn get_team_resource(
    error_handler: AppErrorHandler,
    Path((team_id, resource_id)): Path<(String, String)>,
    identity: AiclIdentity,
    State(state): State<AppState>,
) -> Result<Json<TeamResource>, Response> {
    // Check team access
    if !has_team_access(&identity, &team_id) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have access to this team's resources")));
    }
    
    // Get the resource
    let resources = state.team_resources.read().unwrap();
    match resources.get(&resource_id) {
        Some(resource) => {
            if resource.team_id != team_id {
                Err(error_handler.handle_error(AppError::not_found("You don't have access to this team's resources")))
            } else {
                Ok(Json(resource.clone()))
            }
        }
        None => Err(error_handler.handle_error(AppError::not_found("You don't have access to this team's resources"))),
    }
}

// Update team resource
async fn update_team_resource(
    error_handler: AppErrorHandler,
    Path((team_id, resource_id)): Path<(String, String)>,
    identity: AiclIdentity,
    State(state): State<AppState>,
    Json(payload): Json<ResourcePayload>,
) -> Result<Json<TeamResource>, Response> {
    // Check team access
    if !has_team_access(&identity, &team_id) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have access to this team's resources")));
    }
    
    // Check write permissions
    if !can_write_team_resource(&identity) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have write permissions for this team's resources")));
    }
    
    // Update the resource
    let mut resources = state.team_resources.write().unwrap();
    match resources.get_mut(&resource_id) {
        Some(resource) => {
            if resource.team_id != team_id {
                return Err(error_handler.handle_error(AppError::not_found("Resource not found in this team")));
            } else {
                resource.name = payload.name;
                resource.description = payload.description;
                resource.content = payload.content;
                Ok(Json(resource.clone()))
            }
        }
        None => Err(
            error_handler.handle_error(AppError::not_found("Resource not found in this team")),
        ),
    }
}

// Delete team resource
async fn delete_team_resource(
    error_handler: AppErrorHandler,
    Path((team_id, resource_id)): Path<(String, String)>,
    identity: AiclIdentity,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Check team access
    if !has_team_access(&identity, &team_id) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have access to this team's resources")));
    }
    
    // Check write permissions
    if !can_write_team_resource(&identity) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have write permissions for this team's resources")));
    }
    
    // Delete the resource
    let mut resources = state.team_resources.write().unwrap();
    match resources.get(&resource_id) {
        Some(resource) => {
            if resource.team_id != team_id {
                return Err(error_handler.handle_error(AppError::not_found("You don't have permission to delete this resource")));
            } else {
                resources.remove(&resource_id);
                Ok(Json(serde_json::json!({
                        "message": "Resource deleted successfully"
                    })),
                )
            }
        }
        None => Err(error_handler.handle_error(AppError::not_found("Resource not found"))),
    }
}

// ------------ Institution resource endpoints -------------

// List institution resources
async fn list_institution_resources(
    error_handler: AppErrorHandler,
    Path(institution_id): Path<String>,
    identity: AiclIdentity,
    State(state): State<AppState>,
) -> Result<Json<Vec<InstitutionResource>>, Response> {
    // Check institution access
    if !has_institution_access(&identity, &institution_id) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have access to this institution's resources")));
    }
    
    // Get resources for this institution
    let resources = state.institution_resources.read().unwrap();
    let institution_resources: Vec<_> = resources
        .values()
        .filter(|r| r.institution_id == institution_id)
        .cloned()
        .collect();
    
    Ok(Json(institution_resources))
}

// Create institution resource
async fn create_institution_resource(
    error_handler: AppErrorHandler,
    Path(institution_id): Path<String>,
    identity: AiclIdentity,
    State(state): State<AppState>,
    Json(payload): Json<ResourcePayload>,
) -> Result<Json<InstitutionResource>, Response>  {
    // Check institution access
    if !has_institution_access(&identity, &institution_id) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have access to this institution's resources")));
    }
    
    // Check write permissions
    if !can_write_institution_resource(&identity) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have write permissions for this institution's resources")));
    }
    
    // Create the resource
    let resource_id = Uuid::new_v4().to_string();
    let new_resource = InstitutionResource {
        id: resource_id.clone(),
        institution_id,
        name: payload.name,
        description: payload.description,
        content: payload.content,
        created_by: identity.username,
    };
    
    // Store the resource
    let mut resources = state.institution_resources.write().unwrap();
    resources.insert(resource_id, new_resource.clone());
    
    Ok(Json(new_resource))
}

// Get institution resource
async fn get_institution_resource(
    error_handler: AppErrorHandler,
    Path((institution_id, resource_id)): Path<(String, String)>,
    identity: AiclIdentity,
    State(state): State<AppState>,
) -> Result<Json<InstitutionResource>, Response> {
    // Check institution access
    if !has_institution_access(&identity, &institution_id) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have access to this institution's resources")));
    }
    
    // Get the resource
    let resources = state.institution_resources.read().unwrap();
    match resources.get(&resource_id) {
        Some(resource) => {
            if resource.institution_id != institution_id {
                Err(error_handler.handle_error(AppError::not_found("Resource not found")))
            } else {
                Ok(Json(resource.clone()))
            }
        }
        None => Err(error_handler.handle_error(AppError::not_found("Resource not found"))),
    }
}

// Update institution resource
async fn update_institution_resource(
    error_handler: AppErrorHandler,
    Path((institution_id, resource_id)): Path<(String, String)>,
    identity: AiclIdentity,
    State(state): State<AppState>,
    Json(payload): Json<ResourcePayload>,
) -> Result<Json<InstitutionResource>, Response> {
    // Check institution access
    let can_access = has_institution_access(&identity, &institution_id);
    if !can_access {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have access to this institution's resources")));
    }
    
    // Check write permissions
    if !can_write_institution_resource(&identity) {
        return Err(error_handler.handle_error(AppError::forbidden("You don't have write permissions for this institution's resources")));
    }
    
    // Update the resource
    let mut resources = state.institution_resources.write().unwrap();
    match resources.get_mut(&resource_id) {
        Some(resource) => {
            if resource.institution_id != institution_id {
                Err(error_handler.handle_error(AppError::not_found("Resource not found in this institution")))
            } else {
                resource.name = payload.name;
                resource.description = payload.description;
                resource.content = payload.content;
                Ok(Json(resource.clone()))
            }
        }
        None => Err(error_handler.handle_error(AppError::not_found("Resource not found in this institution")))
    }
}

// ------------ Permission helper functions -------------

// Check if a user has access to a team's resources
fn has_team_access(identity: &AiclIdentity, team_id: &str) -> bool {
    // Admins can access any team
    if identity.role == Role::Admin {
        return true;
    }
    
    // Check if user is a member of this team
    if let Some(team) = &identity.team {
        return team.name == team_id;
    }
    
    false
}

// Check if a user can write (create/update/delete) team resources
fn can_write_team_resource(identity: &AiclIdentity) -> bool {
    matches!(identity.role, Role::Admin | Role::Captain)
}

// Check if a user has access to an institution's resources
fn has_institution_access(identity: &AiclIdentity, institution_id: &str) -> bool {
    // Admins can access any institution
    if identity.role == Role::Admin {
        return true;
    }
    
    // Check if user is an advisor for this institution
    if identity.role == Role::Advisor {
        if let Some(institution) = &identity.institution {
            return institution.name == institution_id;
        }
    }
    
    // Students and captains can access their institution resources
    if matches!(identity.role, Role::Captain | Role::Student | Role::Spectator) {
        if let Some(team) = &identity.team {
            // This is a simplified check - in a real app you'd have a proper 
            // relationship between teams and institutions
            return team.name.starts_with(&institution_id);
        }
    }
    
    false
}

// Check if a user can write (create/update/delete) institution resources
fn can_write_institution_resource(identity: &AiclIdentity) -> bool {
    matches!(identity.role, Role::Admin | Role::Advisor)
}
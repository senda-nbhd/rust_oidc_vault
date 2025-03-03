use std::sync::Arc;

use aicl_oidc::{
    axum::{
        extractors::OptionalIdentity,
        middleware::{AuthenticateLayer, LoginEnforcerLayer},
    },
    idp::admin::IdpAdmin,
    oidc::keycloak::{KeycloakOidcBuilder, KeycloakOidcProvider},
    vault::VaultService,
    AiclIdentity,
};
use axum::{response::IntoResponse, routing::get, Router};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tower_sessions::{
    cookie::{time::Duration, SameSite},
    Expiry, MemoryStore, SessionManagerLayer,
};

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub async fn run(identifier: Arc<KeycloakOidcProvider>) {
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(Duration::seconds(120)));

    let auth_layer = AuthenticateLayer {
        identifier: identifier.clone(),
    };
    let login_layer = LoginEnforcerLayer {
        identifier: identifier.clone(),
    };

    let app: Router<()> = Router::new();

    let app = app
        .route("/foo", get(authenticated))
        .route("/logout", get(logout))
        .layer(login_layer)
        .route("/bar", get(maybe_authenticated))
        .layer(auth_layer)
        .layer(session_layer)
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind("0.0.0.0:4040").await.unwrap();
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

async fn logout() -> impl IntoResponse {
    todo!()
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
    let vault = VaultService::from_env()
        .await
        .expect("Vault service initialization failed");
    let idp_config = vault
        .get_idp_config_from_vault()
        .await
        .expect("Failed to get IDP config from Vault");
    let idp_admin = IdpAdmin::new(idp_config)
        .await
        .expect("IDP admin initialization failed");
    let oidc_provider = KeycloakOidcBuilder::new(
        idp_admin,
        "http://localhost:4040".to_string(), // Application base URL
        "http://keycloak:8080/realms/app-realm".to_string(), // Issuer
        "rust-app".to_string(),              // Client ID
    )
    .with_client_secret(Some("test-client-secret".to_string()))
    .with_scopes(vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ])
    .build()
    .await
    .expect("Failed to build KeycloakOidcProvider");
    run(Arc::new(oidc_provider)).await;
}

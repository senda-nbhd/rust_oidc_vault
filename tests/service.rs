use std::sync::Arc;

use aicl_oidc::{
    axum::{
        extractors::OptionalIdentity,
        middleware::{AuthenticateLayer, LoginEnforcerLayer},
    },
    oidc::keycloak::KeycloakOidcProvider,
    AiclIdentity,
};
use axum::{
    response::IntoResponse, routing::get, Router,
};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tower_sessions::{
    cookie::{time::Duration, SameSite},
    Expiry, MemoryStore, SessionManagerLayer,
};

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

use aicl_oidc::{OptionalIdentity, AiclIdentifier, AiclIdentity, AppErrorHandler};
use axum::{
    response::IntoResponse, routing::get, Router,
};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tower_sessions::{
    cookie::{time::Duration, SameSite},
    Expiry, MemoryStore, SessionManagerLayer,
};

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
        .layer(identifier.login_layer())
        .route("/bar", get(maybe_authenticated))
        .layer(identifier.authenticate_layer())
        .layer(session_layer)
        .layer(error_handler.layer())
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
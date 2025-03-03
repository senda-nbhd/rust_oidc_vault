use std::{convert::Infallible, sync::Arc};

use axum::{extract::Request, response::{IntoResponse, Redirect, Response}};
use futures_util::future::BoxFuture;
use reqwest::StatusCode;
use tower_sessions::Session;

use super::keycloak::KeycloakOidcProvider;

pub struct LogoutService {
    pub identifier: Arc<KeycloakOidcProvider>,
}

impl Clone for LogoutService {
    fn clone(&self) -> Self {
        Self {
            identifier: self.identifier.clone(),
        }
    }
}


impl<B> tower::Service<Request<B>> for LogoutService
where
    B: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let provider = self.identifier.clone();
        
        // Get the session from the request extensions
        let session = match req.extensions().get::<Session>() {
            Some(session) => session.clone(),
            None => {
                return Box::pin(async move {
                    Ok(StatusCode::INTERNAL_SERVER_ERROR
                        .into_response())
                });
            }
        };

        Box::pin(async move {
            match provider.logout(&session).await {
                Ok(logout_uri) => Ok(Redirect::to(logout_uri.to_string().as_str()).into_response()),
                Err(e) => {
                    tracing::error!("Logout failed: {}", e);
                    Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
            }
        })
    }
}
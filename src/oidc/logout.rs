use std::convert::Infallible;

use axum::{
    extract::Request,
    response::{IntoResponse, Redirect, Response},
};
use futures_util::future::BoxFuture;
use reqwest::StatusCode;
use tower_sessions::Session;

use crate::AiclIdentifier;

#[derive(Clone)]
pub struct LogoutService {}

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
        let identifier = req
            .extensions()
            .get::<AiclIdentifier>()
            .expect("Identifier not found")
            .clone();

        // Get the session from the request extensions
        let session = match req.extensions().get::<Session>() {
            Some(session) => session.clone(),
            None => {
                return Box::pin(
                    async move { Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()) },
                );
            }
        };

        Box::pin(async move {
            match identifier.oidc.logout(&session).await {
                Ok(logout_uri) => Ok(Redirect::to(logout_uri.to_string().as_str()).into_response()),
                Err(e) => {
                    tracing::error!("Logout failed: {}", e);
                    Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
            }
        })
    }
}

use std::sync::Arc;

use axum::{
    extract::FromRequestParts, http::{request::Parts, Extensions, Request}, response::{IntoResponse, Response}
};
use reqwest::StatusCode;
use tower::{Layer, Service};

use crate::errors::{AppError, self};

/// A wrapper around an error handler that can be used in request extensions
#[derive(Clone)]
pub struct AppErrorHandler {
    handler: Arc<dyn errors::ErrorHandler>,
}

impl AppErrorHandler {
    pub fn new<H: errors::ErrorHandler>(handler: H) -> Self {
        Self {
            handler: Arc::new(handler),
        }
    }

    pub fn handle_error<E: Into<AppError>>(&self, error: E) -> Response {
        self.handler.handle_error(error.into())
    }

    pub fn layer(&self) -> ErrorHandlerExtensionLayer {
        ErrorHandlerExtensionLayer {
            handler: self.clone(),
        }
    }
}

/// A layer that adds an error handler to request extensions
#[derive(Clone)]
pub struct ErrorHandlerExtensionLayer {
    handler: AppErrorHandler,
}

impl<S> Layer<S> for ErrorHandlerExtensionLayer {
    type Service = ErrorHandlerExtensionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ErrorHandlerExtensionService {
            inner,
            handler: self.handler.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ErrorHandlerExtensionService<S> {
    inner: S,
    handler: AppErrorHandler,
}

impl<S, B> Service<Request<B>> for ErrorHandlerExtensionService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        // Add error handler to request extensions
        req.extensions_mut().insert(self.handler.clone());
        self.inner.call(req)
    }
}

/// Helper function to handle errors in route handlers
pub fn handle_error(
    extensions: &Extensions,
    error: AppError,
) -> Response {
    // Try to get error handler from extensions
    if let Some(handler) = extensions.get::<AppErrorHandler>() {
        handler.handle_error(error)
    } else {
        // Fallback to default error handling if no handler is found
        (error.status_code(), error.to_string()).into_response()
    }
}

impl<S> FromRequestParts<S> for AppErrorHandler
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AppErrorHandler>()
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "AiclIdentity not found".to_string(),
            ))
            .cloned()
    }
}


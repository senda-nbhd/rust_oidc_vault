use axum::{http::Request, response::Response};
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::idp::admin::IdpAdmin;

pub struct IdentifierService<S> {
    identifier: Arc<IdpAdmin>,
    inner: S,
}

impl<S: Clone> Clone for IdentifierService<S> {
    fn clone(&self) -> Self {
        Self {
            identifier: self.identifier.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<B, S> Service<Request<B>> for IdentifierService<S>
where
    S: Service<Request<B>, Response = Response> + Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        request.extensions_mut().insert(self.identifier.clone());
        self.inner.call(request)
    }
}

pub struct IdentifierLayer {
    pub(crate) identifier: Arc<IdpAdmin>,
}

impl Clone for IdentifierLayer {
    fn clone(&self) -> Self {
        Self {
            identifier: self.identifier.clone(),
        }
    }
}

impl<S: Clone> Layer<S> for IdentifierLayer {
    type Service = IdentifierService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IdentifierService {
            identifier: self.identifier.clone(),
            inner,
        }
    }
}

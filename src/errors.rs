use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::fmt;
use thiserror::Error;

use crate::{idp::ext::IdpError, oidc::ext::OidcError, vault::VerificationError};

// Existing identifier error
#[derive(Debug, Error)]
pub enum IdentifierError {
    #[error("Invalid uuid: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("IdpError")]
    IdpError(#[from] IdpError),
    #[error("Empty identifier")]
    EmptyIdentifier,
}

/// Main application error type that can be converted to a response
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Authentication error: {0}")]
    Authentication(#[from] OidcError),

    #[error("Authorization error: {0}")]
    Authorization(String),

    #[error("Token verification failed: {0}")]
    VerificationError(#[from] VerificationError),

    #[error("Identity provider error: {0}")]
    IdentityProvider(#[from] IdpError),

    #[error("Identifier error: {0}")]
    Identifier(#[from] IdentifierError),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal server error: {0}")]
    InternalServer(String),

    #[error("Service Error: {msg}")]
    ServiceError {
        msg: &'static str,
        #[source]
        error: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

// Map AppError variants to appropriate status codes
impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Authentication(_) => StatusCode::UNAUTHORIZED,
            Self::VerificationError(_) => StatusCode::UNAUTHORIZED,
            Self::Authorization(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Session(_) | Self::IdentityProvider(_) | Self::Identifier(_) | Self::InternalServer(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::ServiceError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

// Default error handler that converts AppError to Response
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let message = self.to_string();
        
        (status, message).into_response()
    }
}

/// Error handler trait that can be implemented for different error handling strategies
pub trait ErrorHandler: Send + Sync + 'static {
    fn handle_error(&self, error: AppError) -> Response;
}

/// Default error handler implementation
#[derive(Clone)]
pub struct DefaultErrorHandler {
    pub include_details: bool,
}

impl ErrorHandler for DefaultErrorHandler {
    fn handle_error(&self, error: AppError) -> Response {
        let status = error.status_code();
        
        if self.include_details {
            // In development mode, include error details
            let body = format!("Error: {}", error);
            (status, body).into_response()
        } else {
            // In production mode, use generic error messages
            let message = match status {
                StatusCode::UNAUTHORIZED => "Authentication required",
                StatusCode::FORBIDDEN => "Permission denied",
                StatusCode::NOT_FOUND => "Resource not found",
                StatusCode::BAD_REQUEST => "Invalid request",
                _ => "An unexpected error occurred",
            };
            
            (status, message).into_response()
        }
    }
}

/// HTML templated error handler implementation
#[derive(Clone)]
pub struct HtmlErrorHandler {
    pub template_path: String,
}

impl ErrorHandler for HtmlErrorHandler {
    fn handle_error(&self, error: AppError) -> Response {
        let status = error.status_code();
        
        // Here you would typically render an HTML template with the error details
        // This is a simplified example - you would integrate with your template engine
        let html = format!(
            r#"<!DOCTYPE html>
            <html>
            <head><title>Error</title></head>
            <body>
                <h1>Error {}</h1>
                <p>{}</p>
            </body>
            </html>"#,
            status.as_u16(),
            if status == StatusCode::INTERNAL_SERVER_ERROR {
                "An unexpected error occurred".to_string()
            } else {
                error.to_string()
            }
        );
        
        (status, [(axum::http::header::CONTENT_TYPE, "text/html")], html).into_response()
    }
}

/// JSON error handler implementation
#[derive(Clone)]
pub struct JsonErrorHandler {
    pub include_details: bool,
}

impl Default for JsonErrorHandler {
    fn default() -> Self {
        Self { include_details: true }
    }
}

impl ErrorHandler for JsonErrorHandler {
    fn handle_error(&self, error: AppError) -> Response {
        let status = error.status_code();
        
        let json_body = if self.include_details {
            // Include detailed error information in development
            serde_json::json!({
                "error": {
                    "status": status.as_u16(),
                    "message": error.to_string(),
                    "type": format!("{:?}", error),
                }
            })
        } else {
            // Generic error information in production
            serde_json::json!({
                "error": {
                    "status": status.as_u16(),
                    "message": match status {
                        StatusCode::UNAUTHORIZED => "Authentication required",
                        StatusCode::FORBIDDEN => "Permission denied",
                        StatusCode::NOT_FOUND => "Resource not found",
                        StatusCode::BAD_REQUEST => "Invalid request",
                        _ => "An unexpected error occurred",
                    }
                }
            })
        };
        
        (status, [(axum::http::header::CONTENT_TYPE, "application/json")], 
         serde_json::to_string(&json_body).unwrap()).into_response()
    }
}

// Helper methods to create AppErrors from strings
impl AppError {
    pub fn unauthorized(message: impl fmt::Display) -> Self {
        Self::Authentication(OidcError::AuthenticationError(message.to_string()))
    }
    
    pub fn forbidden(message: impl fmt::Display) -> Self {
        Self::Authorization(message.to_string())
    }
    
    pub fn not_found(message: impl fmt::Display) -> Self {
        Self::NotFound(message.to_string())
    }
    
    pub fn bad_request(message: impl fmt::Display) -> Self {
        Self::BadRequest(message.to_string())
    }
    
    pub fn internal_error(message: impl fmt::Display) -> Self {
        Self::InternalServer(message.to_string())
    }
    
    pub fn session_error(message: impl fmt::Display) -> Self {
        Self::Session(message.to_string())
    }
}
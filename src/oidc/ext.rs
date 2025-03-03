use thiserror::Error;

/// Error types for OIDC operations
#[derive(Error, Debug, Clone)]
pub enum OidcError {
    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("Token validation failed: {0}")]
    ValidationError(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

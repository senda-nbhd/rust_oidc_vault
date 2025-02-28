use crate::idp::ext::IdpError;

#[derive(Debug, thiserror::Error)]
pub enum IdentifierError {
    #[error("Invalid uuid: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("IdpError")]
    IdpError(#[from] IdpError),
    #[error("Empty identifier")]
    EmptyIdentifier,
}

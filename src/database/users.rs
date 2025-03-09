use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::Role;

use super::{institutions::CompleteInstitution, teams::CompleteTeam};

/// Complete user entity with all related information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: bool,
    pub attributes: serde_json::Value,
    pub role: Role,
    pub team: Option<CompleteTeam>,
    pub institution: Option<CompleteInstitution>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}
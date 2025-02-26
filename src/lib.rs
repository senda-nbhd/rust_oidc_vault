pub mod axum;
pub mod idp;
pub mod oidc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents a team identity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TeamIdentity {
    pub id: Uuid,
    pub name: String,
}

/// Represents a team identity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct InstitutionIdentity {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum Role {
    Root,
    Advisor,
    Captain,
    Student,
    Spectator,
}

impl Role {
    pub fn parse(s: &str) -> Self {
        match s {
            "ROOT" => Self::Root,
            "ADVISOR" => Self::Advisor,
            "CAPTAIN" => Self::Captain,
            "STUDENT" => Self::Student,
            "SPECTATOR" => Self::Spectator,
            _ => panic!("Role not found: {}", s),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Root => "ROOT",
            Self::Advisor => "ADVISOR",
            Self::Captain => "CAPTAIN",
            Self::Student => "STUDENT",
            Self::Spectator => "SPECTATOR",
        }
    }

    pub fn is_admin(&self) -> bool {
        match self {
            Self::Root => true,
            _ => false,
        }
    }
}

/// Represents a user's identity in the AICL system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AiclIdentity {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub team: Option<TeamIdentity>,
    pub institution: Option<InstitutionIdentity>,
    pub role: Role,
}

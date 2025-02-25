pub mod keycloak;
pub mod idp_admin;

#[cfg(test)]
mod tests;

use axum_oidc::OidcClaims;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use serde_json::Value;

/// Represents a team identity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TeamIdentity {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum Role {
    Root,
    Advisor,
    Viewer,
    Captain,
    Student,
    Spectator,
}

impl Role {
    pub fn parse(s: &str) -> Self {
        match s {
            "root" => Self::Root,
            "advisor" => Self::Advisor,
            "viewer" => Self::Viewer,
            "captain" => Self::Captain,
            "student" => Self::Student,
            "spectator" => Self::Spectator,
            _ => panic!("Role not found: {}", s),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Advisor => "advisor",
            Self::Viewer => "viewer",
            Self::Captain => "captain",
            Self::Student => "student",
            Self::Spectator => "spectator",
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
    pub name: String,
    pub team: Option<TeamIdentity>,
    pub role: Role,
}

/// Custom claims extracted from the OIDC token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiclClaims {
    pub sub: Option<String>,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    pub user_id: Option<String>,
    
    // Make these fields accept either string or array
    #[serde(default)]
    pub roles: Option<Value>,
    
    #[serde(default)]
    pub groups: Option<Value>,
    
    pub team_id: Vec<Uuid>,
}

impl openidconnect::AdditionalClaims for AiclClaims {}
impl axum_oidc::AdditionalClaims for AiclClaims {}

impl AiclClaims {
    /// Extract roles from Value which could be either a string or array
    fn extract_roles(&self) -> Vec<String> {
        match &self.roles {
            Some(Value::Array(arr)) => arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => vec![],
        }
    }
    
    /// Extract groups from Value which could be either a string or array
    fn extract_groups(&self) -> Vec<String> {
        match &self.groups {
            Some(Value::Array(arr)) => arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => vec![],
        }
    }

    /// Convert OIDC claims to AiclIdentity
    pub fn to_identity(&self) -> Option<AiclIdentity> {
        // Extract name from claims
        let name = self.name.clone().or_else(|| {
            self.preferred_username.clone()
        })?;

        // Extract team information
        let groups = self.extract_groups();
        let team = match (self.team_id.last(), !groups.is_empty()) {
            (Some(team_id), true) => {
                // Get the group name from the path (taking last segment)
                let team_name = groups[0]
                    .split('/')
                    .last()
                    .unwrap_or("Unknown")
                    .to_string();
                
                Some(TeamIdentity {
                    id: team_id.clone(),
                    name: team_name,
                })
            },
            _ => None,
        };

        // Determine role (default to USER if no roles found)
        let roles = self.extract_roles();
        let role = match roles.first().map(|r| Role::parse(&r)) {
            Some(role) => role,
            _ => Role::Spectator,
        };

        Some(AiclIdentity {
            name,
            team,
            role,
        })
    }
}

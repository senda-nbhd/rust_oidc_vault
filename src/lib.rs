pub mod idp;



use axum_oidc::OidcClaims;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

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
            "ROOT" => Self::Root,
            "ADVISOR" => Self::Advisor,
            "VIEWER" => Self::Viewer,
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
            Self::Viewer => "VIEWER",
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
    pub role: Role,
}

/// Custom claims extracted from the OIDC token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiclClaims {
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
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => vec![],
        }
    }

    /// Extract groups from Value which could be either a string or array
    fn extract_groups(&self) -> Vec<String> {
        match &self.groups {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => vec![],
        }
    }

}

pub fn to_domain_user(claims: &OidcClaims<AiclClaims>) -> Option<AiclIdentity> {
    // Extract name from claims
    let extra_claims = claims.additional_claims();
    
    // Extract subject ID
    let id: Uuid = claims.subject().parse().ok()?;
    
    // Extract email
    let email = claims.email()?.as_str().to_string();
    
    // Extract username
    let username = claims.preferred_username()?.as_str().to_string();
    
    // TODO make this get given and family names if username is missing.

    // Extract team information
    let groups = extra_claims.extract_groups();
    let team = match (extra_claims.team_id.last(), !groups.is_empty()) {
        (Some(team_id), true) => {
            // Get the group name from the path (taking last segment)
            let team_name = groups[0].split('/').last().unwrap_or("Unknown").to_string();

            Some(TeamIdentity {
                id: *team_id,
                name: team_name,
            })
        }
        _ => None,
    };

    // Determine role (default to Spectator if no roles found)
    let roles = extra_claims.extract_roles();
    let role = match roles.first().map(|r| Role::parse(r)) {
        Some(role) => role,
        _ => Role::Spectator,
    };

    Some(AiclIdentity { 
        id, 
        email, 
        username, 
        team, 
        role 
    })
}
use super::ext::{
    IdentityProvider, IdpConfig, IdpError, IdpGroup, IdpGroupHeader, IdpRole, IdpUser,
};
use async_trait::async_trait;
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// Types for authentication
#[derive(Serialize)]
struct TokenRequest<'a> {
    username: &'a str,
    password: &'a str,
    grant_type: &'a str,
    client_id: &'a str,
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    expires_in: i32,
    refresh_token: String,
    #[serde(rename = "token_type")]
    token_type: String,
}

// Keycloak specific types (kept private to this module)
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct KeycloakUser {
    pub id: Uuid,
    pub username: String,
    pub enabled: bool,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct KeycloakGroup {
    pub id: Uuid,
    pub name: String,
    pub path: String,
    pub parent_id: Option<Uuid>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct KeycloakRole {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub composite: bool,
    pub client_role: bool,
    pub container_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RoleMappingContainer {
    pub realm_mappings: Option<Vec<KeycloakRole>>,
    pub client_mappings: Option<HashMap<String, ClientRoleMapping>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ClientRoleMapping {
    pub id: String,
    pub client: String,
    pub mappings: Vec<KeycloakRole>,
}

pub struct KeycloakProvider {
    client: Client,
    base_url: String,
    realm: String,
    access_token: Option<String>,
    admin_username: String,
    admin_password: String,
}

impl KeycloakProvider {
    pub fn new(config: &IdpConfig) -> Result<Self, IdpError> {
        let realm = config.realm.clone().ok_or_else(|| {
            IdpError::InvalidInput("Realm is required for Keycloak provider".to_string())
        })?;

        let admin_username = config.admin_username.clone().ok_or_else(|| {
            IdpError::InvalidInput("Admin username is required for Keycloak provider".to_string())
        })?;

        let admin_password = config.admin_password.clone().ok_or_else(|| {
            IdpError::InvalidInput("Admin password is required for Keycloak provider".to_string())
        })?;

        Ok(KeycloakProvider {
            client: Client::new(),
            base_url: config.base_url.clone(),
            realm,
            access_token: None,
            admin_username,
            admin_password,
        })
    }

    // Helper method to get auth headers
    fn get_auth_headers(&self) -> Result<header::HeaderMap, IdpError> {
        let mut headers = header::HeaderMap::new();

        let token = match &self.access_token {
            Some(token) => token,
            None => {
                return Err(IdpError::AuthenticationError(
                    "Not authenticated. Call initialize() first.".to_string(),
                ))
            }
        };

        let auth_value = format!("Bearer {}", token);
        match header::HeaderValue::from_str(&auth_value) {
            Ok(value) => {
                headers.insert(header::AUTHORIZATION, value);
                Ok(headers)
            }
            Err(e) => Err(IdpError::Unknown(format!(
                "Failed to create authorization header: {}",
                e
            ))),
        }
    }

    // Convert Keycloak types to generic IdP types
    fn convert_kc_user_to_idp_user(&self, kc_user: KeycloakUser) -> IdpUser {
        IdpUser {
            id: kc_user.id,
            username: kc_user.username,
            email: kc_user.email,
            first_name: kc_user.first_name,
            last_name: kc_user.last_name,
            enabled: kc_user.enabled,
            attributes: kc_user.attributes.unwrap_or_default(),
        }
    }

    fn convert_kc_group_to_idp_group(&self, kc_group: KeycloakGroup) -> IdpGroup {
        IdpGroup {
            id: kc_group.id,
            name: kc_group.name,
            path: kc_group.path,
            parent_id: kc_group.parent_id,
            attributes: kc_group.attributes.unwrap_or_default(),
        }
    }

    fn convert_kc_role_to_idp_role(&self, kc_role: KeycloakRole) -> IdpRole {
        IdpRole {
            id: kc_role.id,
            name: kc_role.name,
            description: kc_role.description,
            is_composite: kc_role.composite,
            source: if kc_role.client_role {
                format!("client:{}", kc_role.container_id)
            } else {
                "realm".to_string()
            },
        }
    }
}

#[async_trait]
impl IdentityProvider for KeycloakProvider {
    async fn initialize(&mut self) -> Result<(), IdpError> {
        let token_url = format!(
            "{}/realms/master/protocol/openid-connect/token",
            self.base_url
        );

        let token_request = TokenRequest {
            username: &self.admin_username,
            password: &self.admin_password,
            grant_type: "password",
            client_id: "admin-cli",
        };

        let response = match self
            .client
            .post(&token_url)
            .form(&token_request)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return Err(IdpError::NetworkError(format!(
                    "Failed to connect to Keycloak: {}",
                    e
                )))
            }
        };

        if !response.status().is_success() {
            let error_text = match response.text().await {
                Ok(text) => text,
                Err(_) => "Unknown error".to_string(),
            };
            error!("Failed to login to Keycloak: {}", error_text);
            return Err(IdpError::AuthenticationError(format!(
                "Failed to login: {}",
                error_text
            )));
        }

        let token_response: TokenResponse = match response.json().await {
            Ok(token) => token,
            Err(e) => {
                return Err(IdpError::Unknown(format!(
                    "Failed to parse token response: {}",
                    e
                )))
            }
        };

        self.access_token = Some(token_response.access_token);
        info!("Successfully logged in to Keycloak");

        Ok(())
    }

    fn issuer(&self) -> String {
        format!("{}/realms/{}", self.base_url, self.realm)
    }

    async fn get_users(&self) -> Result<Vec<IdpUser>, IdpError> {
        let headers = self.get_auth_headers()?;
        let url = format!("{}/admin/realms/{}/users", self.base_url, self.realm);

        debug!("Fetching users from: {}", url);
        let response = match self.client.get(&url).headers(headers).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(IdpError::NetworkError(format!(
                    "Failed to connect to Keycloak: {}",
                    e
                )))
            }
        };

        if !response.status().is_success() {
            let error_text = match response.text().await {
                Ok(text) => text,
                Err(_) => "Unknown error".to_string(),
            };
            error!("Failed to get users: {}", error_text);
            return Err(IdpError::Unknown(format!(
                "Failed to get users: {}",
                error_text
            )));
        }

        let kc_users: Vec<KeycloakUser> = match response.json().await {
            Ok(users) => users,
            Err(e) => {
                return Err(IdpError::Unknown(format!(
                    "Failed to parse users response: {}",
                    e
                )))
            }
        };

        // Convert to IdpUser type
        let users = kc_users
            .into_iter()
            .map(|user| self.convert_kc_user_to_idp_user(user))
            .collect();

        info!("Successfully retrieved users from Keycloak");
        Ok(users)
    }

    async fn get_user(&self, user_id: Uuid) -> Result<IdpUser, IdpError> {
        let headers = self.get_auth_headers()?;
        let url = format!(
            "{}/admin/realms/{}/users/{}",
            self.base_url, self.realm, user_id
        );

        debug!("Fetching user from: {}", url);
        let response = match self.client.get(&url).headers(headers.clone()).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(IdpError::NetworkError(format!(
                    "Failed to connect to Keycloak: {}",
                    e
                )))
            }
        };

        if response.status().is_client_error() {
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Err(IdpError::NotFound(format!(
                    "User with ID {} not found",
                    user_id
                )));
            } else {
                let error_text = match response.text().await {
                    Ok(text) => text,
                    Err(_) => "Unknown error".to_string(),
                };
                return Err(IdpError::PermissionDenied(format!(
                    "Permission denied: {}",
                    error_text
                )));
            }
        }

        if !response.status().is_success() {
            let error_text = match response.text().await {
                Ok(text) => text,
                Err(_) => "Unknown error".to_string(),
            };
            error!("Failed to get user: {}", error_text);
            return Err(IdpError::Unknown(format!(
                "Failed to get user: {}",
                error_text
            )));
        }

        let kc_user: KeycloakUser = match response.json().await {
            Ok(user) => user,
            Err(e) => {
                return Err(IdpError::Unknown(format!(
                    "Failed to parse user response: {}",
                    e
                )))
            }
        };

        Ok(self.convert_kc_user_to_idp_user(kc_user))
    }

    async fn find_users_by_username(&self, username: &str) -> Result<Vec<IdpUser>, IdpError> {
        let headers = self.get_auth_headers()?;
        let url = format!(
            "{}/admin/realms/{}/users?username={}",
            self.base_url, self.realm, username
        );

        debug!("Searching users with username: {}", username);
        let response = match self.client.get(&url).headers(headers).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(IdpError::NetworkError(format!(
                    "Failed to connect to Keycloak: {}",
                    e
                )))
            }
        };

        if !response.status().is_success() {
            let error_text = match response.text().await {
                Ok(text) => text,
                Err(_) => "Unknown error".to_string(),
            };
            error!("Failed to search users: {}", error_text);
            return Err(IdpError::Unknown(format!(
                "Failed to search users: {}",
                error_text
            )));
        }

        let kc_users: Vec<KeycloakUser> = match response.json().await {
            Ok(users) => users,
            Err(e) => {
                return Err(IdpError::Unknown(format!(
                    "Failed to parse users response: {}",
                    e
                )))
            }
        };

        // Convert to IdpUser type
        let users = kc_users
            .into_iter()
            .map(|user| self.convert_kc_user_to_idp_user(user))
            .collect();

        Ok(users)
    }

    async fn get_groups(&self) -> Result<Vec<IdpGroupHeader>, IdpError> {
        let headers = self.get_auth_headers()?;
        let url = format!("{}/admin/realms/{}/groups", self.base_url, self.realm);

        debug!("Fetching groups from: {}", url);
        let response = match self.client.get(&url).headers(headers).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(IdpError::NetworkError(format!(
                    "Failed to connect to Keycloak: {}",
                    e
                )))
            }
        };

        if !response.status().is_success() {
            let error_text = match response.text().await {
                Ok(text) => text,
                Err(_) => "Unknown error".to_string(),
            };
            error!("Failed to get groups: {}", error_text);
            return Err(IdpError::Unknown(format!(
                "Failed to get groups: {}",
                error_text
            )));
        }

        let groups: Vec<IdpGroupHeader> = match response.json().await {
            Ok(groups) => groups,
            Err(e) => {
                return Err(IdpError::Unknown(format!(
                    "Failed to parse groups response: {}",
                    e
                )))
            }
        };

        info!("Successfully retrieved groups from Keycloak");
        Ok(groups)
    }

    async fn get_group(&self, group_id: Uuid) -> Result<IdpGroup, IdpError> {
        let headers = self.get_auth_headers()?;
        let url = format!(
            "{}/admin/realms/{}/groups/{}",
            self.base_url, self.realm, group_id
        );

        debug!("Fetching group from: {}", url);
        let response = match self.client.get(&url).headers(headers).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(IdpError::NetworkError(format!(
                    "Failed to connect to Keycloak: {}",
                    e
                )))
            }
        };

        if response.status().is_client_error() {
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Err(IdpError::NotFound(format!(
                    "Group with ID {} not found",
                    group_id
                )));
            } else {
                let error_text = match response.text().await {
                    Ok(text) => text,
                    Err(_) => "Unknown error".to_string(),
                };
                return Err(IdpError::PermissionDenied(format!(
                    "Permission denied: {}",
                    error_text
                )));
            }
        }

        if !response.status().is_success() {
            let error_text = match response.text().await {
                Ok(text) => text,
                Err(_) => "Unknown error".to_string(),
            };
            error!("Failed to get group: {}", error_text);
            return Err(IdpError::Unknown(format!(
                "Failed to get group: {}",
                error_text
            )));
        }

        let kc_group: KeycloakGroup = match response.json().await {
            Ok(group) => group,
            Err(e) => {
                return Err(IdpError::Unknown(format!(
                    "Failed to parse group response: {}",
                    e
                )))
            }
        };

        Ok(self.convert_kc_group_to_idp_group(kc_group))
    }

    async fn get_group_members(&self, group_id: Uuid) -> Result<Vec<IdpUser>, IdpError> {
        let headers = self.get_auth_headers()?;
        let url = format!(
            "{}/admin/realms/{}/groups/{}/members",
            self.base_url, self.realm, group_id
        );

        debug!("Fetching group members from: {}", url);
        let response = match self.client.get(&url).headers(headers).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(IdpError::NetworkError(format!(
                    "Failed to connect to Keycloak: {}",
                    e
                )))
            }
        };

        if response.status().is_client_error() {
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Err(IdpError::NotFound(format!(
                    "Group with ID {} not found",
                    group_id
                )));
            } else {
                let error_text = match response.text().await {
                    Ok(text) => text,
                    Err(_) => "Unknown error".to_string(),
                };
                return Err(IdpError::PermissionDenied(format!(
                    "Permission denied: {}",
                    error_text
                )));
            }
        }

        if !response.status().is_success() {
            let error_text = match response.text().await {
                Ok(text) => text,
                Err(_) => "Unknown error".to_string(),
            };
            error!("Failed to get group members: {}", error_text);
            return Err(IdpError::Unknown(format!(
                "Failed to get group members: {}",
                error_text
            )));
        }

        let kc_users: Vec<KeycloakUser> = match response.json().await {
            Ok(users) => users,
            Err(e) => {
                return Err(IdpError::Unknown(format!(
                    "Failed to parse group members response: {}",
                    e
                )))
            }
        };

        // Convert to IdpUser type
        let users = kc_users
            .into_iter()
            .map(|user| self.convert_kc_user_to_idp_user(user))
            .collect();

        Ok(users)
    }

    async fn get_user_groups(&self, user_id: Uuid) -> Result<Vec<IdpGroup>, IdpError> {
        let headers = self.get_auth_headers()?;
        let url = format!(
            "{}/admin/realms/{}/users/{}/groups",
            self.base_url, self.realm, user_id
        );

        debug!("Fetching user groups from: {}", url);
        let response = match self.client.get(&url).headers(headers).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(IdpError::NetworkError(format!(
                    "Failed to connect to Keycloak: {}",
                    e
                )))
            }
        };

        if response.status().is_client_error() {
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Err(IdpError::NotFound(format!(
                    "User with ID {} not found",
                    user_id
                )));
            } else {
                let error_text = match response.text().await {
                    Ok(text) => text,
                    Err(_) => "Unknown error".to_string(),
                };
                return Err(IdpError::PermissionDenied(format!(
                    "Permission denied: {}",
                    error_text
                )));
            }
        }

        if !response.status().is_success() {
            let error_text = match response.text().await {
                Ok(text) => text,
                Err(_) => "Unknown error".to_string(),
            };
            error!("Failed to get user groups: {}", error_text);
            return Err(IdpError::Unknown(format!(
                "Failed to get user groups: {}",
                error_text
            )));
        }

        let kc_groups: Vec<KeycloakGroup> = match response.json().await {
            Ok(groups) => groups,
            Err(e) => {
                return Err(IdpError::Unknown(format!(
                    "Failed to parse user groups response: {}",
                    e
                )))
            }
        };

        // Convert to IdpGroup type
        let groups = kc_groups
            .into_iter()
            .map(|group| self.convert_kc_group_to_idp_group(group))
            .collect();

        Ok(groups)
    }

    async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<IdpRole>, IdpError> {
        let headers = self.get_auth_headers()?;
        let url = format!(
            "{}/admin/realms/{}/users/{}/role-mappings",
            self.base_url, self.realm, user_id
        );

        debug!("Fetching user roles from: {}", url);
        let response = match self.client.get(&url).headers(headers).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(IdpError::NetworkError(format!(
                    "Failed to connect to Keycloak: {}",
                    e
                )))
            }
        };

        if response.status().is_client_error() {
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Err(IdpError::NotFound(format!(
                    "User with ID {} not found",
                    user_id
                )));
            } else {
                let error_text = match response.text().await {
                    Ok(text) => text,
                    Err(_) => "Unknown error".to_string(),
                };
                return Err(IdpError::PermissionDenied(format!(
                    "Permission denied: {}",
                    error_text
                )));
            }
        }

        if !response.status().is_success() {
            let error_text = match response.text().await {
                Ok(text) => text,
                Err(_) => "Unknown error".to_string(),
            };
            error!("Failed to get user roles: {}", error_text);
            return Err(IdpError::Unknown(format!(
                "Failed to get user roles: {}",
                error_text
            )));
        }

        let role_mappings: RoleMappingContainer = match response.json().await {
            Ok(mappings) => mappings,
            Err(e) => {
                return Err(IdpError::Unknown(format!(
                    "Failed to parse role mappings response: {}",
                    e
                )))
            }
        };

        let mut all_roles = Vec::new();

        // Add realm roles
        if let Some(realm_roles) = role_mappings.realm_mappings {
            all_roles.extend(realm_roles);
        }

        // Add client roles
        if let Some(client_mappings) = role_mappings.client_mappings {
            for (_, client_roles) in client_mappings {
                all_roles.extend(client_roles.mappings);
            }
        }

        // Convert to IdpRole type
        let roles = all_roles
            .into_iter()
            .map(|role| self.convert_kc_role_to_idp_role(role))
            .collect();

        Ok(roles)
    }

    fn flatten_groups(&self, groups: &[IdpGroup]) -> Vec<IdpGroup> {
        let mut flat_groups = Vec::new();
        let mut to_process = groups.to_vec();

        while !to_process.is_empty() {
            let current = to_process.remove(0);
            flat_groups.push(current.clone());

            // Find and queue up any subgroups (groups with this as parent)
            let subgroups = groups
                .iter()
                .filter(|g| g.parent_id.as_ref() == Some(&current.id))
                .cloned()
                .collect::<Vec<IdpGroup>>();

            to_process.extend(subgroups);
        }

        flat_groups
    }
}

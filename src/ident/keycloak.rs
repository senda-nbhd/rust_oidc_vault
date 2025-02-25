use super::{AiclIdentity, Role, TeamIdentity};
use super::idp_admin::{IdentityProvider, IdpConfig, IdpError, IdpGroup, IdpRole, IdpUser};
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
struct KeycloakUser {
    pub id: String,
    pub username: String,
    pub enabled: bool,
    pub email: Option<String>,
    pub firstName: Option<String>,
    pub lastName: Option<String>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
    #[serde(skip_deserializing)]
    pub groups: Vec<KeycloakGroup>,
    #[serde(skip_deserializing)]
    pub roles: Vec<KeycloakRole>,
}

#[derive(Deserialize, Debug, Clone)]
struct KeycloakGroup {
    pub id: String,
    pub name: String,
    pub path: String,
    pub subGroups: Option<Vec<KeycloakGroup>>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

#[derive(Deserialize, Debug, Clone)]
struct KeycloakRole {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub composite: bool,
    pub clientRole: bool,
    pub containerId: String,
}

#[derive(Deserialize, Debug)]
struct RoleMappingContainer {
    pub realmMappings: Option<Vec<KeycloakRole>>,
    pub clientMappings: Option<HashMap<String, ClientRoleMapping>>,
}

#[derive(Deserialize, Debug)]
struct ClientRoleMapping {
    pub id: String,
    pub client: String,
    pub mappings: Vec<KeycloakRole>,
}

#[derive(Deserialize, Debug)]
struct KeycloakClient {
    pub id: String,
    pub clientId: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
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
            first_name: kc_user.firstName,
            last_name: kc_user.lastName,
            enabled: kc_user.enabled,
            groups: kc_user
                .groups
                .into_iter()
                .map(|g| self.convert_kc_group_to_idp_group(g))
                .collect(),
            roles: kc_user
                .roles
                .into_iter()
                .map(|r| self.convert_kc_role_to_idp_role(r))
                .collect(),
            attributes: kc_user.attributes.unwrap_or_default(),
        }
    }

    fn convert_kc_group_to_idp_group(&self, kc_group: KeycloakGroup) -> IdpGroup {
        // Extract parent ID from path if possible
        let parent_id = if kc_group.path.contains('/') {
            let path_parts: Vec<&str> =
                kc_group.path.split('/').filter(|p| !p.is_empty()).collect();
            if path_parts.len() > 1 {
                // This is a non-root group, it has a parent
                None // We would need to look up the parent by path, but for simplicity we'll leave this as None
            } else {
                None
            }
        } else {
            None
        };

        IdpGroup {
            id: kc_group.id,
            name: kc_group.name,
            path: kc_group.path,
            parent_id,
            attributes: kc_group.attributes.unwrap_or_default(),
        }
    }

    fn convert_kc_role_to_idp_role(&self, kc_role: KeycloakRole) -> IdpRole {
        IdpRole {
            id: kc_role.id,
            name: kc_role.name,
            description: kc_role.description,
            is_composite: kc_role.composite,
            source: if kc_role.clientRole {
                format!("client:{}", kc_role.containerId)
            } else {
                "realm".to_string()
            },
        }
    }

    // Convert Keycloak's nested group structure to a flat list
    fn flatten_kc_groups(&self, groups: &[KeycloakGroup]) -> Vec<KeycloakGroup> {
        let mut flat_groups = Vec::new();

        for group in groups {
            // Add the current group
            flat_groups.push(group.clone());

            // Recursively add subgroups if any
            if let Some(ref sub_groups) = group.subGroups {
                flat_groups.extend(self.flatten_kc_groups(sub_groups));
            }
        }

        flat_groups
    }
}

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

    async fn get_user(&self, user_id: &str) -> Result<IdpUser, IdpError> {
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

        // Get user's groups and roles
        let mut user_with_details = kc_user.clone();

        // Get groups
        match self.get_user_groups(user_id).await {
            Ok(groups) => {
                // Convert back to Keycloak groups (internal conversion)
                let kc_groups = groups
                    .into_iter()
                    .map(|g| KeycloakGroup {
                        id: g.id,
                        name: g.name,
                        path: g.path,
                        subGroups: None,
                        attributes: Some(g.attributes),
                    })
                    .collect();
                user_with_details.groups = kc_groups;
            }
            Err(e) => {
                error!("Failed to get groups for user {}: {}", user_id, e);
                user_with_details.groups = vec![];
            }
        }

        // Get roles
        let url = format!(
            "{}/admin/realms/{}/users/{}/role-mappings",
            self.base_url, self.realm, user_id
        );
        let response = match self.client.get(&url).headers(headers.clone()).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(IdpError::NetworkError(format!(
                    "Failed to connect to Keycloak: {}",
                    e
                )))
            }
        };

        if response.status().is_success() {
            let role_mappings: RoleMappingContainer = match response.json().await {
                Ok(mappings) => mappings,
                Err(e) => {
                    return Err(IdpError::Unknown(format!(
                        "Failed to parse role mappings: {}",
                        e
                    )))
                }
            };

            // Add realm roles
            if let Some(realm_roles) = role_mappings.realmMappings {
                user_with_details.roles.extend(realm_roles);
            }

            // Add client roles
            if let Some(client_mappings) = role_mappings.clientMappings {
                for (_, client_roles) in client_mappings {
                    user_with_details.roles.extend(client_roles.mappings);
                }
            }
        }

        Ok(self.convert_kc_user_to_idp_user(user_with_details))
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

    async fn find_users_by_email(&self, email: &str) -> Result<Vec<IdpUser>, IdpError> {
        let headers = self.get_auth_headers()?;
        let url = format!(
            "{}/admin/realms/{}/users?email={}",
            self.base_url, self.realm, email
        );

        debug!("Searching users with email: {}", email);
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

    async fn get_groups(&self) -> Result<Vec<IdpGroup>, IdpError> {
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

        let kc_groups: Vec<KeycloakGroup> = match response.json().await {
            Ok(groups) => groups,
            Err(e) => {
                return Err(IdpError::Unknown(format!(
                    "Failed to parse groups response: {}",
                    e
                )))
            }
        };

        // Convert to IdpGroup type
        let groups = kc_groups
            .into_iter()
            .map(|group| self.convert_kc_group_to_idp_group(group))
            .collect();

        info!("Successfully retrieved groups from Keycloak");
        Ok(groups)
    }

    async fn get_group(&self, group_id: &str) -> Result<IdpGroup, IdpError> {
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

    async fn get_group_members(&self, group_id: &str) -> Result<Vec<IdpUser>, IdpError> {
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

    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<IdpGroup>, IdpError> {
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

    async fn get_roles(&self) -> Result<Vec<IdpRole>, IdpError> {
        let headers = self.get_auth_headers()?;
        let url = format!("{}/admin/realms/{}/roles", self.base_url, self.realm);

        debug!("Fetching roles from: {}", url);
        let response = match self.client.get(&url).headers(headers.clone()).send().await {
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
            error!("Failed to get roles: {}", error_text);
            return Err(IdpError::Unknown(format!(
                "Failed to get roles: {}",
                error_text
            )));
        }

        let kc_roles: Vec<KeycloakRole> = match response.json().await {
            Ok(roles) => roles,
            Err(e) => {
                return Err(IdpError::Unknown(format!(
                    "Failed to parse roles response: {}",
                    e
                )))
            }
        };

        // Convert to IdpRole type
        let roles: Vec<IdpRole> = kc_roles
            .into_iter()
            .map(|role| self.convert_kc_role_to_idp_role(role))
            .collect();

        // Get client roles as well
        let clients_url = format!("{}/admin/realms/{}/clients", self.base_url, self.realm);
        let clients_response = match self
            .client
            .get(&clients_url)
            .headers(headers.clone())
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

        if clients_response.status().is_success() {
            let clients: Vec<KeycloakClient> = match clients_response.json().await {
                Ok(c) => c,
                Err(e) => {
                    return Err(IdpError::Unknown(format!(
                        "Failed to parse clients response: {}",
                        e
                    )))
                }
            };

            // Get roles for each client
            let mut client_roles = Vec::new();
            for client in clients {
                let client_roles_url = format!(
                    "{}/admin/realms/{}/clients/{}/roles",
                    self.base_url, self.realm, client.id
                );

                let client_roles_response = match self
                    .client
                    .get(&client_roles_url)
                    .headers(headers.clone())
                    .send()
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        warn!("Failed to get roles for client {}: {}", client.id, e);
                        continue;
                    }
                };

                if client_roles_response.status().is_success() {
                    let mut roles: Vec<KeycloakRole> = match client_roles_response.json().await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("Failed to parse roles for client {}: {}", client.id, e);
                            continue;
                        }
                    };

                    client_roles.append(&mut roles);
                }
            }

            // Add client roles to the result
            let client_idp_roles = client_roles
                .into_iter()
                .map(|role| self.convert_kc_role_to_idp_role(role))
                .collect::<Vec<IdpRole>>();

            let mut all_roles = roles;
            all_roles.extend(client_idp_roles);
            return Ok(all_roles);
        }

        info!("Successfully retrieved roles from Keycloak");
        Ok(roles)
    }

    async fn get_user_roles(&self, user_id: &str) -> Result<Vec<IdpRole>, IdpError> {
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
        if let Some(realm_roles) = role_mappings.realmMappings {
            all_roles.extend(realm_roles);
        }

        // Add client roles
        if let Some(client_mappings) = role_mappings.clientMappings {
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

    async fn get_comprehensive_report(&self) -> Result<Vec<IdpUser>, IdpError> {
        // Get all users
        let mut users = self.get_users().await?;

        // For each user, get their groups and roles
        for user in &mut users {
            // Get user's groups
            match self.get_user_groups(&user.id).await {
                Ok(groups) => {
                    user.groups = groups;
                }
                Err(e) => {
                    error!("Failed to get groups for user {}: {}", user.id, e);
                    user.groups = vec![];
                }
            }

            // Get user's roles
            match self.get_user_roles(&user.id).await {
                Ok(roles) => {
                    user.roles = roles;
                }
                Err(e) => {
                    error!("Failed to get roles for user {}: {}", user.id, e);
                    user.roles = vec![];
                }
            }
        }

        Ok(users)
    }

    fn to_domain_user(&self, user: &IdpUser) -> Result<AiclIdentity,IdpError>  {
        // Extract team information from user's groups
        let team = user.groups.iter().find_map(|group| {
            // Look for team_id attribute in group
            let team_id = group
                .attributes
                .get("team_id")
                .and_then(|ids| ids.first())
                .and_then(|id_str| {
                    match Uuid::parse_str(id_str) {
                        Ok(id) => Some(id),
                        Err(err) => {
                            error!(group.name, "Failed to parse team ID: {}", err);
                            None
                        },
                    }
                });

            if let Some(id) = team_id {
                Some(TeamIdentity {
                    id,
                    name: group.name.clone(),
                })
            } else {
                None
            }
        });

        if user.roles.len() > 0 {
            tracing::error!(user.username, "User has multiple roles, only the first one will be used.");
        }
        if user.roles.len() == 0 {
            tracing::error!(user.username, "User has no roles.");
        }

        let role = match user.roles.first().map(|r| Role::parse(&r.name)) {
            Some(role) => role,
            _ => Role::Spectator,
        };


        Ok(AiclIdentity {
            name: format!(
                "{} {}",
                user.first_name.clone().unwrap_or_default(),
                user.last_name.clone().unwrap_or_default()
            )
            .trim()
            .to_string(),
            team,
            role,
        })
    }
}

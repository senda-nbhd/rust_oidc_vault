# App roles
resource "keycloak_role" "app_roles" {
  for_each    = { for role in local.roles : role.name => role }
  
  realm_id    = keycloak_realm.realm.id
  name        = each.key
  description = each.value.description
}

#------------------------------------------------------------------------------#
# Keycloak Realm
#------------------------------------------------------------------------------#

resource "keycloak_realm" "realm" {
  realm   = "app-realm"
  enabled = true
  
  display_name = "Application Realm"
  display_name_html = "<div>Application Realm</div>"
  
  # Security settings
  verify_email = false
  
  # Session settings
  sso_session_idle_timeout = "30m"
  sso_session_max_lifespan = "10h"
  offline_session_idle_timeout = "720h"
  
  # Token settings
  access_token_lifespan = "5m"
  refresh_token_max_reuse = 0
}

#------------------------------------------------------------------------------#
# Keycloak OIDC Client for Vault
#------------------------------------------------------------------------------#

resource "keycloak_openid_client" "vault_client" {
  realm_id            = keycloak_realm.realm.id
  client_id           = "vault"
  name                = "Vault"
  enabled             = true
  standard_flow_enabled = true
  
  access_type         = "CONFIDENTIAL"
  valid_redirect_uris = [
    "http://vault:8200/ui/vault/auth/oidc/oidc/callback",
    "http://localhost:8200/ui/vault/auth/oidc/oidc/callback",
    format("%s/*", local.app_url)
  ]
  
  client_authenticator_type = "client-secret"
}

resource "keycloak_openid_user_client_role_protocol_mapper" "vault_user_client_role_mapper" {
  realm_id   = keycloak_realm.realm.id
  client_id  = keycloak_openid_client.vault_client.id
  name       = "vault-user-client-role-mapper"
  claim_name = format("resource_access.%s.roles", keycloak_openid_client.vault_client.client_id)
  multivalued = true
}


#------------------------------------------------------------------------------#
# Keycloak OIDC Client for Rust Application
#------------------------------------------------------------------------------#

resource "keycloak_openid_client" "app_client" {
  realm_id            = keycloak_realm.realm.id
  client_id           = "rust-app"

  name                = "Rust Application"
  enabled             = true
  standard_flow_enabled = true

  access_type         = "CONFIDENTIAL"
  valid_redirect_uris = [
    format("%s/*", local.app_url),
  ]

  login_theme = "keycloak"
}

# Map user roles to the app client
resource "keycloak_openid_user_client_role_protocol_mapper" "app_user_client_role_mapper" {
  realm_id   = keycloak_realm.realm.id
  client_id  = keycloak_openid_client.app_client.id
  name       = "app-user-client-role-mapper"
  claim_name = format("resource_access.%s.roles", keycloak_openid_client.app_client.client_id)
  multivalued = true
}


# Map UUID attribute to token
resource "keycloak_openid_user_attribute_protocol_mapper" "id_mapper" {
  realm_id  = keycloak_realm.realm.id
  client_id = keycloak_openid_client.app_client.id
  name      = "user-id-mapper"
  
  user_attribute    = "id"
  claim_name        = "user_id"
  claim_value_type  = "String"
  
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

# Create a composite claim that includes the AiclIdentity structure
resource "keycloak_openid_user_session_note_protocol_mapper" "identity_mapper" {
  realm_id  = keycloak_realm.realm.id
  client_id = keycloak_openid_client.app_client.id
  name      = "identity-mapper"
  
  claim_name        = "aicl_identity"
  claim_value_type  = "String"
  session_note      = "identity"
  
  add_to_id_token     = true
  add_to_access_token = true
}

# Create group protocol mapper to include group membership in tokens
resource "keycloak_openid_group_membership_protocol_mapper" "group_mapper" {
  realm_id    = keycloak_realm.realm.id
  client_id   = keycloak_openid_client.app_client.id
  name        = "group-mapper"
  
  claim_name  = "groups"
  full_path   = true
  
  # Include groups in both ID and access tokens
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

# Create group attribute mappers to include team attributes in tokens
resource "keycloak_openid_group_membership_protocol_mapper" "team_id_mapper" {
  realm_id    = keycloak_realm.realm.id
  client_id   = keycloak_openid_client.app_client.id
  name        = "team-id-mapper"
  
  claim_name  = "team_id"
  full_path   = false
  
  # Include team ID in both ID and access tokens
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

# Create region attribute mapper to include region code in tokens
resource "keycloak_openid_user_attribute_protocol_mapper" "region_code_mapper" {
  realm_id  = keycloak_realm.realm.id
  client_id = keycloak_openid_client.app_client.id
  name      = "region-code-mapper"
  
  user_attribute    = "region_code"
  claim_name        = "region_code"
  claim_value_type  = "String"
  
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

# Create openid client role protocol mapper to include roles in tokens
resource "keycloak_openid_user_realm_role_protocol_mapper" "realm_roles_mapper" {
  realm_id    = keycloak_realm.realm.id
  client_id   = keycloak_openid_client.app_client.id
  name        = "realm-roles-mapper"
  
  claim_name  = "roles"
  multivalued = true
  
  # Include roles in both ID and access tokens
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}
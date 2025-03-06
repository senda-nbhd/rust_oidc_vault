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

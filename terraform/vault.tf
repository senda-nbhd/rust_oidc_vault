#------------------------------------------------------------------------------#
# Vault Configuration
#------------------------------------------------------------------------------#

# JWT Auth Backend for Keycloak
resource "vault_jwt_auth_backend" "keycloak" {
  path               = "oidc"
  type               = "oidc"
  default_role       = "default"
  oidc_discovery_url = format("http://keycloak:8080/realms/%s", keycloak_realm.realm.id)
  oidc_client_id     = keycloak_openid_client.vault_client.client_id
  oidc_client_secret = keycloak_openid_client.vault_client.client_secret

  tune {
    default_lease_ttl = "1h"
    max_lease_ttl     = "1h"
    token_type        = "default-service"
  }
}

# JWT Auth Role
resource "vault_jwt_auth_backend_role" "default" {
  backend        = vault_jwt_auth_backend.keycloak.path
  role_name      = "default"
  token_ttl      = 3600
  token_max_ttl  = 3600

  bound_audiences = [keycloak_openid_client.vault_client.client_id]
  user_claim      = "sub"
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
  role_type             = "oidc"
  allowed_redirect_uris = [
    "http://localhost:8200/ui/vault/auth/oidc/oidc/callback", 
    "http://vault:8200/ui/vault/auth/oidc/oidc/callback"
  ]
  groups_claim          = format("/resource_access/%s/roles", keycloak_openid_client.vault_client.client_id)
}

# Store App OIDC configuration in Vault
resource "vault_kv_secret_v2" "app_idp_config" {
  mount               = "secret"
  name                = "idp/app-config"
  delete_all_versions = true
  data_json = jsonencode({
    app_url       = local.app_url,
    provider_type = "keycloak"
    base_url      = local.keycloak_url,
    realm         = keycloak_realm.realm.id,
    issuer        = format("%s/realms/%s", local.keycloak_url, keycloak_realm.realm.id)
    client_id     = keycloak_openid_client.app_client.client_id
    client_secret = keycloak_openid_client.app_client.client_secret
    admin_username = local.keycloak_user,
    admin_password = local.keycloak_password,
  })
}

# Create policy for app to read OIDC config
resource "vault_policy" "app_oidc_policy" {
  name = "app-oidc-policy"

  policy = <<EOT
# Allow reading the OIDC configuration
path "secret/data/oidc/app-config" {
  capabilities = ["read"]
}
EOT
}

# Create token for app
resource "vault_token" "app_token" {
  policies = [vault_policy.app_oidc_policy.name]
  
  renewable = true
  ttl       = "720h"  # 30 days
  
  metadata = {
    description = "Token for Rust application to read OIDC configuration"
  }
}

# Add this to terraform/vault.tf after the existing JWT auth backend

#------------------------------------------------------------------------------#
# Configure Vault to accept OIDC authentication directly
#------------------------------------------------------------------------------#

# Configure the OIDC auth method for end users
resource "vault_jwt_auth_backend" "user_oidc" {
  path               = "oidc-user"
  type               = "oidc"
  default_role       = "user"
  oidc_discovery_url = format("http://keycloak:8080/realms/%s", keycloak_realm.realm.id)
  oidc_client_id     = keycloak_openid_client.app_client.client_id
  oidc_client_secret = keycloak_openid_client.app_client.client_secret

  # User info is not needed for our use case
  oidc_response_mode = "form_post"
  oidc_response_types = ["code"]

  tune {
    default_lease_ttl = "1h"
    max_lease_ttl     = "24h"
    token_type        = "default-service"
  }
}

# Create policy mapping for admin role
resource "vault_jwt_auth_backend_role" "admin_role" {
  backend        = vault_jwt_auth_backend.user_oidc.path
  role_name      = "admin"
  token_ttl      = 3600 # 1 hour
  token_max_ttl  = 86400 # 24 hours
  allowed_redirect_uris = [
    "http://localhost:4040/api/auth/oidc/callback",
    "http://app:4040/api/auth/oidc/callback"
  ]
  token_policies = ["admin"]
  bound_audiences = [keycloak_openid_client.app_client.client_id]
  user_claim      = "sub"
  bound_claims    = {
    "roles" = "admin"
  }
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
}

# Create policy mapping for team admin role
resource "vault_jwt_auth_backend_role" "team_admin_role" {
  backend        = vault_jwt_auth_backend.user_oidc.path
  role_name      = "team-admin"
  token_ttl      = 3600 # 1 hour
  token_max_ttl  = 86400 # 24 hours
  allowed_redirect_uris = [
    "http://localhost:4040/api/auth/oidc/callback",
    "http://app:4040/api/auth/oidc/callback"
  ]
  token_policies = ["team-admin"]
  bound_audiences = [keycloak_openid_client.app_client.client_id]
  user_claim      = "sub"
  bound_claims    = {
    "roles" = "team-admin"
  }
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
}

# Create policy mapping for team member role
resource "vault_jwt_auth_backend_role" "team_member_role" {
  backend        = vault_jwt_auth_backend.user_oidc.path
  role_name      = "team-member"
  token_ttl      = 3600 # 1 hour
  token_max_ttl  = 86400 # 24 hours
  allowed_redirect_uris = [
    "http://localhost:4040/api/auth/oidc/callback",
    "http://app:4040/api/auth/oidc/callback"
  ]
  token_policies = ["team-member"]
  bound_audiences = [keycloak_openid_client.app_client.client_id]
  user_claim      = "sub"
  bound_claims    = {
    "roles" = "team-member"
  }
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
}

# Create policy mapping for advisor role
resource "vault_jwt_auth_backend_role" "advisor_role" {
  backend        = vault_jwt_auth_backend.user_oidc.path
  role_name      = "advisor"
  token_ttl      = 3600 # 1 hour
  token_max_ttl  = 86400 # 24 hours
  allowed_redirect_uris = [
    "http://localhost:4040/api/auth/oidc/callback",
    "http://app:4040/api/auth/oidc/callback"
  ]
  token_policies = ["advisor"]
  bound_audiences = [keycloak_openid_client.app_client.client_id]
  user_claim      = "sub"
  bound_claims    = {
    "roles" = "advisor"
  }
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
}

# Create policy mapping for readonly role
resource "vault_jwt_auth_backend_role" "readonly_role" {
  backend        = vault_jwt_auth_backend.user_oidc.path
  role_name      = "readonly"
  token_ttl      = 3600 # 1 hour
  token_max_ttl  = 86400 # 24 hours
  allowed_redirect_uris = [
    "http://localhost:4040/api/auth/oidc/callback",
    "http://app:4040/api/auth/oidc/callback"
  ]
  token_policies = ["readonly"]
  bound_audiences = [keycloak_openid_client.app_client.client_id]
  user_claim      = "sub"
  bound_claims    = {
    "roles" = "readonly"
  }
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
}

# Configure allowed redirect URIs for OIDC
resource "vault_jwt_auth_backend_role" "user_oidc_callback" {
  backend        = vault_jwt_auth_backend.user_oidc.path
  role_name      = "callback"
  token_ttl      = 3600
  token_max_ttl  = 86400
  bound_audiences = [keycloak_openid_client.app_client.client_id]
  user_claim      = "sub"
  role_type       = "jwt"
  allowed_redirect_uris = [
    "http://localhost:4040/api/auth/oidc/callback",
    "http://app:4040/api/auth/oidc/callback"
  ]
}
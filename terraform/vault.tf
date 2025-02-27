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
resource "vault_kv_secret_v2" "app_oidc_config" {
  mount               = "secret"
  name                = "oidc/app-config"
  delete_all_versions = true
  data_json = jsonencode({
    app_url       = local.app_url,
    provider_type = "keycloak"
    base_url      = keycloak.url,
    realm         = keycloak_realm.realm.id,
    issuer        = format("%s/realms/%s", keycloak.url, keycloak_realm.realm.id)
    client_id     = keycloak_openid_client.app_client.client_id
    client_secret = keycloak_openid_client.app_client.client_secret
    admin_username = keycloak.username,
    admin_password = keycloak.password,
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
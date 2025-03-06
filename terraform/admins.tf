# Create global admin and spectator users

# Global Admin Users
resource "keycloak_user" "global_admin_users" {
  for_each = {
    "admin"  = { first_name = "Admin", last_name = "User", email = "admin@competition.org" },
    "admin2" = { first_name = "Super", last_name = "Admin", email = "admin2@competition.org" }
  }
  
  realm_id   = keycloak_realm.realm.id
  username   = each.key
  enabled    = true
  email      = each.value.email
  first_name = each.value.first_name
  last_name  = each.value.last_name

  initial_password {
    value     = "admin"
    temporary = false
  }
}

# Global Spectator Users
resource "keycloak_user" "global_spectator_users" {
  for_each = {
    "viewer_global"  = { first_name = "View", last_name = "Global", email = "viewer@competition.org" },
    "viewer_global2" = { first_name = "Read", last_name = "Global", email = "viewer2@competition.org" }
  }
  
  realm_id   = keycloak_realm.realm.id
  username   = each.key
  enabled    = true
  email      = each.value.email
  first_name = each.value.first_name
  last_name  = each.value.last_name

  initial_password {
    value     = "admin"
    temporary = false
  }
}

# Assign admin role to global admins
resource "keycloak_user_roles" "admin_role_assignment" {
  for_each = keycloak_user.global_admin_users
  
  realm_id = keycloak_realm.realm.id
  user_id  = each.value.id
  role_ids = [lookup(local.roles_map, "admin")]
}

# Assign spectator role to global spectators
resource "keycloak_user_roles" "spectator_role_assignment" {
  for_each = keycloak_user.global_spectator_users
  
  realm_id = keycloak_realm.realm.id
  user_id  = each.value.id
  role_ids = [lookup(local.roles_map, "spectator")]
}

# Vault policy for global admins
resource "vault_policy" "global_admin_policy" {
  name = "global-admin"

  policy = <<EOT
# Allow managing all secrets
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow managing auth methods
path "auth/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Allow managing Vault system configuration
path "sys/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOT
}

# Vault policy for global spectators
resource "vault_policy" "global_spectator_policy" {
  name = "global-spectator"

  policy = <<EOT
# Allow reading public secrets
path "secret/data/public/*" {
  capabilities = ["read", "list"]
}

# Allow reading teams information
path "secret/data/teams/*/metadata" {
  capabilities = ["read", "list"]
}

# Allow reading institutions information
path "secret/data/institutions/*/metadata" {
  capabilities = ["read", "list"]
}
EOT
}

# Create JWT/OIDC role for global admins
resource "vault_jwt_auth_backend_role" "global_admin_role" {
  backend        = vault_jwt_auth_backend.keycloak.path
  role_name      = "global-admin"
  token_ttl      = 3600  # 1 hour
  token_max_ttl  = 86400 # 24 hours
  token_policies = [vault_policy.global_admin_policy.name]
  
  bound_audiences = [keycloak_openid_client.app_client.client_id]
  user_claim      = "sub"
  bound_claims    = {
    "roles" = "admin"
  }
  
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
  
  allowed_redirect_uris = vault_jwt_auth_backend_role.default.allowed_redirect_uris
}

# Create JWT/OIDC role for global spectators
resource "vault_jwt_auth_backend_role" "global_spectator_role" {
  backend        = vault_jwt_auth_backend.keycloak.path
  role_name      = "global-spectator"
  token_ttl      = 3600  # 1 hour
  token_max_ttl  = 86400 # 24 hours
  token_policies = [vault_policy.global_spectator_policy.name]
  
  bound_audiences = [keycloak_openid_client.app_client.client_id]
  user_claim      = "sub"
  bound_claims    = {
    "roles" = "spectator"
  }
  
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
  
  allowed_redirect_uris = vault_jwt_auth_backend_role.default.allowed_redirect_uris
}
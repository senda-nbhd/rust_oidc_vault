# Team-specific Vault policies and roles
# This creates policies for team members to access their secrets

# Create a read-only policy for team members/spectators
resource "vault_policy" "team_read_policy" {
  name = "team-${var.team_name}-read"

  policy = <<EOT
# Allow reading team secrets
path "secret/data/teams/${var.team_name}/*" {
  capabilities = ["read", "list"]
}

# Allow reading team metadata
path "secret/metadata/teams/${var.team_name}/*" {
  capabilities = ["read", "list"]
}
EOT
}

# Create a read/write policy for team captains
resource "vault_policy" "team_admin_policy" {
  name = "team-${var.team_name}-admin"

  policy = <<EOT
# Allow managing team secrets
path "secret/data/teams/${var.team_name}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow managing team metadata
path "secret/metadata/teams/${var.team_name}/*" {
  capabilities = ["read", "list", "delete"]
}

# Allow team captains to create and manage team tokens
path "auth/token/create/team-${var.team_name}-admin" {
  capabilities = ["create", "read", "update"]
}

# Allow creating child tokens with reduced privileges
path "auth/token/create/team-${var.team_name}-read" {
  capabilities = ["create", "read", "update"]
}
EOT
}

# Create a Vault role for team members (using JWT/OIDC auth)
resource "vault_jwt_auth_backend_role" "team_member_role" {
  count = var.create_vault_roles ? 1 : 0

  backend        = var.vault_auth_backend_path
  role_name      = "team-${var.team_name}-member"
  role_type      = "jwt"
  token_ttl      = 3600  # 1 hour
  token_max_ttl  = 86400 # 24 hours
  token_policies = [vault_policy.team_read_policy.name]
  
  bound_audiences = [var.client_id]
  user_claim      = "sub"
  bound_claims    = {
    "groups" = "Teams/${var.team_name}"
  }
  
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
}

# Create a Vault role for team captains (using JWT/OIDC auth)
resource "vault_jwt_auth_backend_role" "team_captain_role" {
  count = var.create_vault_roles ? 1 : 0

  backend        = var.vault_auth_backend_path
  role_name      = "team-${var.team_name}-captain"
  role_type      = "jwt"
  token_ttl      = 3600  # 1 hour
  token_max_ttl  = 86400 # 24 hours
  token_policies = [vault_policy.team_admin_policy.name]
  
  bound_audiences = [var.client_id]
  user_claim      = "sub"
  bound_claims    = {
    "groups" = "Teams/${var.team_name}",
    "roles"  = "captain"
  }
  
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
}

# Create a team KV store if enabled
resource "vault_kv_secret_v2" "team_secret" {
  count = var.create_team_kv_store ? 1 : 0
  
  mount               = "secret"
  name                = "teams/${var.team_name}/config"
  delete_all_versions = true
  data_json = jsonencode({
    name        = var.team_name
    description = var.team_description
    created_at  = timestamp()
  })
}
# Institution-specific Vault policies and roles
# This creates policies for institution advisors to access their resources

# Create a read-only policy for institution spectators
resource "vault_policy" "institution_read_policy" {
  name = "institution-${var.institution_name}-read"

  policy = <<EOT
# Allow reading institution shared secrets
path "secret/data/institutions/${var.institution_name}/*" {
  capabilities = ["read", "list"]
}

# Allow reading institution metadata
path "secret/metadata/institutions/${var.institution_name}/*" {
  capabilities = ["read", "list"]
}

# Allow reading all teams under this institution
path "secret/data/teams/byinstitution/${var.institution_name}/*" {
  capabilities = ["read", "list"]
}
EOT
}

# Create a read/write policy for institution advisors
resource "vault_policy" "institution_advisor_policy" {
  name = "institution-${var.institution_name}-advisor"

  policy = <<EOT
# Allow managing institution secrets
path "secret/data/institutions/${var.institution_name}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow managing institution metadata
path "secret/metadata/institutions/${var.institution_name}/*" {
  capabilities = ["read", "list", "delete"]
}

# Allow reading all teams under this institution
path "secret/data/teams/byinstitution/${var.institution_name}/*" {
  capabilities = ["read", "list", "update"]
}

# Allow advisors to create and manage institution tokens
path "auth/token/create/institution-${var.institution_name}-advisor" {
  capabilities = ["create", "read", "update"]
}

# Allow creating child tokens with reduced privileges
path "auth/token/create/institution-${var.institution_name}-read" {
  capabilities = ["create", "read", "update"]
}
EOT
}

# Create a Vault role for institution spectators (using JWT/OIDC auth)
resource "vault_jwt_auth_backend_role" "institution_spectator_role" {
  count = var.create_vault_roles ? 1 : 0

  backend        = var.vault_auth_backend_path
  role_name      = "institution-${var.institution_name}-spectator"
  role_type      = "jwt"
  token_ttl      = 3600  # 1 hour
  token_max_ttl  = 86400 # 24 hours
  token_policies = [vault_policy.institution_read_policy.name]
  
  bound_audiences = [var.client_id]
  user_claim      = "sub"
  bound_claims    = {
    "roles"  = "spectator"
    groups = "/Institutions/${var.institution_name}"
  }
  groups_claim = "groups"
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
}

# Create a Vault role for institution advisors (using JWT/OIDC auth)
resource "vault_jwt_auth_backend_role" "institution_advisor_role" {
  count = var.create_vault_roles ? 1 : 0

  backend        = var.vault_auth_backend_path
  role_name      = "institution-${var.institution_name}-advisor"
  role_type      = "jwt"
  token_ttl      = 3600  # 1 hour
  token_max_ttl  = 86400 # 24 hours
  token_policies = [vault_policy.institution_advisor_policy.name]
  
  bound_audiences = [var.client_id]
  user_claim      = "sub"
  bound_claims    = {
    "roles"  = "advisor"
    groups = "/Institutions/${var.institution_name}"
  }
  groups_claim = "groups"
  
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
}

# Create an institution KV store if enabled
resource "vault_kv_secret_v2" "institution_secret" {
  count = var.create_institution_kv_store ? 1 : 0
  
  mount               = "secret"
  name                = "institutions/${var.institution_name}/config"
  delete_all_versions = true
  data_json = jsonencode({
    name        = var.institution_name
    description = var.institution_description
    created_at  = timestamp()
  })
}
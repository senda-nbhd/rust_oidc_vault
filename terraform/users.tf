# Updated users.tf based on SQL fixtures

resource "vault_identity_oidc_key" "keycloak_provider_key" {
  name      = "keycloak"
  algorithm = "RS256"
}

module "identity" {
  source = "./modules/identity"
  
  realm_id      = keycloak_realm.realm.id
  app_client_id = keycloak_openid_client.app_client.id
  vault_identity_oidc_key_name = vault_identity_oidc_key.keycloak_provider_key.name
  external_accessor = vault_jwt_auth_backend.keycloak.accessor

  # Define teams extracted from SQL fixtures
  institutions = [
    {
      name        = "School1"
      description = "School for authentication testing"
    },
    {
      name        = "School2"
      description = "School for authentication testing"
    },
  ]
  
  # Roles extracted from SQL fixtures
  roles = [
    {
      name        = "captain"
      description = "Team captain with administrative privileges"
      rules = [
        {
          path         = "/secret/*"
          capabilities = ["create", "update", "delete"]
        }
      ]
    },
    {
      name        = "student"
      description = "Regular team member"
      rules = [
        {
          path         = "/secret/*"
          capabilities = ["create", "update", "delete"]
        }
      ]
    },
    {
      name        = "spectator"
      description = "Read-only access to team resources"
      rules = [
        {
          path         = "/secret/*"
          capabilities = ["create", "update", "delete"]
        }
      ]
    },
    {
      name        = "admin"
      description = "System administrator with full access"
      rules = [
        {
          path         = "/secret/*"
          capabilities = ["create", "update", "delete"]
        }
      ]
    },
    {
      name        = "advisor"
      description = "Academic advisor for institutions"
      rules = [
        {
          path         = "/secret/*"
          capabilities = ["create", "update", "delete"]
        }
      ]
    }
  ]
}

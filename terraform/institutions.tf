# Create team groups as subgroups of regions
resource "keycloak_group" "institutions_parent" {
  realm_id  = keycloak_realm.realm.id
  name      = "Institutions"
}

# Institutions setup
module "school1" {
  source = "./modules/institution"
  
  realm_id               = keycloak_realm.realm.id
  institution_name       = "School1"
  institution_description = "First academic institution"
  institutions_parent_id = keycloak_group.institutions_parent.id
  realm_roles            = local.roles_map
  
  # Vault configuration
  create_vault_roles           = true
  create_institution_kv_store  = true
  vault_auth_backend_path      = vault_jwt_auth_backend.keycloak.path
  vault_auth_backend_allowed_redirect_uris = vault_jwt_auth_backend_role.default.allowed_redirect_uris
  client_id                    = keycloak_openid_client.app_client.client_id
  
  users = [
    {
      username   = "advisor1"
      email      = "advisor1@school1.org"
      first_name = "Advisor"
      last_name  = "One"
      password   = "admin"
      role       = "advisor"
    },
    {
      username   = "spec_school1"
      email      = "spectator@school1.org"
      first_name = "School"
      last_name  = "Spectator"
      password   = "spectator"
      role       = "spectator"
    }
  ]
}

module "school2" {
  source = "./modules/institution"
  
  realm_id               = keycloak_realm.realm.id
  institution_name       = "School2"
  institution_description = "Second academic institution"
  institutions_parent_id = keycloak_group.institutions_parent.id
  realm_roles            = local.roles_map
  
  # Vault configuration
  create_vault_roles           = true
  create_institution_kv_store  = true
  vault_auth_backend_path      = vault_jwt_auth_backend.keycloak.path
  vault_auth_backend_allowed_redirect_uris = vault_jwt_auth_backend_role.default.allowed_redirect_uris
  client_id                    = keycloak_openid_client.app_client.client_id
  
  users = [
    {
      username   = "advisor2"
      email      = "advisor2@school2.org"
      first_name = "Advisor"
      last_name  = "Two"
      password   = "admin"
      role       = "advisor"
    },
    {
      username   = "spec_school2"
      email      = "spectator@school2.org"
      first_name = "School"
      last_name  = "Spectator"
      password   = "spectator"
      role       = "spectator"
    }
  ]
}
# Create team groups as subgroups of regions
resource "keycloak_group" "teams_parent" {
  realm_id  = keycloak_realm.realm.id
  name      = "Teams"
}


# Team1 setup
module "team1" {
  source = "./modules/team"
  
  realm_id            = keycloak_realm.realm.id
  team_name           = "Team1"
  team_description    = "Team for authentication testing"
  teams_parent_id       = keycloak_group.teams_parent.id
  institution_group_id = module.school1.institution_group_id
  realm_roles         = local.roles_map
  
  # Vault configuration
  create_vault_roles      = true
  create_team_kv_store    = true
  vault_auth_backend_path = vault_jwt_auth_backend.keycloak.path
  vault_auth_backend_allowed_redirect_uris = vault_jwt_auth_backend_role.default.allowed_redirect_uris
  client_id               = keycloak_openid_client.app_client.client_id
  
  users = [
    {
      username   = "admin1"
      email      = "admin1@test.com"
      first_name = "Charles"
      last_name  = "Student"
      password   = "admin"
      role       = "captain"
    },
    {
      username   = "member1"
      email      = "member1@test.com"
      first_name = "Mike"
      last_name  = "Student"
      password   = "member"
      role       = "student"
    },
    {
      username   = "viewer1"
      email      = "viewer1@test.com"
      first_name = "Smith"
      last_name  = "Student"
      password   = "viewer"
      role       = "spectator"
    }
  ]
}

# Team2 setup
module "team2" {
  source = "./modules/team"
  
  realm_id            = keycloak_realm.realm.id
  team_name           = "Team2"
  team_description    = "Team for authentication testing"
  teams_parent_id       = keycloak_group.teams_parent.id
  institution_group_id = module.school1.institution_group_id
  realm_roles         = local.roles_map
  
  # Vault configuration
  create_vault_roles      = true
  create_team_kv_store    = true
  vault_auth_backend_path = vault_jwt_auth_backend.keycloak.path
  vault_auth_backend_allowed_redirect_uris = vault_jwt_auth_backend_role.default.allowed_redirect_uris
  client_id               = keycloak_openid_client.app_client.client_id
  
  users = [
    {
      username   = "admin2"
      email      = "admin2@test.com"
      first_name = "Clara"
      last_name  = "Student"
      password   = "admin"
      role       = "captain"
    },
    {
      username   = "member2"
      email      = "member2@test.com"
      first_name = "Megan"
      last_name  = "Student"
      password   = "member"
      role       = "student"
    },
    {
      username   = "viewer2"
      email      = "viewer2@test.com"
      first_name = "Stephanie"
      last_name  = "Student"
      password   = "viewer"
      role       = "spectator" 
    }
  ]
}

# Team3 setup
module "team3" {
  source = "./modules/team"
  
  realm_id            = keycloak_realm.realm.id
  team_name           = "Team3"
  team_description    = "Team for authentication testing"
  teams_parent_id       = keycloak_group.teams_parent.id
  institution_group_id = module.school2.institution_group_id
  realm_roles         = local.roles_map
  
  # Vault configuration
  create_vault_roles      = true
  create_team_kv_store    = true
  vault_auth_backend_path = vault_jwt_auth_backend.keycloak.path
  vault_auth_backend_allowed_redirect_uris = vault_jwt_auth_backend_role.default.allowed_redirect_uris
  client_id               = keycloak_openid_client.app_client.client_id
  
  users = [
    {
      username   = "admin3"
      email      = "admin3@test.com"
      first_name = "Clara"
      last_name  = "Student"
      password   = "admin"
      role       = "captain"
    },
    {
      username   = "member3"
      email      = "member3@test.com"
      first_name = "Megan"
      last_name  = "Student"
      password   = "member"
      role       = "student"
    },
    {
      username   = "viewer3"
      email      = "viewer3@test.com"
      first_name = "Stephanie"
      last_name  = "Student"
      password   = "viewer"
      role       = "spectator"
    }
  ]
}
# Team1 setup
module "team1" {
  source = "./modules/team"
  
  realm_id            = keycloak_realm.realm.id
  team_name           = "Team1"
  team_description    = "Team for authentication testing"
  team_group_id       = lookup(module.identity.groups, "Team1", "")
  institution_group_id = lookup(module.identity.groups, "School1", "")
  realm_roles         = module.identity.roles
  
  # Vault configuration
  create_vault_roles      = true
  create_team_kv_store    = true
  vault_auth_backend_path = "oidc-user"
  client_id               = keycloak_openid_client.app_client.client_id
  
  users = [
    {
      username   = "admin1"
      email      = "admin1@test.com"
      first_name = "Charles"
      last_name  = "Student"
      password   = "admin"
      role       = "CAPTAIN"
    },
    {
      username   = "member1"
      email      = "member1@test.com"
      first_name = "Mike"
      last_name  = "Student"
      password   = "member"
      role       = "STUDENT"
    },
    {
      username   = "viewer1"
      email      = "viewer1@test.com"
      first_name = "Smith"
      last_name  = "Student"
      password   = "viewer"
      role       = "SPECTATOR"
    }
  ]
}

# Team2 setup
module "team2" {
  source = "./modules/team"
  
  realm_id            = keycloak_realm.realm.id
  team_name           = "Team2"
  team_description    = "Team for authentication testing"
  team_group_id       = lookup(module.identity.groups, "Team2", "")
  institution_group_id = lookup(module.identity.groups, "School1", "")
  realm_roles         = module.identity.roles
  
  # Vault configuration
  create_vault_roles      = true
  create_team_kv_store    = true
  vault_auth_backend_path = "oidc-user"
  client_id               = keycloak_openid_client.app_client.client_id
  
  users = [
    {
      username   = "admin2"
      email      = "admin2@test.com"
      first_name = "Clara"
      last_name  = "Student"
      password   = "admin"
      role       = "CAPTAIN"
    },
    {
      username   = "member2"
      email      = "member2@test.com"
      first_name = "Megan"
      last_name  = "Student"
      password   = "member"
      role       = "STUDENT"
    },
    {
      username   = "viewer2"
      email      = "viewer2@test.com"
      first_name = "Stephanie"
      last_name  = "Student"
      password   = "viewer"
      role       = "SPECTATOR" 
    }
  ]
}

# Team3 setup
module "team3" {
  source = "./modules/team"
  
  realm_id            = keycloak_realm.realm.id
  team_name           = "Team3"
  team_description    = "Team for authentication testing"
  team_group_id       = lookup(module.identity.groups, "Team3", "")
  institution_group_id = lookup(module.identity.groups, "School2", "")
  realm_roles         = module.identity.roles
  
  # Vault configuration
  create_vault_roles      = true
  create_team_kv_store    = true
  vault_auth_backend_path = "oidc-user"
  client_id               = keycloak_openid_client.app_client.client_id
  
  users = [
    {
      username   = "admin3"
      email      = "admin3@test.com"
      first_name = "Clara"
      last_name  = "Student"
      password   = "admin"
      role       = "CAPTAIN"
    },
    {
      username   = "member3"
      email      = "member3@test.com"
      first_name = "Megan"
      last_name  = "Student"
      password   = "member"
      role       = "STUDENT"
    },
    {
      username   = "viewer3"
      email      = "viewer3@test.com"
      first_name = "Stephanie"
      last_name  = "Student"
      password   = "viewer"
      role       = "SPECTATOR"
    }
  ]
}
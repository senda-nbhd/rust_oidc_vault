# Example usage of the modules

module "identity" {
  source = "./modules/identity"
  
  realm_id      = keycloak_realm.realm.id
  app_client_id = keycloak_openid_client.app_client.id

  regions = [
    {
      name        = "Singapore"
      description = "Located in Southeast Asia"
      code       = "SG"
    }
  ]
  
  teams = [
    {
      id          = "team-engineering-123"
      name        = "Engineering"
      description = "Engineering team responsible for development"
      region      = "Singapore"
    },
    {
      id          = "team-research-456"
      name        = "Research"
      description = "Research team responsible for innovation"
      region      = "Singapore"
    },
    {
      id          = "team-academic-789"
      name        = "Academic"
      description = "Academic partners and collaborators"
      region      = "Singapore"
    }
  ]
  
  # Optional: Override default roles if needed
  roles = [
    {
      name        = "ADMIN"
      description = "Administrator role with full access"
    },
    {
      name        = "USER"
      description = "Standard user role with limited access"
    },
    {
      name        = "SPECTATOR"
      description = "Read-only role for viewing data"
    },
    {
      name        = "ACADEMIC_ADVISOR"
      description = "Role for academic advisors with specialized permissions"
    }
  ]
}

module "users" {
  source = "./modules/users"
  
  realm_id = keycloak_realm.realm.id
  roles    = module.identity.roles
  groups   = module.identity.groups
  
  users = [
    {
      username   = "alice"
      email      = "alice@domain.com"
      first_name = "Alice"
      last_name  = "Aliceberg"
      id         = "550e8400-e29b-41d4-a716-446655440000"
      password   = "alice"
      roles      = ["ADMIN", "USER"]
      team       = "Engineering"
    },
    {
      username   = "bob"
      email      = "bob@domain.com"
      first_name = "Bob"
      last_name  = "Bobsen"
      id         = "660e8400-e29b-41d4-a716-446655440001"
      password   = "bob"
      roles      = ["USER"]
      team       = "Engineering"
    },
    {
      username   = "carol"
      email      = "carol@university.edu"
      first_name = "Carol"
      last_name  = "Caroline"
      id         = "770e8400-e29b-41d4-a716-446655440002"
      password   = "carol"
      roles      = ["ACADEMIC_ADVISOR"]
      team       = "Academic"
    },
    {
      username   = "dave"
      email      = "dave@domain.com"
      first_name = "Dave"
      last_name  = "Davison"
      id         = "880e8400-e29b-41d4-a716-446655440003"
      password   = "dave"
      roles      = ["SPECTATOR"]
      team       = "Research"
    }
  ]
}
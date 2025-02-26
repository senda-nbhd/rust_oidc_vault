# Updated users.tf based on SQL fixtures

module "identity" {
  source = "./modules/identity"
  
  realm_id      = keycloak_realm.realm.id
  app_client_id = keycloak_openid_client.app_client.id

  # Define teams extracted from SQL fixtures
  institutions = [
    # Teams from team_setup.sql
    {
      name        = "School1"
      description = "School for authentication testing"
    },
    {
      name        = "School2"
      description = "School for authentication testing"
    },
  ]
  
  # Define teams extracted from SQL fixtures
  teams = [
    # Teams from team_setup.sql
    {
      name        = "Team1"
      description = "Team for authentication testing"
    },
    {
      name        = "Team2"
      description = "Team for authentication testing"
    },
    {
      name        = "Team3"
      description = "Team for authentication testing"
    },
  ]
  
  # Roles extracted from SQL fixtures
  roles = [
    # From team_setup.sql
    {
      name        = "CAPTAIN"
      description = "Team captain with administrative privileges"
    },
    {
      name        = "STUDENT"
      description = "Regular team member"
    },
    {
      name        = "SPECTATOR"
      description = "Read-only access to team resources"
    },
    # From admin_setup.sql
    {
      name        = "ROOT"
      description = "System administrator with full access"
    },
    {
      name        = "ADVISOR"
      description = "Academic advisor for institutions"
    },
    {
      name        = "VIEWER"
      description = "Read-only access to system resources"
    }
  ]
}

module "users" {
  source = "./modules/users"
  
  realm_id = keycloak_realm.realm.id
  roles    = module.identity.roles
  groups   = module.identity.groups
  
  users = [
    # Team users from team_setup.sql
    {
      username   = "admin1"
      email      = "admin1@test.com"
      first_name = "Charles"
      last_name  = ""
      password   = "admin"
      roles      = ["CAPTAIN"]
      team       = "Team1"
      institution = "School1"
    },
    {
      username   = "member1"
      email      = "member1@test.com"
      first_name = "Mike"
      last_name  = ""
      password   = "member"
      roles      = ["STUDENT"]
      team       = "Team1"
      institution = "School1"
    },
    {
      username   = "viewer1"
      email      = "viewer1@test.com"
      first_name = "Smith"
      last_name  = ""
      password   = "viewer"
      roles      = ["TEAM_SPECTATOR"]
      team       = "Team1"
      institution = "School1"
    },
    {
      username   = "admin2"
      email      = "admin2@test.com"
      first_name = "Clara"
      last_name  = ""
      password   = "admin"
      roles      = ["CAPTAIN"]
      team       = "Team2"
      institution = "School1"
    },
    {
      username   = "member2"
      email      = "member2@test.com"
      first_name = "Megan"
      last_name  = ""
      password   = "member"
      roles      = ["STUDENT"]
      team       = "Team2"
      institution = "School1"
    },
    {
      username   = "viewer2"
      email      = "viewer2@test.com"
      first_name = "Stephanie"
      last_name  = ""
      password   = "viewer"
      roles      = ["TEAM_SPECTATOR"]
      team       = "Team2"
      institution = "School1"
    },

        {
      username   = "admin3"
      email      = "admin3@test.com"
      first_name = "Clara"
      last_name  = ""
      password   = "admin"
      roles      = ["CAPTAIN"]
      team       = "Team3"
      institution = "School2"
    },
    {
      username   = "member3"
      email      = "member3@test.com"
      first_name = "Megan"
      last_name  = ""
      password   = "member"
      roles      = ["STUDENT"]
      team       = "Team3"
      institution = "School2"
    },
    {
      username   = "viewer3"
      email      = "viewer3@test.com"
      first_name = "Stephanie"
      last_name  = ""
      password   = "viewer"
      roles      = ["TEAM_SPECTATOR"]
      team       = "Team3"
      institution = "School2"
    },
    # Advisors 
    {
      username   = "advisor1"
      email      = "advisor1@competition.org"
      first_name = "Advisor"
      last_name  = ""
      password   = "admin"
      roles      = ["ADVISOR"]
      team       = null
      institution = "School1"
    },
    {
      username   = "advisor2"
      email      = "advisor2@competition.org"
      first_name = "Advisor"
      last_name  = ""
      password   = "admin"
      roles      = ["ADVISOR"]
      team       = null
      institution = "School2"
    },
    
    # Admin users from admin_setup.sql
    {
      username   = "root"
      email      = "root@competition.org"
      first_name = "Admin"
      last_name  = ""
      password   = "admin"
      roles      = ["ROOT"]
      team       = null
      institution = null
    },
    {
      username   = "root2"
      email      = "root2@competition.org"
      first_name = "Super"
      last_name  = ""
      password   = "admin"
      roles      = ["ROOT"]
      team       = null
      institution = null
    },
    {
      username   = "viewer_global"
      email      = "viewer@competition.org"
      first_name = "View"
      last_name  = ""
      password   = "admin"
      roles      = ["VIEWER"]
      team       = null
      institution = null
    },
    {
      username   = "viewer_global2"
      email      = "viewer2@competition.org"
      first_name = "Read"
      last_name  = ""
      password   = "admin"
      roles      = ["VIEWER"]
      team       = null
      institution = null
    }
  ]
}

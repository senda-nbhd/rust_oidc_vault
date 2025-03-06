# Admin users setup
module "admin_users" {
  source = "./modules/admin"
  
  realm_id = keycloak_realm.realm.id
  realm_roles = module.identity.roles
  institution_groups = {
    for name, id in module.identity.groups :
    name => id if contains(["School1", "School2"], name)
  }
  
  users = [
    # Advisors
    {
      username    = "advisor1"
      email       = "advisor1@school1.org"
      first_name  = "Advisor"
      last_name   = "Advisor"
      password    = "admin"
      role        = "ADVISOR"
      institution = "School1"
    },
    {
      username    = "advisor2"
      email       = "advisor2@school2.org"
      first_name  = "Advisor"
      last_name   = "Advisor"
      password    = "admin"
      role        = "ADVISOR"
      institution = "School2"
    },
    
    # Admin users
    {
      username    = "root"
      email       = "root@competition.org"
      first_name  = "Admin"
      last_name   = "Admin"
      password    = "admin"
      role        = "ROOT"
      institution = null
    },
    {
      username    = "root2"
      email       = "root2@competition.org"
      first_name  = "Super"
      last_name   = "Admin"
      password    = "admin"
      role        = "ROOT"
      institution = null
    },
    {
      username    = "viewer_global"
      email       = "viewer@competition.org"
      first_name  = "View"
      last_name   = "View"
      password    = "admin"
      role        = "SPECTATOR"
      institution = null
    },
    {
      username    = "viewer_global2"
      email       = "viewer2@competition.org"
      first_name  = "Read"
      last_name   = "View"
      password    = "admin"
      role        = "SPECTATOR"
      institution = null
    }
  ]
}
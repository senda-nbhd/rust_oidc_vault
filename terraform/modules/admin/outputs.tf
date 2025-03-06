output "user_ids" {
  description = "Map of usernames to Keycloak user IDs"
  value       = { for k, v in keycloak_user.admin_users : k => v.id }
}

output "root_ids" {
  description = "List of root admin user IDs"
  value       = [
    for username, user in keycloak_user.admin_users : 
    user.id if contains([for u in var.users : u.username if u.role == "ROOT"], username)
  ]
}

output "advisor_ids" {
  description = "Map of advisors by institution"
  value = {
    for institution in distinct([for u in local.advisors : u.institution if u.institution != null]) :
    institution => [
      for username, user in keycloak_user.admin_users :
      user.id if contains([for u in local.advisors : u.username if u.institution == institution], username)
    ]
  }
}
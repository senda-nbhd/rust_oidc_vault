output "user_ids" {
  description = "Map of usernames to Keycloak user IDs"
  value       = { for k, v in keycloak_user.team_users : k => v.id }
}

output "captain_ids" {
  description = "List of captain user IDs"
  value       = [
    for username, user in keycloak_user.team_users : 
    user.id if contains([for u in var.users : u.username if u.role == "CAPTAIN"], username)
  ]
}

output "student_ids" {
  description = "List of student user IDs"
  value       = [
    for username, user in keycloak_user.team_users : 
    user.id if contains([for u in var.users : u.username if u.role == "STUDENT"], username)
  ]
}

output "spectator_ids" {
  description = "List of spectator user IDs"
  value       = [
    for username, user in keycloak_user.team_users : 
    user.id if contains([for u in var.users : u.username if u.role == "SPECTATOR"], username)
  ]
}

# Vault-related outputs
output "vault_policies" {
  description = "The Vault policies created for this team"
  value = {
    team_read_policy  = vault_policy.team_read_policy.name
    team_admin_policy = vault_policy.team_admin_policy.name
  }
}

output "vault_roles" {
  description = "The Vault roles created for this team"
  value = var.create_vault_roles ? {
    member_role  = vault_jwt_auth_backend_role.team_member_role[0].role_name
    captain_role = vault_jwt_auth_backend_role.team_captain_role[0].role_name
  } : null
}

output "secrets_path" {
  description = "The path to the team's secrets in Vault"
  value = "secret/teams/${var.team_name}/"
}
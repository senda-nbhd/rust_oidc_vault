output "user_ids" {
  description = "Map of usernames to Keycloak user IDs"
  value       = { for k, v in keycloak_user.institution_users : k => v.id }
}

output "advisor_ids" {
  description = "List of advisor user IDs"
  value       = [
    for username, user in keycloak_user.institution_users : 
    user.id if contains([for u in var.users : u.username if u.role == "ADVISOR"], username)
  ]
}

output "spectator_ids" {
  description = "List of institution spectator user IDs"
  value       = [
    for username, user in keycloak_user.institution_users : 
    user.id if contains([for u in var.users : u.username if u.role == "SPECTATOR"], username)
  ]
}

output "institution_group_id" {
  description = "The ID of the institution group"
  value = var.create_institution_group ? keycloak_group.institution_group[0].id : var.institution_group_id
}

# Vault-related outputs
output "vault_policies" {
  description = "The Vault policies created for this institution"
  value = {
    institution_read_policy    = vault_policy.institution_read_policy.name
    institution_advisor_policy = vault_policy.institution_advisor_policy.name
  }
}

output "vault_roles" {
  description = "The Vault roles created for this institution"
  value = var.create_vault_roles ? {
    spectator_role = vault_jwt_auth_backend_role.institution_spectator_role[0].role_name
    advisor_role   = vault_jwt_auth_backend_role.institution_advisor_role[0].role_name
  } : null
}

output "secrets_path" {
  description = "The path to the institution's secrets in Vault"
  value = "secret/institutions/${var.institution_name}/"
}
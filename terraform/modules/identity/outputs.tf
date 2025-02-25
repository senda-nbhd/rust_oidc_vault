output "roles" {
  description = "Map of role names to role IDs"
  value       = local.roles_map
}

output "groups" {
  description = "Map of group names to group IDs"
  value       = local.groups_map
}

output "composite_admin_role_id" {
  description = "ID of the composite admin role"
  value       = keycloak_role.composite_admin_role.id
}
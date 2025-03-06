output "roles" {
  description = "Map of role names to role IDs"
  value       = local.roles_map
}

output "groups" {
  description = "Map of team names to group IDs"
  value       = local.groups_map
}

output "institutions_parent_id" {
  description = "Parent group ID for institutions"
  value       = keycloak_group.institutions_parent.id
}

output "teams_parent_id" {
  description = "Parent group ID for teams"
  value       = keycloak_group.teams_parent.id
}


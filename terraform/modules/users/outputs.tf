output "user_ids" {
  description = "Map of usernames to Keycloak user IDs"
  value       = { for k, v in keycloak_user.users : k => v.id }
}
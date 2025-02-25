# Create realm roles for the application
resource "keycloak_role" "app_roles" {
  for_each    = { for role in var.roles : role.name => role }
  
  realm_id    = var.realm_id
  name        = each.key
  description = each.value.description
}

# Create role mappings for common actions
# You can create composite roles if needed
resource "keycloak_role" "composite_admin_role" {
  realm_id    = var.realm_id
  name        = "COMPOSITE_ADMIN"
  description = "Composite role with all permissions"
  composite_roles = [
    for role in keycloak_role.app_roles : role.id if role.name != "ADMIN"
  ]
}

# Create openid client role protocol mapper to include roles in tokens
resource "keycloak_openid_user_realm_role_protocol_mapper" "realm_roles_mapper" {
  realm_id    = var.realm_id
  client_id   = var.app_client_id
  name        = "realm-roles-mapper"
  
  claim_name  = "roles"
  multivalued = true
  
  # Include roles in both ID and access tokens
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}
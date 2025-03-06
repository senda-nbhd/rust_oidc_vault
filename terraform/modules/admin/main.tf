# Admin Module - Creates administration users
# This module sets up global admin users and advisors

terraform {
  required_providers {
    keycloak = {
      source  = "mrparkers/keycloak"
      version = "4.4.0"
    }
  }
}

locals {
  # Separate users by role type
  root_users = [for user in var.users : user if user.role == "root"]
  advisors = [for user in var.users : user if user.role == "advisor"]
  viewers = [for user in var.users : user if user.role == "spectator"]
}

# Create admin users
resource "keycloak_user" "admin_users" {
  for_each = { for user in var.users : user.username => user }
  
  realm_id   = var.realm_id
  username   = each.key
  enabled    = true

  email      = each.value.email
  first_name = each.value.first_name
  last_name  = each.value.last_name

  initial_password {
    value     = each.value.password
    temporary = false
  }
}

# Assign roles to admin users
resource "keycloak_user_roles" "admin_user_roles" {
  for_each = { for user in var.users : user.username => user }
  
  realm_id = var.realm_id
  user_id  = keycloak_user.admin_users[each.key].id

  role_ids = [
    lookup(var.realm_roles, each.value.role, "")
  ]
}

# Add advisors to their institution groups
resource "keycloak_group_memberships" "advisor_institution_memberships" {
  for_each = {
    for user in local.advisors : user.username => user
    if user.institution != null
  }
  
  realm_id = var.realm_id
  group_id = lookup(var.institution_groups, each.value.institution, null)
  
  members = [each.key]

  depends_on = [keycloak_user.admin_users]
}
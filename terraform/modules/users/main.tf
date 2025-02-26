# User Module - User creation and assignment

terraform {
  required_providers {
    keycloak = {
      source  = "mrparkers/keycloak"
      version = "4.4.0"
    }
  }
}

# Create users
resource "keycloak_user" "users" {
  for_each  = { for user in var.users : user.username => user }
  
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

# Assign roles to users
resource "keycloak_user_roles" "user_roles" {
  for_each = { for user in var.users : user.username => user }
  
  realm_id = var.realm_id
  user_id  = keycloak_user.users[each.key].id

  role_ids = [
    for role_name in each.value.roles : 
    lookup(var.roles, role_name, "")
    if lookup(var.roles, role_name, "") != ""
  ]
}

# Create a map of users by team
locals {
  # Collect all group memberships in a flat structure
  all_user_group_memberships = concat(
    # Team memberships
    [for user in var.users : 
      {
        username = user.username
        group_name = user.team
      } if user.team != null
    ],
    # Institution memberships
    [for user in var.users : 
      {
        username = user.username
        group_name = user.institution
      } if user.institution != null
    ]
  )
  
  # Group by group_name for keycloak_group_memberships resource
  memberships_by_group = {
    for group_name, items in {
      for membership in local.all_user_group_memberships : 
      membership.group_name => membership...
    } : group_name => items
  }
}

# Single resource for all group memberships
resource "keycloak_group_memberships" "all_memberships" {
  for_each = local.memberships_by_group
  
  realm_id = var.realm_id
  group_id = lookup(var.groups, each.key, "")
  
  members = [
    for item in each.value : item.username
  ]

  depends_on = [keycloak_user.users]
}
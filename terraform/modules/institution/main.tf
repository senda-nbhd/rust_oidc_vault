# Institution Module - Creates an institution with its advisors
# This module creates an institution group and its advisor members with appropriate roles

terraform {
  required_providers {
    keycloak = {
      source  = "mrparkers/keycloak"
      version = "4.4.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "4.6.0"
    }
  }
}

locals {
  # Create a map of institution members by role for easier processing
  institution_members = {
    advisors   = [for user in var.users : user if user.role == "ADVISOR"]
    spectators = [for user in var.users : user if user.role == "SPECTATOR"]
  }
}

# Create users for this institution
resource "keycloak_user" "institution_users" {
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

# Assign roles to users
resource "keycloak_user_roles" "institution_user_roles" {
  for_each = { for user in var.users : user.username => user }
  
  realm_id = var.realm_id
  user_id  = keycloak_user.institution_users[each.key].id

  role_ids = [
    lookup(var.realm_roles, each.value.role, "")
  ]
}

# Create institution group if it doesn't exist yet
resource "keycloak_group" "institution_group" {
  count = var.create_institution_group ? 1 : 0
  
  realm_id  = var.realm_id
  name      = var.institution_name
  parent_id = var.institutions_parent_id
  
  attributes = {
    "institution_description" = var.institution_description
  }
}

# Add users to the institution group
resource "keycloak_group_memberships" "institution_memberships" {
  realm_id = var.realm_id
  group_id = var.create_institution_group ? keycloak_group.institution_group[0].id : var.institution_group_id
  
  members = [
    for username, user in keycloak_user.institution_users : user.username
  ]
}
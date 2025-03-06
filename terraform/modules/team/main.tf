# Team Module - Creates a team with its members
# This module creates a team group and its members with appropriate roles

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
  # Create a map of team members by role for easier processing
  team_members = {
    captain   = [for user in var.users : user if user.role == "CAPTAIN"]
    students  = [for user in var.users : user if user.role == "STUDENT"]
    spectators = [for user in var.users : user if user.role == "SPECTATOR"]
  }
}

# Create users for this team
resource "keycloak_user" "team_users" {
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
resource "keycloak_user_roles" "team_user_roles" {
  for_each = { for user in var.users : user.username => user }
  
  realm_id = var.realm_id
  user_id  = keycloak_user.team_users[each.key].id

  role_ids = [
    lookup(var.realm_roles, each.value.role, "")
  ]
}

# Create team groups as subgroups of regions
resource "keycloak_group" "team_group" {
  
  realm_id  = var.realm_id
  name      = var.team_name
  parent_id = var.teams_parent_id
  
  attributes = {
    "team_description" = var.team_description
  }
}

# Add users to the team group
resource "keycloak_group_memberships" "team_memberships" {
  realm_id = var.realm_id
  group_id = keycloak_group.team_group.id
  
  members = [
    for username, user in keycloak_user.team_users : user.username
  ]
}

# Add users to their institution group
resource "keycloak_group_memberships" "institution_memberships" {
  #count = var.institution_group_id != null ? 1 : 0
  
  realm_id = var.realm_id
  group_id = var.institution_group_id
  
  members = [
    for username, user in keycloak_user.team_users : user.username
  ]
}
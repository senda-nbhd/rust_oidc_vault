# Identity Module - Main Configuration
# This module creates the role and group structure for the application

terraform {
  required_providers {
    keycloak = {
      source  = "mrparkers/keycloak"
      version = ">= 3.0.0"
    }
  }
}

# Local variables
locals {
  # Create a map of roles for easier access
  roles_map = { for role in keycloak_role.app_roles : role.name => role.id }
  
  # Create a map of groups for easier access
  groups_map = { for group in keycloak_group.teams : group.name => group.id }
}
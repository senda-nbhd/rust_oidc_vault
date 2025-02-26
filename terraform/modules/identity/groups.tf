
# Create team groups as subgroups of regions
resource "keycloak_group" "institutions_parent" {
  realm_id  = var.realm_id
  name      = "Institutions"
}

# Create team groups as subgroups of regions
resource "keycloak_group" "institutions" {
  for_each = { for team in var.institutions : team.name => team }
  
  realm_id  = var.realm_id
  name      = each.key
  parent_id = keycloak_group.institutions_parent.id
  
  attributes = {
    "institution_description" = each.value.description
  }
}

# Create team groups as subgroups of regions
resource "keycloak_group" "teams_parent" {
  
  realm_id  = var.realm_id
  name      = "Teams"
}

# Create team groups as subgroups of regions
resource "keycloak_group" "teams" {
  for_each = { for team in var.teams : team.name => team }
  
  realm_id  = var.realm_id
  name      = each.key
  parent_id = keycloak_group.teams_parent.id
  
  attributes = {
    "team_description" = each.value.description
  }
}

# Create group protocol mapper to include group membership in tokens
resource "keycloak_openid_group_membership_protocol_mapper" "group_mapper" {
  realm_id    = var.realm_id
  client_id   = var.app_client_id
  name        = "group-mapper"
  
  claim_name  = "groups"
  full_path   = true
  
  # Include groups in both ID and access tokens
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}


# Create group attribute mappers to include team attributes in tokens
resource "keycloak_openid_group_membership_protocol_mapper" "team_id_mapper" {
  realm_id    = var.realm_id
  client_id   = var.app_client_id
  name        = "team-id-mapper"
  
  claim_name  = "team_id"
  full_path   = false
  
  # Include team ID in both ID and access tokens
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

# Create region attribute mapper to include region code in tokens
resource "keycloak_openid_user_attribute_protocol_mapper" "region_code_mapper" {
  realm_id  = var.realm_id
  client_id = var.app_client_id
  name      = "region-code-mapper"
  
  user_attribute    = "region_code"
  claim_name        = "region_code"
  claim_value_type  = "String"
  
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}
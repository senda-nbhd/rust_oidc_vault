

# Create team groups as subgroups of regions
resource "keycloak_group" "regions" {
  for_each = { for region in var.regions : region.name => region }
  
  realm_id  = var.realm_id
  name      = each.key

  attributes = {
    "region_description" = each.value.description
  }
}

# Create team groups as subgroups of regions
resource "keycloak_group" "teams" {
  for_each = { for team in var.teams : team.name => team }
  
  realm_id  = var.realm_id
  parent_id = keycloak_group.regions[each.value.region].id
  name      = each.key
  
  attributes = {
    "team_id"          = each.value.id
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
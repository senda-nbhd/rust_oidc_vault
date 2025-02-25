# Protocol mappers for custom user attributes

# Map UUID attribute to token
resource "keycloak_openid_user_attribute_protocol_mapper" "id_mapper" {
  realm_id  = var.realm_id
  client_id = var.app_client_id
  name      = "user-id-mapper"
  
  user_attribute    = "id"
  claim_name        = "user_id"
  claim_value_type  = "String"
  
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

# Create a composite claim that includes the AiclIdentity structure
resource "keycloak_openid_user_session_note_protocol_mapper" "identity_mapper" {
  realm_id  = var.realm_id
  client_id = var.app_client_id
  name      = "identity-mapper"
  
  claim_name        = "aicl_identity"
  claim_value_type  = "String"
  session_note      = "identity"
  
  add_to_id_token     = true
  add_to_access_token = true
}
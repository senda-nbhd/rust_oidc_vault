# Create realm roles for the application
resource "keycloak_role" "app_roles" {
  for_each    = { for role in var.roles : role.name => role }
  
  realm_id    = var.realm_id
  name        = each.key
  description = each.value.description
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

#------------------------------------------------------------------------------#
# Vault policy
#------------------------------------------------------------------------------#

data "vault_policy_document" "policy" {
  count = length(var.roles)

  dynamic "rule" {
    for_each = var.roles[count.index].rules
    content {
      path = rule.value.path
      capabilities = rule.value.capabilities
    }
  }
}

resource "vault_policy" "policy" {
  count = length(var.roles)
  name   = var.roles[count.index].name
  policy = data.vault_policy_document.policy[count.index].hcl
}

#------------------------------------------------------------------------------#
# Vault external group
#------------------------------------------------------------------------------#

resource "vault_identity_oidc_role" "role" {
  count = length(var.roles)
  name = var.roles[count.index].name
  key  = var.vault_identity_oidc_key_name
}

resource "vault_identity_group" "group" {
  count = length(var.roles)
  name     = vault_identity_oidc_role.role[count.index].name
  type     = "external"
  policies = [
    vault_policy.policy[count.index].name
  ]
}

resource "vault_identity_group_alias" "reader_group_alias" {
  count = length(var.roles)
  name           = var.roles[count.index].name
  mount_accessor = var.external_accessor
  canonical_id   = vault_identity_group.group[count.index].id
}
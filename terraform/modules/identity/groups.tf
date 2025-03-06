
# Create team groups as subgroups of regions
resource "keycloak_group" "institutions_parent" {
  realm_id  = var.realm_id
  name      = "Institutions"
}

resource "keycloak_group" "institutions" {
  for_each = { for inst in var.institutions : inst.name => inst }
  
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

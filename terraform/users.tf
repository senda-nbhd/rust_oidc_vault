#------------------------------------------------------------------------------#
# Keycloak Users
#------------------------------------------------------------------------------#

resource "keycloak_user" "user_alice" {
  realm_id   = keycloak_realm.realm.id
  username   = "alice"
  enabled    = true

  email      = "alice@domain.com"
  first_name = "Alice"
  last_name  = "Aliceberg"

  initial_password {
    value     = "alice"
    temporary = false
  }
}

resource "keycloak_user" "user_bob" {
  realm_id   = keycloak_realm.realm.id
  username   = "bob"
  enabled    = true

  email      = "bob@domain.com"
  first_name = "Bob"
  last_name  = "Bobsen"

  initial_password {
    value     = "bob"
    temporary = false
  }
}

# Assign Vault roles to users
resource "keycloak_user_roles" "alice_vault_roles" {
  realm_id = keycloak_realm.realm.id
  user_id  = keycloak_user.user_alice.id

  role_ids = [
    keycloak_role.vault_reader_role.id
  ]
}

resource "keycloak_user_roles" "bob_vault_roles" {
  realm_id = keycloak_realm.realm.id
  user_id  = keycloak_user.user_bob.id

  role_ids = [
    keycloak_role.vault_management_role.id
  ]
}

# Assign app roles to users
resource "keycloak_user_roles" "alice_app_roles" {
  realm_id = keycloak_realm.realm.id
  user_id  = keycloak_user.user_alice.id

  role_ids = [
    keycloak_role.app_reader_role.id
  ]
}

resource "keycloak_user_roles" "bob_app_roles" {
  realm_id = keycloak_realm.realm.id
  user_id  = keycloak_user.user_bob.id

  role_ids = [
    keycloak_role.app_admin_role.id,
    keycloak_role.app_reader_role.id
  ]
}
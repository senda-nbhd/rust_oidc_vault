resource "vault_jwt_auth_backend" "keycloak" {
  path               = "jwt"
  type               = "jwt"
  default_role       = "default"
  jwks_url           = "http://keycloak:8080/realms/app-realm/protocol/openid-connect/certs"
  bound_issuer       = "http://keycloak:8080/realms/app-realm"
  depends_on = [
    keycloak_realm.realm
  ]

  tune {
    default_lease_ttl = "1h"
    max_lease_ttl     = "24h"
    token_type        = "default-service"
  }
}

resource "vault_kv_secret_v2" "app_idp_config" {
  mount               = "secret"
  name                = "idp/app-config"
  delete_all_versions = true
  data_json = jsonencode({
    app_url       = local.app_url,
    provider_type = "keycloak"
    base_url      = local.keycloak_url,
    realm         = keycloak_realm.realm.id,
    issuer        = format("%s/realms/%s", local.keycloak_url, keycloak_realm.realm.id)
    client_id     = keycloak_openid_client.app_client.client_id
    client_secret = keycloak_openid_client.app_client.client_secret
    admin_username = local.keycloak_user,
    admin_password = local.keycloak_password,
  })
}

# Create policy for app to read OIDC config
resource "vault_policy" "app_oidc_policy" {
  name = "app-oidc-policy"

  policy = <<EOT
# Allow reading the OIDC configuration
path "secret/data/oidc/app-config" {
  capabilities = ["read"]
}
EOT
}
terraform {
  required_version = ">= 0.13"

  required_providers {
    vault = {
      source = "hashicorp/vault"
      version = "4.6.0"
    }
    keycloak = {
      source  = "mrparkers/keycloak"
      version = "4.4.0"
    }
  }
}

locals {
  // values from docker-compose.yml
  vault_root_token = "myroot"
  keycloak_user = "root"
  keycloak_password = "root"
  app_url = "http://localhost:4040"
  keycloak_url = "http://keycloak:8080"
  vault_url = "http://vault:8200"
}

provider "vault" {
  // see docker-compose.yml
  address = local.vault_url
  token   = local.vault_root_token
}

provider "keycloak" {
  client_id = "admin-cli"
  username  = local.keycloak_user
  password  = local.keycloak_password
  base_path = ""
  // see docker-compose.yml
  url       = local.keycloak_url
}
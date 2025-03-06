variable "realm_id" {
  description = "The ID of the Keycloak realm"
  type        = string
}

variable "team_name" {
  description = "The name of the team"
  type        = string
}

variable "team_description" {
  description = "Description of the team"
  type        = string
  default     = ""
}

variable "teams_parent_id" {
  description = "The ID of the parent team group"
  type        = string
}

variable "institution_group_id" {
  description = "The ID of the institution group"
  type        = string
  default     = null
}

variable "realm_roles" {
  description = "Map of role names to role IDs"
  type        = map(string)
}

variable "users" {
  description = "List of team user definitions with their roles"
  type = list(object({
    username    = string
    email       = string
    first_name  = string
    last_name   = string
    password    = string
    role        = string  # Possible values: CAPTAIN, STUDENT, SPECTATOR
  }))
  default = []
}

# Vault-specific variables
variable "create_vault_roles" {
  description = "Whether to create Vault roles for the team"
  type        = bool
  default     = true
}

variable "create_team_kv_store" {
  description = "Whether to create a KV store for the team"
  type        = bool
  default     = true
}

variable "vault_auth_backend_path" {
  description = "Path to the Vault JWT/OIDC auth backend"
  type        = string
  default     = "oidc"
}

variable "vault_auth_backend_allowed_redirect_uris" {
  description = "List of allowed redirect URIs for the Vault JWT/OIDC auth backend"
  type        = list(string)
  default     = []
}

variable "client_id" {
  description = "OAuth client ID used for Vault authentication"
  type        = string
  default     = "rust-app"
}
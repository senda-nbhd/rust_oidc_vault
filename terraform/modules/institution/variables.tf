variable "realm_id" {
  description = "The ID of the Keycloak realm"
  type        = string
}

variable "institution_name" {
  description = "The name of the institution"
  type        = string
}

variable "institution_description" {
  description = "Description of the institution"
  type        = string
  default     = ""
}

variable "institutions_parent_id" {
  description = "The ID of the parent institutions group"
  type        = string
}

variable "institution_group_id" {
  description = "The ID of an existing institution group (if not creating a new one)"
  type        = string
  default     = null
}

variable "create_institution_group" {
  description = "Whether to create a new institution group or use an existing one"
  type        = bool
  default     = true
}

variable "realm_roles" {
  description = "Map of role names to role IDs"
  type        = map(string)
}

variable "users" {
  description = "List of institution user definitions with their roles"
  type = list(object({
    username    = string
    email       = string
    first_name  = string
    last_name   = string
    password    = string
    role        = string  # Possible values: ADVISOR, SPECTATOR
  }))
  default = []
}

# Vault-specific variables
variable "create_vault_roles" {
  description = "Whether to create Vault roles for the institution"
  type        = bool
  default     = true
}

variable "create_institution_kv_store" {
  description = "Whether to create a KV store for the institution"
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
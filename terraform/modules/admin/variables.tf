variable "realm_id" {
  description = "The ID of the Keycloak realm"
  type        = string
}

variable "realm_roles" {
  description = "Map of role names to role IDs"
  type        = map(string)
}

variable "institution_groups" {
  description = "Map of institution names to group IDs"
  type        = map(string)
  default     = {}
}

variable "users" {
  description = "List of admin user definitions with their roles"
  type = list(object({
    username    = string
    email       = string
    first_name  = string
    last_name   = string
    password    = string
    role        = string  # Possible values: ROOT, ADVISOR, SPECTATOR
    institution = string  # Optional institution name for advisors
  }))
  default = []
}
variable "realm_id" {
  description = "The ID of the Keycloak realm"
  type        = string
}

variable "roles" {
  description = "Map of role names to role IDs"
  type        = map(string)
}

variable "groups" {
  description = "Map of group names to group IDs"
  type        = map(string)
}

variable "users" {
  description = "List of user definitions with their roles and teams"
  type = list(object({
    username    = string
    email       = string
    first_name  = string
    last_name   = string
    password    = string
    roles       = list(string)
    team        = string  # Team name
    institution = string  # Institution name
  }))
  default = []
}
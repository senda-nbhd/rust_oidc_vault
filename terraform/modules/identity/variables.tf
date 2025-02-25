variable "realm_id" {
  description = "The ID of the Keycloak realm"
  type        = string
}

variable "app_client_id" {
  description = "The ID of the Keycloak OIDC client for the application"
  type        = string
}

variable "regions" {
  description = "List of team definitions with their regions"
  type = list(object({
    name      = string
    description = string
    code = string
  }))
  default = []
}

variable "teams" {
  description = "List of team definitions"
  type = list(object({
    id          = string
    name        = string
    description = string
    region      = string
  }))
  default = []
}

variable "roles" {
  description = "List of role definitions"
  type = list(object({
    name        = string
    description = string
  }))
  default = [
    {
      name        = "ADMIN"
      description = "Administrator role with full access"
    },
    {
      name        = "USER"
      description = "Standard user role with limited access"
    },
    {
      name        = "SPECTATOR"
      description = "Read-only role for viewing data"
    },
    {
      name        = "ACADEMIC_ADVISOR"
      description = "Role for academic advisors with specialized permissions"
    }
  ]
}
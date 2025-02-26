variable "realm_id" {
  description = "The ID of the Keycloak realm"
  type        = string
}

variable "app_client_id" {
  description = "The ID of the Keycloak OIDC client for the application"
  type        = string
}

variable "institutions" {
  description = "List of team definitions"
  type = list(object({
    name        = string
    description = string
  }))
  default = []
}

variable "teams" {
  description = "List of team definitions"
  type = list(object({
    name        = string
    description = string
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
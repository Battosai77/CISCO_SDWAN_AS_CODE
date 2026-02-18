# terraform/variables.tf  (ajout GitLab OIDC)
variable "gitlab_token" {
  type      = string
  sensitive = true
  nullable  = false
  description = "GitLab CI token for auth"
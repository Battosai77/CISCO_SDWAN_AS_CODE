# terraform/providers.tf
terraform {
  required_providers {
    sdwan = {
      source  = "CiscoDevNet/sdwan"     # Provider officiel Cisco → API vManage
      version = "~> 0.9.0"              # Compatible 20.x (vérifier registry.terraform.io)
    }
  }
}

provider "sdwan" {
  # Les 4 vars ci-dessous sont injectées via terraform.tfvars
  url      = var.sdwan_url              # URL vManage depuis YAML
  username = var.sdwan_username         # User API
  password = var.sdwan_password         # Pass (sensitive=true)
  insecure = var.sdwan_insecure         # Ignore SSL (lab only) 
} 
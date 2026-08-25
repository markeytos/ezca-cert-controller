terraform {
  required_version = ">= 1.0"

  required_providers {
    keytos = {
      source = "markeytos/keytos"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "keytos" {
  ezca_url = var.ezca_url
}

variable "ezca_url" {
  description = "EZCA instance URL. Defaults to the provider's own default when left unset."
  type        = string
  default     = null
}

variable "authority_id" {
  description = "ID of the EZCA SSL certificate authority to issue from."
  type        = string
}

variable "template_id" {
  description = "ID of the EZCA template within the certificate authority."
  type        = string
}

variable "common_name" {
  description = "Subject common name of the identity certificate. Must be a domain registered in EZCA."
  type        = string
}

variable "organization" {
  description = "Subject organization of the identity certificate."
  type        = string
}

variable "dns_names" {
  description = "Subject alternative DNS names to add to the certificate."
  type        = list(string)
  default     = []
}

variable "validity_period" {
  description = "How long the issued certificate stays valid, as a Go duration."
  type        = string
  default     = "8760h" # 365d
}

variable "early_renewal_period" {
  description = "Treat the certificate as ready for renewal this long before it expires."
  type        = string
  default     = "720h" # 30d
}

variable "rsa_bits" {
  description = "RSA key size for the generated private key."
  type        = number
  default     = 4096
}

data "keytos_ezca_ssl_authority" "identity" {
  authority_id = var.authority_id
  template_id  = var.template_id
}

resource "tls_private_key" "identity" {
  algorithm = "RSA"
  rsa_bits  = var.rsa_bits
}

resource "tls_cert_request" "identity" {
  private_key_pem = tls_private_key.identity.private_key_pem

  subject {
    common_name  = var.common_name
    organization = var.organization
  }
}

resource "keytos_ezca_ssl_leaf_cert" "identity" {
  authority_id     = data.keytos_ezca_ssl_authority.identity.authority_id
  template_id      = data.keytos_ezca_ssl_authority.identity.template_id
  cert_request_pem = tls_cert_request.identity.cert_request_pem

  validity_period      = var.validity_period
  early_renewal_period = var.early_renewal_period

  additional_subject_alternative_names = {
    dns_names = var.dns_names
  }
}

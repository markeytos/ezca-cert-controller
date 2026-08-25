# cert_pem and private_key_pem are read by tf-kube-script.sh via
# `terraform output -raw` to build the bootstrap Secret. Renaming either one
# means updating the script to match.

output "cert_pem" {
  description = "Issued certificate data in PEM format."
  value       = keytos_ezca_ssl_leaf_cert.identity.cert_pem
}

output "private_key_pem" {
  description = "Private key for the issued certificate, in PEM format. Never leaves Terraform state."
  value       = tls_private_key.identity.private_key_pem
  sensitive   = true
}

output "cert_serial_number" {
  description = "Certificate serial number. The unique identifier for this resource."
  value       = keytos_ezca_ssl_leaf_cert.identity.cert_serial_number
}

output "cert_thumbprint_hex" {
  description = "Certificate thumbprint. SHA-1 sum of the raw certificate contents."
  value       = keytos_ezca_ssl_leaf_cert.identity.cert_thumbprint_hex
}

output "ready_for_renewal" {
  description = "True when the certificate is expired or inside the early renewal period."
  value       = keytos_ezca_ssl_leaf_cert.identity.ready_for_renewal
}

output "validity" {
  description = "Window in which the certificate is valid, as RFC3339 timestamps."
  value = {
    not_before = keytos_ezca_ssl_leaf_cert.identity.validity_not_before
    not_after  = keytos_ezca_ssl_leaf_cert.identity.validity_not_after
  }
}

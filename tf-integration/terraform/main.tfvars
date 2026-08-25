# Passed explicitly by tf-kube-script.sh as -var-file=main.tfvars.
# (Terraform only auto-loads terraform.tfvars and *.auto.tfvars, so this name
# does nothing on its own if you run terraform by hand.)

ezca_url = "https://portal.ezca.io"

# From the EZCA portal: the CA and template to issue the identity cert from.
authority_id = "00000000-0000-0000-0000-000000000000"
template_id  = "00000000-0000-0000-0000-000000000000"

# common_name must be a domain you have registered in EZCA.
common_name  = "cluster-identity.example.com"
organization = "Example Inc"
dns_names    = ["cluster-identity.example.com"]

validity_period      = "8760h" # 365d
early_renewal_period = "720h"  # 30d
rsa_bits             = 4096

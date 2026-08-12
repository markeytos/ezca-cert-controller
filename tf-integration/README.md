# Integration with [Keytos Terraform Provider](https://registry.terraform.io/providers/markeytos/keytos/latest/docs)

This folder showcases an end-to-end integration with the EZCA Kubernetes Operator and the Keytos Terraform Provider. The bash script does the following:

1. Initializes and applies the terraform configuration found in `terraform/`. This will provision an SSL certificate. The certificate PEM and private key PEM will be written to temporary files to be used by the EZCA Kubernetes Operator.
1. Creates a Kubernetes secret with the certificate and private key from the previous step.
1. Installs the EZCA Kubernetes Operator via its Helm Chart, passing in the `values.yaml` file found in `chart/`


#!/usr/bin/env bash
#
# End-to-end EZCA bootstrap: issue the identity certificate with Terraform, then
# install the ezca-cert-controller chart that renews everything from there on.
#
# Usage:
#   tf-kube-script.sh
#
# Runs from anywhere; paths below are resolved relative to this script, so the
# expected layout is:
#
#   tf-kube-script.sh
#   terraform/   main.tf, main.tfvars, outputs.tf
#   chart/       values.yaml
#
# What it does, in order:
#   1. terraform init -upgrade + apply in terraform/, writing the issued
#      certificate and its private key to terraform/cert.pem and
#      terraform/cert.key
#   2. creates the namespaces and the kubernetes.io/tls Secret holding that
#      certificate -- the "pre-existing" Secret referenced by
#      clusterIdentity.certSecretName in chart/values.yaml, which the chart
#      never creates itself
#   3. pulls the chart from the public Keytos OCI registry and installs it
#
# Terraform is pointed at a temporary CLI config, so any dev_overrides or
# filesystem_mirror in ~/.terraformrc is bypassed and the provider comes from
# the registry rather than a local build. Your config governs which version is
# used; pin it in required_providers if you need a specific one. To switch back
# to a local build afterwards, run `terraform init -upgrade` again with your
# normal ~/.terraformrc.
#
# Step 1 writes no .tf files, but it does update terraform/.terraform/ and
# terraform/.terraform.lock.hcl.
#
# Authentication uses azidentity.NewDefaultAzureCredential, so run `az login`
# first. kubectl must already point at the target cluster.
set -euo pipefail

# --- settings ---------------------------------------------------------------

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

tf_dir="$script_dir/terraform"
tfvars='main.tfvars' # relative to tf_dir, since terraform -chdir resolves it there
cert_pem="$tf_dir/cert.pem"
cert_key="$tf_dir/cert.key"

values_file="$script_dir/chart/values.yaml"

# Must match clusterIdentity.certSecretName / certSecretNamespace in values.yaml.
secret_name='cluster-cert-identity'
namespace='ezca-cert-controller-system'
secret_namespace="$namespace"

release='ezca-cert-controller-system'
chart='oci://keytos-eqgzasb8bufxa0cd.azurecr.io/ezca/helm/ezca-cert-controller'
chart_version='' # empty means latest

# --- helpers ----------------------------------------------------------------

die() {
	printf 'error: %s\n' "$1" >&2
	exit 1
}

usage() {
	# Print the header comment block verbatim, stopping at the first line of code
	# so the help text can never drift out of sync with a line range.
	awk 'NR < 3 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
}

case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
esac

# One cleanup handler for both temp paths: a second `trap ... EXIT` would replace
# the first rather than add to it.
cli_config=''
pull_dir=''
cleanup() {
	[ -n "$cli_config" ] && rm -f "$cli_config"
	[ -n "$pull_dir" ] && rm -rf "$pull_dir"
	return 0
}
trap cleanup EXIT

# --- preflight --------------------------------------------------------------
# Check everything up front: a missing helm should not surface only after a
# certificate has already been issued.

for cmd in terraform kubectl helm; do
	command -v "$cmd" >/dev/null || die "$cmd not found on PATH"
done

[ -d "$tf_dir" ] || die "terraform directory not found at $tf_dir"
compgen -G "$tf_dir/*.tf" >/dev/null || die "no .tf files in $tf_dir"
[ -f "$tf_dir/$tfvars" ] || die "$tfvars not found in $tf_dir"
[ -f "$values_file" ] || die "values file not found at $values_file"

# --- 1. issue the certificate with terraform --------------------------------

# An explicit provider_installation block means ONLY the listed methods are
# used, so this shadows whatever is in ~/.terraformrc. Without it a local
# dev_overrides or filesystem_mirror entry would silently serve your own build
# and defeat the point of pulling from the registry.
cli_config="$(mktemp -t keytos-public-tfrc)"
cat >"$cli_config" <<'EOF'
provider_installation {
  direct {}
}
EOF

export TF_CLI_CONFIG_FILE="$cli_config"
export TF_IN_AUTOMATION=1

printf 'config   : %s\n' "$tf_dir"
printf 'tfvars   : %s\n' "$tfvars"
printf 'provider : from registry (local builds bypassed)\n\n'

# -upgrade so a rerun picks up a newly published version rather than staying on
# whatever the lock file recorded first.
terraform -chdir="$tf_dir" init -input=false -upgrade

printf '\n'
terraform version
printf '\n'

terraform -chdir="$tf_dir" apply -input=false -auto-approve -var-file="$tfvars"

# umask so the key is not briefly world-readable between create and chmod.
(
	umask 077
	terraform -chdir="$tf_dir" output -raw cert_pem >"$cert_pem"
	terraform -chdir="$tf_dir" output -raw private_key_pem >"$cert_key"
)

printf '\nwrote %s and %s\n\n' "$cert_pem" "$cert_key"

# --- 2. namespaces + bootstrap Secret ---------------------------------------

for ns in "$namespace" "$secret_namespace"; do
	kubectl create namespace "$ns" --dry-run=client -o yaml |
		kubectl apply -f - >/dev/null
done

# create --dry-run=client | apply makes this idempotent: it creates the Secret
# the first time and rewrites tls.crt/tls.key on later runs.
kubectl create secret tls "$secret_name" \
	--cert "$cert_pem" --key "$cert_key" \
	--namespace "$secret_namespace" \
	--dry-run=client -o yaml |
	kubectl apply -f -

# --- 3. fetch the chart -----------------------------------------------------
# The chart lives in an OCI registry, so there is no `helm repo add/update`:
# pulling is how you refresh it. Installing from the pulled .tgz means the
# version that was fetched is exactly the one that gets installed.

pull_dir="$(mktemp -d)"

pull=(pull "$chart" --destination "$pull_dir")
[ -n "$chart_version" ] && pull+=(--version "$chart_version")
helm "${pull[@]}"

chart_tgz="$(find "$pull_dir" -maxdepth 1 -name '*.tgz' | head -1)"
[ -n "$chart_tgz" ] || die "helm pull produced no chart archive in $pull_dir"

# --- 4. install / upgrade ---------------------------------------------------

helm upgrade --install "$release" "$chart_tgz" \
	--namespace "$namespace" --create-namespace \
	-f "$values_file" \
	--wait --timeout 5m

echo >&2
kubectl get clustercertidentity 2>/dev/null >&2 || true
kubectl get managedcredential -A 2>/dev/null >&2 || true

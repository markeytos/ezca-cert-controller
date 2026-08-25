#!/usr/bin/env bash
set -euo pipefail

# Creates the identity Secret from a certificate + key PEM, pulls the
# ezca-cert-controller chart from the public Keytos registry, and installs it.
#
# Edit the settings below to match your setup, then run the script with no
# arguments. The Secret is the "pre-existing" one referenced by
# clusterIdentity.certSecretName (or appCerts[].certSecretName) in your values
# file; the chart never creates it.

# --- settings ---------------------------------------------------------------

CERT_PEM="cert.pem"                  # certificate PEM (leaf first, chain optional)
KEY_PEM="key.pem"                    # private key PEM for that certificate
VALUES_FILE="values.yaml"            # Helm values file

SECRET_NAME="cluster-cert-identity"  # kubernetes.io/tls Secret to create/update
NAMESPACE="ezca-cert-controller-system"
SECRET_NAMESPACE="$NAMESPACE"        # change if the Secret lives elsewhere

RELEASE="ezca-cert-controller-system"
CHART="oci://keytos-eqgzasb8bufxa0cd.azurecr.io/ezca/helm/ezca-cert-controller"
CHART_VERSION="" # empty means latest

# --- 1. namespaces + Secret -------------------------------------------------

for ns in "$NAMESPACE" "$SECRET_NAMESPACE"; do
	kubectl create namespace "$ns" --dry-run=client -o yaml |
		kubectl apply -f - >/dev/null
done

# create --dry-run=client | apply makes this idempotent: it creates the Secret
# the first time and rewrites tls.crt/tls.key on later runs.
kubectl create secret tls "$SECRET_NAME" \
	--cert "$CERT_PEM" --key "$KEY_PEM" \
	--namespace "$SECRET_NAMESPACE" \
	--dry-run=client -o yaml |
	kubectl apply -f -

# --- 2. fetch the chart -----------------------------------------------------
# The chart lives in an OCI registry, so there is no `helm repo add/update`:
# pulling is how you refresh it. Installing from the pulled .tgz means the
# version that was fetched is exactly the one that gets installed.

pull_dir="$(mktemp -d)"
trap 'rm -rf "$pull_dir"' EXIT

pull=(pull "$CHART" --destination "$pull_dir")
[ -n "$CHART_VERSION" ] && pull+=(--version "$CHART_VERSION")
helm "${pull[@]}"

chart_tgz="$(find "$pull_dir" -maxdepth 1 -name '*.tgz' | head -1)"
[ -n "$chart_tgz" ] || {
	echo "error: helm pull produced no chart archive in $pull_dir" >&2
	exit 1
}

# --- 3. install / upgrade ---------------------------------------------------

helm upgrade --install "$RELEASE" "$chart_tgz" \
	--namespace "$NAMESPACE" --create-namespace \
	-f "$VALUES_FILE" \
	--wait --timeout 5m

echo >&2
kubectl get clustercertidentity 2>/dev/null >&2 || true
kubectl get managedcredential -A 2>/dev/null >&2 || true

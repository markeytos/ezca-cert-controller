#!/usr/bin/env bash
set -euo pipefail

# Extracts the public certificate from a kubernetes.io/tls Secret (its tls.crt)
# and writes it as a .cer file. The private key (tls.key) is never read.
# By default it writes the leaf certificate in DER form (the usual .cer format,
# e.g. for uploading to an Entra app registration).

usage() {
	cat >&2 <<EOF
usage: $0 <secret-name> [-n namespace] [-o output.cer] [--pem] [--chain]

  <secret-name>      name of the kubernetes.io/tls Secret
  -n, --namespace    namespace of the Secret (default: current kubectl context)
  -o, --output       output file (default: <secret-name>.cer)
  --pem              write PEM instead of DER (leaf only)
  --chain            write the full public chain as PEM (implies --pem)
EOF
	exit 1
}

secret=""
namespace=""
output=""
format="der" # der | pem
chain="false"

while [ "$#" -gt 0 ]; do
	case "$1" in
	-n | --namespace)
		namespace="${2:?missing namespace}"
		shift 2
		;;
	-o | --output)
		output="${2:?missing output path}"
		shift 2
		;;
	--pem)
		format="pem"
		shift
		;;
	--chain)
		chain="true"
		format="pem"
		shift
		;;
	-h | --help) usage ;;
	-*)
		echo "unknown option: $1" >&2
		usage
		;;
	*)
		if [ -z "$secret" ]; then
			secret="$1"
		else
			echo "unexpected argument: $1" >&2
			usage
		fi
		shift
		;;
	esac
done

[ -n "$secret" ] || usage
output="${output:-${secret}.cer}"

ns_args=()
[ -n "$namespace" ] && ns_args=(-n "$namespace")

# Decode tls.crt server-side via go-template, so this works regardless of the
# local base64 flavor. tls.crt may hold a chain (leaf first, then issuers).
pem="$(kubectl get secret "$secret" "${ns_args[@]}" -o go-template='{{index .data "tls.crt" | base64decode}}')"
if [ -z "$pem" ]; then
	echo "error: secret $secret has no tls.crt" >&2
	exit 1
fi

if [ "$chain" = "true" ]; then
	# Full public chain, PEM.
	printf '%s\n' "$pem" >"$output"
	inform="PEM"
elif [ "$format" = "pem" ]; then
	# Leaf certificate only, PEM.
	printf '%s\n' "$pem" | openssl x509 -outform PEM >"$output"
	inform="PEM"
else
	# Leaf certificate only, DER (typical .cer).
	printf '%s\n' "$pem" | openssl x509 -outform DER >"$output"
	inform="DER"
fi

echo "wrote $output" >&2
openssl x509 -in "$output" -inform "$inform" -noout -subject -issuer -serial -fingerprint -dates >&2

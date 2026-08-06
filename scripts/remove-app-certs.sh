#!/usr/bin/env bash
set -euo pipefail

# Removes all certificate credentials from an Entra ID app registration.
# Authenticates as the current Azure CLI login (az login / default credential),
# which must be allowed to update the app (Application.ReadWrite.All or owner).
#
# usage: remove-app-certs.sh <app-id>
#   <app-id>   the app registration's Application (client) ID or object ID

app_id="${1:?usage: $0 <app-id>}"

key_ids="$(az ad app credential list --id "$app_id" --cert --query '[].keyId' -o tsv)"

if [ -z "$key_ids" ]; then
	echo "no certificates on app $app_id" >&2
	exit 0
fi

for kid in $key_ids; do
	echo "removing certificate $kid" >&2
	az ad app credential delete --id "$app_id" --key-id "$kid" --cert
done

echo "done" >&2

#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: $0 <bundle.pem>" >&2
	exit 1
fi

bundle="$1"

awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' "$bundle" >tls.crt
awk '/-----BEGIN .*PRIVATE KEY-----/,/-----END .*PRIVATE KEY-----/' "$bundle" >tls.key

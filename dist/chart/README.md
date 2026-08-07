# cert-controller Helm chart

Deploys the **ezca-cert-controller** operator (Deployment, RBAC, and the three
`ezca.keytos.io/v1` CRDs) and renders the certificate resources it manages from
values:

- `clusterIdentity` → one cluster-scoped **ClusterCertIdentity**
- `appCerts[]` → one namespaced **ManagedCredential** each

## Install

```bash
helm install my-release oci://keytos-eqgzasb8bufxa0cd.azurecr.io/ezca/helm/ezca-cert-controller \
  --version <version> \
  --namespace ezca-cert-controller-system --create-namespace \
  -f my-values.yaml
```

## Verifying the chart signature

Released charts are PGP-signed (a `.prov` provenance file is published alongside the
chart). To verify integrity and origin at install time, import the Keytos public
signing key into a legacy keyring and pass `--verify`:

```bash
# one-time: import the public key (published at <KEYS location>) into a legacy keyring
gpg --dearmor < keytos-helm-pubkey.asc > ~/.gnupg/ezca-pubring.gpg

helm install my-release oci://keytos-eqgzasb8bufxa0cd.azurecr.io/ezca/helm/ezca-cert-controller \
  --version <version> --verify --keyring ~/.gnupg/ezca-pubring.gpg \
  --namespace ezca-cert-controller-system --create-namespace
```

`helm pull --verify` works the same way. Verification fails if the chart was tampered
with or was not signed by the Keytos key.

## Prerequisite: bootstrap Secret (you create it, not the chart)

Each identity references a `kubernetes.io/tls` Secret (`certSecretName`) that holds
the **bootstrap certificate** (`tls.crt` = leaf + chain) and its **RSA key**
(`tls.key`). The controller reads and rewrites this Secret as it renews. The chart
**only references it by name** — it never creates it and never holds private-key
material (that would place key material in Helm release storage and CI logs).

Create it out-of-band before installing, in the namespace the CR uses:

```bash
kubectl -n ezca-cert-controller-system create secret tls cluster-cert-identity \
  --cert=tls.crt --key=tls.key
```

## Field model

- **Root-only fields** — set once at the top level, applied to every generated CR
  (not overridable per item): `cloud`, `ezcaURL`, `tenantID`, `appInsightsConnString`.
- **Per-item Entra app** — `appID` / `appObjectID` live on each `clusterIdentity` /
  `appCerts[]` entry and pair with the root `tenantID`. The CRD requires
  tenantID + appID + appObjectID all-or-nothing; the chart fails rendering if only
  some are set. `keyVault` requires these app fields.

## CRD lifecycle

`crd.enabled=true` installs the CRDs as templates; `crd.keep=true` (default) leaves
them (and any CRs) in place on `helm uninstall`. Manage CRDs via **either** this
chart **or** kustomize (`config/`), not both — set `crd.enabled=false` when they are
installed separately.

See `values.yaml` for the full list of operator and certificate settings.

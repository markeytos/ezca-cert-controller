# ezca-cert-controller

A Helm chart for the **ezca-cert-controller** — a Kubernetes operator that keeps
[EZCA](https://www.keytos.io/azure-pki)-issued certificates alive inside your cluster.

## Prerequisites

- Kubernetes cluster and Helm 3.
- An EZCA subscription.
- For each identity, a **bootstrap Secret you create yourself** (see below).
- (optional) For Entra rotation / Key Vault sync: an Entra app registration and its
  `tenantID` / `appID` / `appObjectID`, with Graph and Key Vault permissions.

## Installation

### Create the Bootstrap Secret

To create the bootstrap certificate for your `certIdentity`, create a domain in EZCA and a certificate for that domain. 
Download the certificate in PEM format and save the private key in unencrypted PEM format.

Create the release namespace (the install step below reuses it), then import the
certificate into it as a tls secret:

```bash
kubectl create namespace ezca-cert-controller-system
kubectl -n ezca-cert-controller-system create secret tls cluster-cert-identity \
  --cert=tls.crt --key=tls.key
```

> The `helm install` command below uses `--create-namespace`, which is a no-op
> when the namespace already exists — so creating it here first is safe.

### Create your values.yaml file
To configure the Helm chart, you will need to create a `values.yaml` file. Here is an example:

```yaml
global:
  ezcaURL: https://portal.ezca.io
  tenantID: "00000000-0000-0000-0000-000000000000"

clusterIdentity:
  name: master-cert-identity-1
  appID: "11111111-1111-1111-1111-111111111111"
  appObjectID: "22222222-2222-2222-2222-222222222222"
  certSecretName: cluster-cert-identity
  renewalThreshold: 20
  allowedNamespaces:
    - team-web
  keyVault:
    vaultName: my-keyvault
    certName: master-identity

appCerts:
  - name: web-frontend-cert
    namespace: team-web
    subjectName: web.example.com
    dnsNames: [web.example.com, www.example.com]
    extendedKeyUsages: [ServerAuth]
    validityInDays: 90
    caID: "33333333-3333-3333-3333-333333333333"
    templateID: "44444444-4444-4444-4444-444444444444"
    certSecretName: web-frontend-cert
    identityRef:
      name: master-cert-identity-1
      kind: ClusterCertIdentity
  - name: web-backend-cert
    namespace: team-web
    subjectName: backend.example.com
    dnsNames: [backend.example.com]
    extendedKeyUsages: [ClientAuth]
    caID: "33333333-3333-3333-3333-333333333333"
    templateID: "44444444-4444-4444-4444-444444444444"
    identityRef:
      name: master-cert-identity-1
      kind: ClusterCertIdentity
```

This example uses a single `clusterIdentity` to bootstrap the `appCerts` below it,
but every part is optional — you configure only the behavior you need:

- **Certificates only.** Give an entry a `subjectName`, `caID`, and `templateID`
  and the controller issues and renews that certificate into a Secret. Nothing
  else is required.
- **Entra credential rotation.** Add `appID` / `appObjectID` (with
  `global.tenantID`) and the controller also installs each renewed certificate onto that
  Entra app registration, removing the old credential once it expires.
- **Key Vault sync.** Add `keyVault` and the controller keeps the named Key Vault
  certificate in step with the Secret, re-importing whenever they diverge. This
  builds on the Entra fields, since the controller authenticates to the vault as
  that app.
- **No cluster identity.** The `ClusterCertIdentity` is opt-in: it is rendered
  only when you set `clusterIdentity.name`. Omit the `clusterIdentity` block (or
  leave `name` blank) and no `ClusterCertIdentity` is created — for when your
  `appCerts` bootstrap from an identity created elsewhere, or you only need
  namespaced `ManagedCredential`s.

### Install the Helm Chart

Next, run this command to install the Helm chart in your cluster, passing in the values file
via `-f values.yaml`.

```bash
helm install ezca-cert-controller-system \
  oci://keytos-eqgzasb8bufxa0cd.azurecr.io/ezca/helm/ezca-cert-controller \
  --namespace ezca-cert-controller-system --create-namespace \
  -f values.yaml
```

> The chart ships its CRDs in the chart's `crds/` directory, so Helm installs
> them before anything else — a single install on a fresh cluster works even
> when your values render `ClusterCertIdentity` / `ManagedCredential` resources.
> If you manage CRDs out of band, pass `--skip-crds`.

## What it does

You store a certificate in a Kubernetes `kubernetes.io/tls` Secret. The controller
watches it and, before it expires, renews it against your EZCA instance and rewrites
the Secret in place. Your workloads mount the Secret as usual and never see an
outage.

On top of renewal it can, per certificate:

- **Issue certificates from EZCA** — bootstrap a brand-new certificate into an empty
  Secret from an EZCA CA + template. It does this by authenticating as the `clusterIdentity` 
  set in your Helm chart (see above).
- **Rotate Entra ID (Azure AD) app credentials** — when a certificate is a credential
  on an Entra app registration, the controller adds the renewed certificate to the app
  and removes the old one once it expires.
- **Sync to Azure Key Vault** — keep a named Key Vault certificate in step with the
  Secret, re-importing whenever they diverge.

### The two resource kinds

| Kind | Scope | Purpose |
| --- | --- | --- |
| **ClusterCertIdentity** | Cluster | A long-lived "identity" certificate (often an Entra app credential) that other credentials trust to bootstrap themselves. |
| **ManagedCredential** | Namespaced | An application/leaf certificate. On first issuance it authenticates to EZCA using an identity (`identityRef`); thereafter the controller renews and rotates it. |


### Upgrade

Helm deliberately never touches the contents of a chart's `crds/` directory
after the first install, so `helm upgrade` alone will not pick up CRD schema
changes. When upgrading to a new chart version, apply the packaged CRDs first,
then upgrade the release:

```bash
helm pull oci://keytos-eqgzasb8bufxa0cd.azurecr.io/ezca/helm/ezca-cert-controller \
  --version <version> --untar --destination /tmp/ezca-cert-controller
kubectl apply --server-side --force-conflicts -f /tmp/ezca-cert-controller/ezca-cert-controller/crds/
helm upgrade ezca-cert-controller-system \
  oci://keytos-eqgzasb8bufxa0cd.azurecr.io/ezca/helm/ezca-cert-controller \
  --version <version> --namespace ezca-cert-controller-system -f values.yaml
```

Both steps are idempotent, so it is safe to run them unconditionally in CI.

### Uninstall

```bash
helm uninstall ezca-cert-controller-system --namespace ezca-cert-controller-system
```

This will not delete the CRDs (or therefore your `ClusterCertIdentity` /
`CertIdentity` / `ManagedCredential` resources) from your cluster. To fully tear down, delete the
CRDs manually afterwards:

```bash
kubectl delete crd certidentities.ezca.keytos.io clustercertidentities.ezca.keytos.io managedcredentials.ezca.keytos.io
```

## Values reference

> See [`dist/chart/values.yaml`](dist/chart/values.yaml) for the authoritative,
> commented list of every setting.

The chart ships a JSON Schema ([`values.schema.json`](dist/chart/values.schema.json))
that Helm checks your values against on `install`, `upgrade`, `template` and `lint`.
Misspelled keys, bad enum values, out-of-range thresholds and malformed UUIDs are
reported before anything reaches the cluster:

```
Error: values don't meet the specifications of the schema(s) in the following chart(s):
ezca-cert-controller:
- at '/appCerts/0': additional properties 'dnsName' not allowed
```

That file is **generated**: each section of `values.yaml` points at a readable
schema in [`dist/chart/schemas/`](dist/chart/schemas) — `global.schema.yaml`,
`cluster-identity.schema.yaml`, `app-cert.schema.yaml`, `controller.schema.yaml` —
which `make helm-schema` bundles into `values.schema.json`. Edit the schema files,
never the generated one; CI fails if the two are out of step.

Your values file only ever needs the certificate settings documented below. The
operator's own runtime — image, replicas, RBAC scope, metrics, scheduling — lives
under a single `controller:` key whose defaults install a working controller; see
the second half of [`values.yaml`](dist/chart/values.yaml) if you need to reach in.

The chart renders **one** `ClusterCertIdentity` (from `clusterIdentity`) and **one**
`ManagedCredential` per entry in `appCerts`.

### `global` — settings shared by every certificate

**Global fields** are set once and applied to *every* generated CR; they cannot be
overridden per item.

| Key | Default | Description |
| --- | --- | --- |
| `global.cloud` | `Public` | Azure sovereign cloud for Entra ID / Graph. One of `Public`, `USGov`. |
| `global.ezcaURL` | `https://portal.ezca.io` | Base URL of your EZCA instance. **Required.** |
| `global.tenantID` | `""` | Entra tenant that owns the app registrations. Only emitted on a CR that also sets `appID` + `appObjectID`. |
| `global.appInsightsConnString` | `""` | Optional App Insights connection string; when set, renewals/rotations/errors are reported. |

> **Entra fields are all-or-nothing.** The CRD requires `global.tenantID`, `appID`, and
> `appObjectID` to be set together (or all absent). `keyVault` requires them too,
> since the controller authenticates to the vault as that app. The chart fails
> rendering if only some are set.

### `clusterIdentity` — the ClusterCertIdentity

The `ClusterCertIdentity` is **opt-in**: it is rendered only when you set
`clusterIdentity.name`. Omit the block, or leave `name` blank/`null`, and no
`ClusterCertIdentity` is created (e.g. when your `appCerts` reference an identity
created elsewhere).

| Key | Default | Description |
| --- | --- | --- |
| `name` | `""` | `metadata.name` of the ClusterCertIdentity. Blank → not created. |
| `appID` / `appObjectID` | `""` | Entra app (client) ID and directory object ID. Set both to enable Entra rotation + Key Vault sync; leave blank for a certificate-only identity. |
| `certSecretName` | `cluster-cert-identity` | Name of the pre-existing `kubernetes.io/tls` Secret with the bootstrap cert. |
| `certSecretNamespace` | `""` | Namespace of that Secret. Blank → the release namespace. |
| `renewalThreshold` | `20` | Percent of lifetime remaining at/below which to renew (1–99). |
| `allowedNamespaces` | `[]` | Namespaces whose `ManagedCredential`s may reference this identity via `identityRef`. Required (≥1); blank → `[release namespace]`. |
| `keyVault.vaultName` / `keyVault.certName` | `""` | Optional Key Vault cert to keep in sync. Requires the Entra app fields. |

### `appCerts[]` — the ManagedCredentials

Zero or more entries; each with a `subjectName` renders one `ManagedCredential`.

| Key | Required | Description |
| --- | --- | --- |
| `name` | no | `metadata.name` (defaults to `app-cert-<n>`). |
| `namespace` | no | `metadata.namespace`; blank → release namespace. |
| `subjectName` | **yes** | Certificate subject: a full RFC 4514 DN (`CN=app,O=corp`) or a bare CN (`app.example.com`). |
| `caID` | **yes** | EZCA SSL CA UUID that issues the certificate. |
| `templateID` | **yes** | EZCA template UUID used when issuing. |
| `dnsNames` / `ipAddresses` / `uris` / `emailAddresses` | no | Subject alternative names. |
| `keyUsages` | no | Subset of `DigitalSignature`, `KeyEncipherment`, `DataEncipherment`, `KeyAgreement`, `NonRepudiation`. Empty → `DigitalSignature` + `KeyEncipherment`. |
| `extendedKeyUsages` | no | Subset of `Any`, `ServerAuth`, `ClientAuth`, `CodeSigning`, `EmailProtection`, `IPSECEndSystem`, `IPSECTunnel`, `IPSECUser`, `TimeStamping`, `OCSPSigning`, `MicrosoftServerGatedCrypto`, `NetscapeServerGatedCrypto`, `MicrosoftCommercialCodeSigning`, `MicrosoftKernelCodeSigning`. Empty → `ServerAuth` + `ClientAuth`. |
| `validityInDays` | no | Requested lifetime in days. Unset → issuer default (90 days). |
| `certSecretName` | no | Name of the issued-cert Secret. |
| `renewalThreshold` | no | Percent of lifetime remaining at/below which to renew (1–99, default 20). |
| `appID` / `appObjectID` | no | Optional per-item Entra app (paired with `global.tenantID`). |
| `keyVault.vaultName` / `keyVault.certName` | no | Optional Key Vault sync; requires the app fields. |
| `identityRef.name` / `identityRef.kind` | no | Identity that bootstraps first issuance. `kind` is `ClusterCertIdentity` or `CertIdentity`. Required only on first issuance into an empty Secret; omit if the Secret is provisioned externally. |


## Observing your certificates

To view the status of your certificates, use `kubectl get`:

```bash
kubectl get clustercertidentity        # short name: cci
kubectl get managedcredential -A       # short name: mc
```

`Ready` reflects the `Available` condition; `EXPIRATION` is the current certificate's
`notAfter`. Full `status` (conditions, `lastRenewalTime`, `pendingThumbprint`,
`managedKeyCredentials`) is visible via `kubectl describe`.

## Verifying the chart signature (optional)

Released charts are PGP-signed (a `.prov` provenance file is published alongside the
chart). Each [GitHub release](https://github.com/markeytos/ezca-cert-controller/releases)
attaches the packaged chart, its `.prov` signature, and the public signing key
(`keytos-helm-pubkey.asc`) so the release can be verified independently.

Import the public key into a keyring:

```bash
gpg --dearmor < keytos-helm-pubkey.asc > ~/.gnupg/ezca-pubring.gpg
```

**Verify a single release** by downloading its `.tgz` and `.tgz.prov` assets and
checking them locally:

```bash
helm verify --keyring ~/.gnupg/ezca-pubring.gpg ezca-cert-controller-<version>.tgz
helm install ezca-cert-controller-system ./ezca-cert-controller-<version>.tgz \
  --namespace ezca-cert-controller-system --create-namespace -f values.yaml
```

**Or verify at install time** straight from the registry with `--verify`:

```bash
helm install ezca-cert-controller-system \
  oci://keytos-eqgzasb8bufxa0cd.azurecr.io/ezca/helm/ezca-cert-controller \
  --version <version> --verify --keyring ~/.gnupg/ezca-pubring.gpg \
  --namespace ezca-cert-controller-system --create-namespace
```

Verification fails if the chart was tampered with or was not signed by the Keytos key.

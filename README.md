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

Import the certificate into your cluster as a tls secret:

```bash
kubectl -n ezca-cert-controller-system create secret tls cluster-cert-identity \
  --cert=tls.crt --key=tls.key
```

### Create your values.yaml file
To configure the Helm chart, you will need to create a `values.yaml` file. Here is an example:

```yaml
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
  ...
```

This example consists of a single `clusterIdentity` to bootstrap multiple other identities.

todo: explain in elegant language the functionality. How, if they include an app id, we install the renewed
certificates on the app, and if they specify keyvault, we keep a keyvault certificate in sync. But if they just 
want to do certificates, we just do certificates. And if they don't want a cluster wide cert identity, they don't
need to create one.

### Install the Helm Chart

Next, run this command to install the Helm chart in your cluster, passing in the values file
via `-f values.yaml`.

```bash
helm install ezca-cert-controller-system \
  oci://keytos-eqgzasb8bufxa0cd.azurecr.io/ezca/helm/ezca-cert-controller \
  --namespace ezca-cert-controller-system --create-namespace \
  -f values.yaml
```

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


### Uninstall

```bash
helm uninstall ezca-cert-controller-system --namespace ezca-cert-controller-system
```

This will not delete the CRDs from your cluster. You must delete them manually if you want a full teardown.

## Values reference

> See [`dist/chart/values.yaml`](dist/chart/values.yaml) for the authoritative,
> commented list of every setting.

The chart renders **one** `ClusterCertIdentity` (from `clusterIdentity`) and **one**
`ManagedCredential` per entry in `appCerts`.

**Root-only fields** are set once at the top level and applied to *every* generated CR.

| Key | Default | Description |
| --- | --- | --- |
| `cloud` | `Public` | Azure sovereign cloud for Entra ID / Graph. One of `Public`, `USGov`. |
| `ezcaURL` | `https://portal.ezca.io` | Base URL of your EZCA instance. **Required.** |
| `tenantID` | `""` | Entra tenant that owns the app registrations. Only emitted on a CR that also sets `appID` + `appObjectID`. |
| `appInsightsConnString` | `""` | Optional App Insights connection string; when set, renewals/rotations/errors are reported. |

> **Entra fields are all-or-nothing.** The CRD requires `tenantID`, `appID`, and
> `appObjectID` to be set together (or all absent). `keyVault` requires them too,
> since the controller authenticates to the vault as that app. The chart fails
> rendering if only some are set.

### `clusterIdentity` — the ClusterCertIdentity

Set `clusterIdentity.name` to `""` (or `null`) to skip rendering it (e.g. when your
`appCerts` reference an identity created elsewhere).

| Key | Default | Description |
| --- | --- | --- |
| `name` | `master-cert-identity-1` | `metadata.name` of the ClusterCertIdentity. |
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
| `appID` / `appObjectID` | no | Optional per-item Entra app (paired with root `tenantID`). |
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
chart). Each [GitHub release](https://github.com/keytos/ezca-cert-controller/releases)
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
helm install my-release ./ezca-cert-controller-<version>.tgz \
  --namespace ezca-cert-controller-system --create-namespace -f my-values.yaml
```

**Or verify at install time** straight from the registry with `--verify`:

```bash
helm install ezca-cert-controller-system \
  oci://keytos-eqgzasb8bufxa0cd.azurecr.io/ezca/helm/ezca-cert-controller \
  --version <version> --verify --keyring ~/.gnupg/ezca-pubring.gpg \
  --namespace ezca-cert-controller-system --create-namespace
```

Verification fails if the chart was tampered with or was not signed by the Keytos key.

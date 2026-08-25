{{/*
Custom helpers for rendering EZCA certificate resources (ClusterCertIdentity /
ManagedCredential) from the cert-config section of values.yaml.

These are additive to the plugin-generated _helpers.tpl and live in a separate
file so re-running `kubebuilder edit --plugins=helm/v2-alpha` (which rewrites
_helpers.tpl) cannot clobber them.
*/}}

{{/*
ezca.labels — common labels applied to the CRs this chart renders.
*/}}
{{- define "ezca.labels" -}}
app.kubernetes.io/name: {{ include "ezca-cert-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{/*
ezca.baseSpec — renders the shared CertIdentitySpecBase fields for one CR.

Call: {{ include "ezca.baseSpec" (dict "item" <perCRmap> "root" .Values.global) }}

Field ownership:
  - GLOBAL (from $root = .Values.global, never overridable per item): ezcaURL,
    cloud, tenantID, appInsightsConnString.
  - PER-ITEM (from $item): appID, appObjectID, certSecretName, renewalThreshold,
    keyVault.

The CRD CEL rules require tenantID+appID+appObjectID to be set together, and
keyVault requires the app fields. The global tenantID pairs with each item's own
appID/appObjectID; the trio is emitted only when all three resolve, so the CEL
constraint is always satisfied.
*/}}
{{- define "ezca.baseSpec" -}}
{{- $item := .item -}}
{{- $root := .root -}}
ezcaURL: {{ required "global.ezcaURL must be set in values.yaml" $root.ezcaURL | quote }}
{{- if $root.cloud }}
cloud: {{ $root.cloud }}
{{- end }}
{{- if and $root.tenantID $item.appID $item.appObjectID }}
tenantID: {{ $root.tenantID | quote }}
appID: {{ $item.appID | quote }}
appObjectID: {{ $item.appObjectID | quote }}
{{- else if or $item.appID $item.appObjectID }}
{{- fail "appID and appObjectID must be set together with global.tenantID (CRD CEL: tenantID/appID/appObjectID are all-or-nothing)" }}
{{- end }}
{{- if $root.appInsightsConnString }}
appInsightsConnString: {{ $root.appInsightsConnString | quote }}
{{- end }}
{{- if $item.certSecretName }}
certSecretName: {{ $item.certSecretName | quote }}
{{- end }}
renewalThreshold: {{ default 20 $item.renewalThreshold }}
{{- if $item.keyVault }}
{{- if and (or $item.keyVault.vaultName $item.keyVault.certName) (not (and $item.keyVault.vaultName $item.keyVault.certName)) }}
{{- fail "keyVault needs both vaultName and certName; set both to enable Key Vault sync, or neither to disable it" }}
{{- end }}
{{- if and $item.keyVault.vaultName $item.keyVault.certName }}
{{- if not (and $root.tenantID $item.appID $item.appObjectID) }}
{{- fail "keyVault requires the Entra app fields (global.tenantID plus this item's appID/appObjectID); the certificate authenticates to Key Vault as that app" }}
{{- end }}
keyVault:
  vaultName: {{ $item.keyVault.vaultName | quote }}
  certName: {{ $item.keyVault.certName | quote }}
{{- end }}
{{- end }}
{{- end -}}

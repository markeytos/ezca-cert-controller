/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// CloudEnvironment selects the Azure sovereign cloud used for Entra ID and
// Microsoft Graph.
// +kubebuilder:validation:Enum=Public;USGov
type CloudEnvironment string

const (
	// CloudPublic is the Azure public cloud.
	CloudPublic CloudEnvironment = "Public"
	// CloudUSGov is the Azure US Government cloud.
	CloudUSGov CloudEnvironment = "USGov"
)

type CertIdentityStatusBase struct {
	// conditions represent the current state of the ClusterCertIdentity resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// notBefore is the start of the current certificate's validity window.
	// +optional
	NotBefore *metav1.Time `json:"notBefore,omitempty"`

	// notAfter is the end of the current certificate's validity window.
	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`

	// thumbprint is the SHA-1 thumbprint (hex) of the current certificate.
	// +optional
	Thumbprint string `json:"thumbprint,omitempty"`

	// lastRenewalTime is when the controller last renewed the certificate.
	// +optional
	LastRenewalTime *metav1.Time `json:"lastRenewalTime,omitempty"`

	// pendingThumbprint is the SHA-1 thumbprint (hex) of a renewed certificate
	// that has been added to the app registration and is awaiting propagation
	// in Entra ID before it is promoted into the Secret.
	// +optional
	PendingThumbprint string `json:"pendingThumbprint,omitempty"`

	// pendingSince is when the pending certificate was added, used to bound how
	// long the controller waits for Entra ID propagation.
	// +optional
	PendingSince *metav1.Time `json:"pendingSince,omitempty"`

	// managedKeyCredentials are the certificates the controller has added to
	// the Entra ID app registration, tracked so expired ones can be removed.
	// +listType=map
	// +listMapKey=thumbprint
	// +optional
	ManagedKeyCredentials []ManagedKeyCredential `json:"managedKeyCredentials,omitempty"`
}

type CertIdentitySpecBase struct {
	// ezcaURL is the base URL of the EZCA instance used to renew the
	// certificate (for example https://portal.ezca.io).
	// +required
	// +kubebuilder:validation:MinLength=1
	EZCAURL *string `json:"ezcaURL"`

	// tenantID is the Entra ID (Azure AD) tenant that owns the app
	// registration. It must be set together with appID.
	// +optional
	// +kubebuilder:validation:MinLength=1
	TenantID *string `json:"tenantID,omitempty"`

	// appID is the Entra ID (Azure AD) application (client) ID whose
	// certificate credentials are rotated. It is used to authenticate as the
	// app and as the proof-of-possession issuer. It must be set together with
	// tenantID and appObjectID.
	// +optional
	// +kubebuilder:validation:MinLength=1
	AppID *string `json:"appID,omitempty"`

	// appObjectID is the Entra ID directory object ID of the app registration
	// (the "id" of the application object, not the appId). It is required to
	// call Graph addKey/removeKey directly, avoiding a lookup that needs
	// directory read permissions. It must be set together with tenantID and
	// appID.
	// +optional
	// +kubebuilder:validation:MinLength=1
	AppObjectID *string `json:"appObjectID,omitempty"`

	// cloud selects the Azure sovereign cloud used to reach Entra ID and
	// Microsoft Graph.
	// +optional
	// +kubebuilder:default:=Public
	Cloud CloudEnvironment `json:"cloud,omitempty"`

	// certSecretName is the name of the kubernetes.io/tls Secret holding the
	// bootstrapped certificate (tls.crt, leaf plus chain) and its RSA private
	// key (tls.key). The controller reads and rewrites this Secret.
	// +kubebuilder:default:="cluster-cert-identity"
	CertSecretName string `json:"certSecretName"`

	// appInsightsConnString is an optional Azure Application Insights
	// connection string. When set, renewals, rotations, and errors are
	// reported to Application Insights.
	// +optional
	// +kubebuilder:validation:MinLength=1
	AppInsightsConnString *string `json:"appInsightsConnString,omitempty"`

	// keyVault, when set, keeps a certificate in an Azure Key Vault in sync with
	// the Secret. On every reconcile the controller ensures the named vault
	// certificate matches the Secret, importing the current certificate (and
	// key) whenever they differ. The controller authenticates to the vault as
	// the identity's app using its certificate, so this requires the app fields
	// (tenantID, appID, appObjectID) and the app service principal must have get
	// and import permission on the vault.
	// +optional
	KeyVault *KeyVaultSpec `json:"keyVault,omitempty"`

	// renewalThreshold is the percentage of the certificate's total lifetime
	// remaining at or below which the certificate is renewed.
	// +kubebuilder:default:=20
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=99
	RenewalThreshold int32 `json:"renewalThreshold"`
}

// ClusterCertIdentitySpec defines the desired state of ClusterCertIdentity.
//
// A ClusterCertIdentity represents either a bare certificate or an Entra ID app
// registration paired with a certificate. The certificate and its RSA private
// key are bootstrapped by an administrator into the referenced Secret; the
// controller renews the certificate through EZCA before it expires and, when an
// app is configured, rotates the renewed certificate onto the app registration.
//
// +kubebuilder:validation:XValidation:rule="has(self.tenantID) == has(self.appID) && has(self.appID) == has(self.appObjectID)",message="tenantID, appID, and appObjectID must be set together"
// +kubebuilder:validation:XValidation:rule="!has(self.keyVault) || has(self.appID)",message="keyVault requires the Entra app fields (tenantID, appID, appObjectID); the certificate authenticates to Key Vault as that app"
type ClusterCertIdentitySpec struct {
	CertIdentitySpecBase `json:",inline"`

	// certSecretNamespace is the namespace of the certificate Secret. When
	// empty it defaults to the namespace the controller runs in.
	// +optional
	// +kubebuilder:validation:MinLength=1
	CertSecretNamespace string `json:"certSecretNamespace,omitempty"`

	// allowedNamespaces is the set of namespaces whose ManagedCredentials may
	// reference this ClusterCertIdentity (via spec.identityRef) to bootstrap
	// their certificate. Because a ClusterCertIdentity is cluster-scoped, a
	// reference lets the referencing ManagedCredential issue certificates as
	// this identity's Entra app; this allowlist bounds which namespaces may do
	// so. It is required and must be non-empty: a ClusterCertIdentity that lists
	// no namespaces can be referenced by no one.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:MinLength=1
	AllowedNamespaces []string `json:"allowedNamespaces"`
}

// KeyVaultSpec identifies an Azure Key Vault certificate to keep in sync with
// the controller-managed certificate.
type KeyVaultSpec struct {
	// vaultName is the name of the Azure Key Vault (not the full URL).
	// +required
	// +kubebuilder:validation:MinLength=1
	VaultName string `json:"vaultName"`

	// certName is the name of the certificate in the vault to keep in sync.
	// +required
	// +kubebuilder:validation:MinLength=1
	CertName string `json:"certName"`
}

// ManagedKeyCredential records a certificate the controller added to an Entra ID
// app registration so it can be removed once it expires.
type ManagedKeyCredential struct {
	// thumbprint is the SHA-1 thumbprint (hex) of the managed certificate.
	// +required
	Thumbprint string `json:"thumbprint"`

	// keyID is the keyCredential identifier assigned by Microsoft Graph.
	// +required
	KeyID string `json:"keyID"`

	// notAfter is the managed certificate's expiry. The credential is removed
	// from the app registration only after this time.
	// +required
	NotAfter metav1.Time `json:"notAfter"`

	// addedAt is when the credential was added to the app registration. Entra
	// propagation windows are measured from this time; the certificate's own
	// notBefore can predate the registration by hours (EZCA backdates it) or
	// days (a certificate registered after issuance).
	// +optional
	AddedAt *metav1.Time `json:"addedAt,omitempty"`
}

// ClusterCertIdentityStatus defines the observed state of ClusterCertIdentity.
type ClusterCertIdentityStatus struct {
	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	CertIdentityStatusBase `json:",inline"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cci
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Available')].status"
// +kubebuilder:printcolumn:name="Expiration",type=string,JSONPath=".status.notAfter"
// +kubebuilder:printcolumn:name="Thumbprint",type=string,JSONPath=".status.thumbprint"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// ClusterCertIdentity is the Schema for the clustercertidentities API
type ClusterCertIdentity struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ClusterCertIdentity
	// +required
	Spec ClusterCertIdentitySpec `json:"spec"`

	// status defines the observed state of ClusterCertIdentity
	// +optional
	Status ClusterCertIdentityStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ClusterCertIdentityList contains a list of ClusterCertIdentity
type ClusterCertIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ClusterCertIdentity `json:"items"`
}

// SpecBase returns the shared certificate-identity spec fields, letting the
// controller treat ClusterCertIdentity and ManagedCredential uniformly.
func (c *ClusterCertIdentity) SpecBase() *CertIdentitySpecBase {
	return &c.Spec.CertIdentitySpecBase
}

// StatusBase returns the shared certificate-identity status fields.
func (c *ClusterCertIdentity) StatusBase() *CertIdentityStatusBase {
	return &c.Status.CertIdentityStatusBase
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ClusterCertIdentity{}, &ClusterCertIdentityList{})
		return nil
	})
}

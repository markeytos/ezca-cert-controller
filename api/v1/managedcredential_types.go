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

// +kubebuilder:validation:Enum=ClusterCertIdentity;CertIdentity
type IdentityKind string

const (
	IdentityKindClusterCertIdentity IdentityKind = "ClusterCertIdentity"
	IdentityKindCertIdentity        IdentityKind = "CertIdentity"
)

// KeyUsage is a certificate key usage. The values mirror the key usages
// supported by EZCA (see ezca-go's KeyUsage).
// +kubebuilder:validation:Enum=DigitalSignature;KeyEncipherment;DataEncipherment;KeyAgreement;NonRepudiation
type KeyUsage string

const (
	KeyUsageDigitalSignature KeyUsage = "DigitalSignature"
	KeyUsageKeyEncipherment  KeyUsage = "KeyEncipherment"
	KeyUsageDataEncipherment KeyUsage = "DataEncipherment"
	KeyUsageKeyAgreement     KeyUsage = "KeyAgreement"
	KeyUsageNonRepudiation   KeyUsage = "NonRepudiation"
)

// ExtKeyUsage is a certificate extended key usage. The values mirror the
// extended key usages supported by EZCA (see ezca-go's ExtKeyUsage).
// +kubebuilder:validation:Enum=Any;ServerAuth;ClientAuth;CodeSigning;EmailProtection;IPSECEndSystem;IPSECTunnel;IPSECUser;TimeStamping;OCSPSigning;MicrosoftServerGatedCrypto;NetscapeServerGatedCrypto;MicrosoftCommercialCodeSigning;MicrosoftKernelCodeSigning
type ExtKeyUsage string

const (
	ExtKeyUsageAny                            ExtKeyUsage = "Any"
	ExtKeyUsageServerAuth                     ExtKeyUsage = "ServerAuth"
	ExtKeyUsageClientAuth                     ExtKeyUsage = "ClientAuth"
	ExtKeyUsageCodeSigning                    ExtKeyUsage = "CodeSigning"
	ExtKeyUsageEmailProtection                ExtKeyUsage = "EmailProtection"
	ExtKeyUsageIPSECEndSystem                 ExtKeyUsage = "IPSECEndSystem"
	ExtKeyUsageIPSECTunnel                    ExtKeyUsage = "IPSECTunnel"
	ExtKeyUsageIPSECUser                      ExtKeyUsage = "IPSECUser"
	ExtKeyUsageTimeStamping                   ExtKeyUsage = "TimeStamping"
	ExtKeyUsageOCSPSigning                    ExtKeyUsage = "OCSPSigning"
	ExtKeyUsageMicrosoftServerGatedCrypto     ExtKeyUsage = "MicrosoftServerGatedCrypto"
	ExtKeyUsageNetscapeServerGatedCrypto      ExtKeyUsage = "NetscapeServerGatedCrypto"
	ExtKeyUsageMicrosoftCommercialCodeSigning ExtKeyUsage = "MicrosoftCommercialCodeSigning"
	ExtKeyUsageMicrosoftKernelCodeSigning     ExtKeyUsage = "MicrosoftKernelCodeSigning"
)

// ManagedCredentialSpec defines the desired state of ManagedCredential.
//
// +kubebuilder:validation:XValidation:rule="has(self.tenantID) == has(self.appID) && has(self.appID) == has(self.appObjectID)",message="tenantID, appID, and appObjectID must be set together"
// +kubebuilder:validation:XValidation:rule="!has(self.keyVault) || has(self.appID)",message="keyVault requires the Entra app fields (tenantID, appID, appObjectID); the certificate authenticates to Key Vault as that app"
type ManagedCredentialSpec struct {
	CertIdentitySpecBase `json:",inline"`

	// subjectName is the certificate subject. It may be a full RFC 4514
	// distinguished name (for example "CN=app,OU=team,O=corp") or a bare common
	// name (for example "app.example.com"), in which case it is treated as the
	// CN.
	// +required
	// +kubebuilder:validation:MinLength=1
	SubjectName string `json:"subjectName"`

	// dnsNames are the DNS Name (dNSName) subject alternative names.
	// +optional
	// +kubebuilder:validation:items:MinLength=1
	DNSNames []string `json:"dnsNames,omitempty"`

	// ipAddresses are the IP Address (iPAddress) subject alternative names.
	// +optional
	// +kubebuilder:validation:items:MinLength=1
	IPAddresses []string `json:"ipAddresses,omitempty"`

	// uris are the URI (uniformResourceIdentifier) subject alternative names.
	// +optional
	// +kubebuilder:validation:items:MinLength=1
	URIs []string `json:"uris,omitempty"`

	// emailAddresses are the email (rfc822Name) subject alternative names.
	// +optional
	// +kubebuilder:validation:items:MinLength=1
	EmailAddresses []string `json:"emailAddresses,omitempty"`

	// validityInDays is the requested certificate lifetime in days. When unset
	// the issuing authority's default (90 days) is used.
	// +optional
	// +kubebuilder:validation:Minimum=1
	ValidityInDays int32 `json:"validityInDays,omitempty"`

	// keyUsages are the certificate key usages. When empty the issuer defaults
	// to Digital Signature and Key Encipherment.
	// +optional
	KeyUsages []KeyUsage `json:"keyUsages,omitempty"`

	// extendedKeyUsages are the certificate extended key usages. When empty the
	// issuer defaults to Server Authentication and Client Authentication.
	// +optional
	ExtendedKeyUsages []ExtKeyUsage `json:"extendedKeyUsages,omitempty"`

	// caID is the EZCA SSL certificate authority (UUID) that issues this
	// credential's certificate when it is bootstrapped or re-issued.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Format=uuid
	CAID string `json:"caID"`

	// templateID is the EZCA template (UUID) used when issuing this credential's
	// certificate.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Format=uuid
	TemplateID string `json:"templateID"`

	// identityRef points to the identity whose certificate bootstraps this
	// credential. It is required on first issuance (when the Secret is empty),
	// where its certificate authenticates the issuance request to EZCA.
	// +optional
	IdentityRef IdentityRefSpec `json:"identityRef,omitempty"`
}

type IdentityRefSpec struct {
	// name is the name of the identity from which we bootstrap this credential.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// kind is the kind of identity referenced (ClusterCertIdentity or
	// CertIdentity).
	// +required
	// +kubebuilder:validation:MinLength=1
	Kind IdentityKind `json:"kind"`
}

// ManagedCredentialStatus defines the observed state of ManagedCredential.
type ManagedCredentialStatus struct {
	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	CertIdentityStatusBase `json:",inline"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mc
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Available')].status"
// +kubebuilder:printcolumn:name="Expiration",type=string,JSONPath=".status.notAfter"
// +kubebuilder:printcolumn:name="Thumbprint",type=string,JSONPath=".status.thumbprint"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// ManagedCredential is the Schema for the managedcredentials API
type ManagedCredential struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ManagedCredential
	// +required
	Spec ManagedCredentialSpec `json:"spec"`

	// status defines the observed state of ManagedCredential
	// +optional
	Status ManagedCredentialStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ManagedCredentialList contains a list of ManagedCredential
type ManagedCredentialList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ManagedCredential `json:"items"`
}

// SpecBase returns the shared certificate-identity spec fields, letting the
// controller treat ManagedCredential and ClusterCertIdentity uniformly.
func (m *ManagedCredential) SpecBase() *CertIdentitySpecBase {
	return &m.Spec.CertIdentitySpecBase
}

// StatusBase returns the shared certificate-identity status fields.
func (m *ManagedCredential) StatusBase() *CertIdentityStatusBase {
	return &m.Status.CertIdentityStatusBase
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ManagedCredential{}, &ManagedCredentialList{})
		return nil
	})
}

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

// CertIdentitySpec defines the desired state of CertIdentity.
//
// +kubebuilder:validation:XValidation:rule="has(self.tenantID) == has(self.appID) && has(self.appID) == has(self.appObjectID)",message="tenantID, appID, and appObjectID must be set together"
// +kubebuilder:validation:XValidation:rule="!has(self.keyVault) || has(self.appID)",message="keyVault requires the Entra app fields (tenantID, appID, appObjectID); the certificate authenticates to Key Vault as that app"
type CertIdentitySpec struct {
	CertIdentitySpecBase `json:",inline"`
}

// CertIdentityStatus defines the observed state of CertIdentity.
type CertIdentityStatus struct {
	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// Conditions and the other shared status fields (including conditions) come
	// from the embedded base.
	CertIdentityStatusBase `json:",inline"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ci

// CertIdentity is the Schema for the certidentities API
type CertIdentity struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of CertIdentity
	// +required
	Spec CertIdentitySpec `json:"spec"`

	// status defines the observed state of CertIdentity
	// +optional
	Status CertIdentityStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=ci
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Available')].status"
// +kubebuilder:printcolumn:name="Expiration",type=string,JSONPath=".status.notAfter"
// +kubebuilder:printcolumn:name="Thumbprint",type=string,JSONPath=".status.thumbprint"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// CertIdentityList contains a list of CertIdentity
type CertIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []CertIdentity `json:"items"`
}

func (c *CertIdentity) SpecBase() *CertIdentitySpecBase {
	return &c.Spec.CertIdentitySpecBase
}

func (c *CertIdentity) StatusBase() *CertIdentityStatusBase {
	return &c.Status.CertIdentityStatusBase
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &CertIdentity{}, &CertIdentityList{})
		return nil
	})
}

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

package controller

import (
	"crypto/rsa"
	"crypto/x509"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ezca "github.com/markeytos/ezca-go"

	"github.com/markeytos/ezca-cert-controller/internal/entra"
	"github.com/markeytos/ezca-cert-controller/internal/keyvault"
)

// ReconcilerBase holds the fields every certificate-identity reconciler shares
// and implements the reconcilerDeps methods on their behalf. Each concrete
// reconciler embeds it, so the shared state machine can reach the Kubernetes
// client, the clock, and the (test-overridable) Azure/EZCA client factories
// uniformly.
type ReconcilerBase struct {
	client.Client
	Scheme *runtime.Scheme

	// Now, NewEZCAClient, NewEntraClient, and NewKeyVaultClient are injection
	// points for tests. When nil, real implementations are used.
	Now               func() time.Time
	NewEZCAClient     func(ezcaURL string) (ezcaRenewer, error)
	NewEntraClient    func(tenantID, appID string, cl entra.Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (entraManager, error)
	NewKeyVaultClient func(vaultName, tenantID, appID string, cl keyvault.Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (keyVaultManager, error)
}

// kubeClient returns the controller-runtime client (reconcilerDeps).
func (r *ReconcilerBase) kubeClient() client.Client {
	return r.Client
}

func (r *ReconcilerBase) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *ReconcilerBase) newEZCAClient(ezcaURL string) (ezcaRenewer, error) {
	if r.NewEZCAClient != nil {
		return r.NewEZCAClient(ezcaURL)
	}
	return ezca.NewCertificateClient(ezcaURL)
}

func (r *ReconcilerBase) newEntraClient(tenantID, appID string, cl entra.Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (entraManager, error) {
	if r.NewEntraClient != nil {
		return r.NewEntraClient(tenantID, appID, cl, cert, key)
	}
	return entra.NewClient(tenantID, appID, cl, cert, key)
}

func (r *ReconcilerBase) newKeyVaultClient(vaultName, tenantID, appID string, cl keyvault.Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (keyVaultManager, error) {
	if r.NewKeyVaultClient != nil {
		return r.NewKeyVaultClient(vaultName, tenantID, appID, cl, cert, key)
	}
	return keyvault.NewClient(vaultName, tenantID, appID, cl, cert, key)
}

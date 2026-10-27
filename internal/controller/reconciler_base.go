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
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	ezca "github.com/markeytos/ezca-go"

	"github.com/markeytos/ezca-cert-controller/internal/entra"
	"github.com/markeytos/ezca-cert-controller/internal/keyvault"
)

// specOrDeletionChanged filters the events of a reconciler's own resource down
// to spec changes (generation) and deletion. It drops status-only updates: the
// controller's own status writes would otherwise start another reconcile
// straight away, bypassing the error backoff — and a Degraded message that
// carries a fresh Entra trace ID changes on every failed attempt.
var specOrDeletionChanged = predicate.Or[client.Object](
	predicate.GenerationChangedPredicate{},
	predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		return !e.ObjectNew.GetDeletionTimestamp().IsZero()
	}},
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

	// Propagation bounds how long a key added to an app registration is given
	// to propagate across Entra ID. Zero fields use the defaults.
	Propagation PropagationTiming

	// issued holds certificates EZCA issued that are not stored in a Secret
	// yet, by object UID, so a Secret write that keeps failing is retried with
	// the same certificate instead of having EZCA issue another on every pass.
	// It is in memory only: a restart can cost at most one more issuance.
	issuedMu sync.Mutex
	issued   map[types.UID]heldIssuance
}

// heldIssuance is an issued certificate awaiting storage. replaces is the
// thumbprint of the active certificate it was issued to replace ("" when
// there was none).
type heldIssuance struct {
	replaces string
	chain    []*x509.Certificate
	key      *rsa.PrivateKey
}

// holdIssued keeps an issued certificate until releaseIssued confirms it was
// stored.
func (r *ReconcilerBase) holdIssued(uid types.UID, replaces string, chain []*x509.Certificate, key *rsa.PrivateKey) {
	r.issuedMu.Lock()
	defer r.issuedMu.Unlock()
	if r.issued == nil {
		r.issued = map[types.UID]heldIssuance{}
	}
	r.issued[uid] = heldIssuance{replaces: replaces, chain: chain, key: key}
}

// heldIssued returns the certificate held for uid when it was issued to
// replace the given active certificate and is still valid.
func (r *ReconcilerBase) heldIssued(uid types.UID, replaces string, now time.Time) ([]*x509.Certificate, *rsa.PrivateKey, bool) {
	r.issuedMu.Lock()
	defer r.issuedMu.Unlock()
	h, ok := r.issued[uid]
	if !ok {
		return nil, nil, false
	}
	if !h.chain[0].NotAfter.After(now) {
		delete(r.issued, uid)
		return nil, nil, false
	}
	if h.replaces != replaces {
		return nil, nil, false
	}
	return h.chain, h.key, true
}

// releaseIssued drops the certificate held for uid once it is stored.
func (r *ReconcilerBase) releaseIssued(uid types.UID) {
	r.issuedMu.Lock()
	defer r.issuedMu.Unlock()
	delete(r.issued, uid)
}

// PropagationTiming bounds how long the controller waits for a key added to an
// app registration to propagate across Entra ID before relying on it.
type PropagationTiming struct {
	// Grace is the minimum time between adding a key to an app and promoting
	// the certificate. The checks that the certificate authenticates are
	// spread across it.
	Grace time.Duration
	// Timeout is how long after adding a key the certificate may still fail
	// to authenticate before the identity reports Degraded. It must exceed
	// Grace.
	Timeout time.Duration
}

// Validate reports whether the timing is usable.
func (t PropagationTiming) Validate() error {
	if t.Grace <= 0 {
		return fmt.Errorf("propagation grace must be positive, got %s", t.Grace)
	}
	if t.Timeout <= t.Grace {
		return fmt.Errorf("propagation timeout (%s) must exceed the propagation grace (%s)", t.Timeout, t.Grace)
	}
	return nil
}

// verifyInterval is how far apart the checks that a staged certificate
// authenticates are spaced, so that propagationVerifications of them span the
// grace.
func (t PropagationTiming) verifyInterval() time.Duration {
	return t.Grace / propagationVerifications
}

func (r *ReconcilerBase) propagation() PropagationTiming {
	t := r.Propagation
	if t.Grace <= 0 {
		t.Grace = DefaultPropagationGrace
	}
	if t.Timeout <= 0 {
		t.Timeout = DefaultPropagationTimeout
	}
	return t
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

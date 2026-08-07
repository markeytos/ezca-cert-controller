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
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	ezcav1 "github.com/markeytos/ezca-cert-controller/api/v1"
	"github.com/markeytos/ezca-cert-controller/internal/entra"
	"github.com/markeytos/ezca-cert-controller/internal/keyvault"
	"github.com/markeytos/ezca-cert-controller/internal/pki"
	"github.com/markeytos/ezca-cert-controller/internal/telemetry"
)

// Shared status condition types used by every certificate-identity kind.
const (
	// typeAvailableCertIdentity indicates the certificate is present and valid.
	typeAvailableCertIdentity = "Available"
	// typeProgressingCertIdentity indicates the certificate is being renewed.
	typeProgressingCertIdentity = "Progressing"
	// typeDegradedCertIdentity indicates reconciliation encountered an error.
	typeDegradedCertIdentity = "Degraded"

	// reasonPendingPropagation is the Progressing condition reason used while a
	// newly added certificate awaits Entra ID propagation before promotion.
	reasonPendingPropagation = "PendingPropagation"

	tlsCertKey = "tls.crt"
	tlsKeyKey  = "tls.key"
	// tlsCertPendingKey and tlsKeyPendingKey stage a renewed certificate that
	// has been added to the app registration but is awaiting Entra ID
	// propagation. The active tls.crt/tls.key keep serving the current
	// certificate until the staged one can authenticate.
	tlsCertPendingKey = "tls.crt.pending"
	tlsKeyPendingKey  = "tls.key.pending"

	// maxRequeueAfter bounds how long the controller waits before re-checking a
	// certificate, so managed-credential cleanup also runs at least this often.
	maxRequeueAfter = 24 * time.Hour

	// propagationRequeue is how often the controller re-checks whether a staged
	// certificate has become usable, once the propagation grace has elapsed and
	// there is a point in trying to authenticate with it.
	propagationRequeue = 30 * time.Second
	// propagationGrace is the minimum time to wait after adding a key before
	// using it at all. A newly added key is not immediately present on every
	// token-endpoint replica, so the controller does not authenticate with the
	// certificate until this window has passed.
	propagationGrace = 5 * time.Minute
	// propagationTimeout is how long propagation may take before the controller
	// surfaces a Degraded condition (it keeps retrying afterwards).
	propagationTimeout = 15 * time.Minute
)

// ezcaRenewer renews a certificate through EZCA. Satisfied by
// *ezca.CertificateClient; overridable in tests.
type ezcaRenewer interface {
	RenewCertificateV3(ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey, csr []byte, validityDays int) ([]*x509.Certificate, error)
}

// entraManager manages certificate credentials on an app registration.
// Satisfied by *entra.Client; overridable in tests.
type entraManager interface {
	VerifyCredential(ctx context.Context) error
	AddKey(ctx context.Context, objectID string, newCertDER []byte) (string, error)
	RemoveKey(ctx context.Context, objectID, keyID string) error
}

// keyVaultManager keeps a certificate in Azure Key Vault in sync. Satisfied by
// *keyvault.Client; overridable in tests.
type keyVaultManager interface {
	CertificateMatches(ctx context.Context, certName, thumbprint string) (bool, error)
	ImportCertificate(ctx context.Context, certName string, pemBundle []byte) error
}

// certIdentity is the shared behavior of the certificate-identity kinds
// (ClusterCertIdentity, CertIdentity, and ManagedCredential). Exposing the
// embedded base spec and status lets the renewal/rotation/Key Vault state
// machine operate on all kinds uniformly.
type certIdentity interface {
	client.Object
	SpecBase() *ezcav1.CertIdentitySpecBase
	StatusBase() *ezcav1.CertIdentityStatusBase
}

// reconcilerDeps provides the shared state machine with the Kubernetes client,
// a clock, and the (test-overridable) Azure/EZCA client factories. Every
// reconciler satisfies it by embedding reconcilerBase.
type reconcilerDeps interface {
	kubeClient() client.Client
	now() time.Time
	newEZCAClient(ezcaURL string) (ezcaRenewer, error)
	newEntraClient(tenantID, appID string, cl entra.Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (entraManager, error)
	newKeyVaultClient(vaultName, tenantID, appID string, cl keyvault.Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (keyVaultManager, error)
}

// renewFallback lets a kind (ManagedCredential) recover from a renewal failure
// by re-issuing a fresh certificate. reissueOnRenewFailure returns handled=true
// when it took over, along with the result to return. Kinds that do not
// implement it (ClusterCertIdentity and CertIdentity) simply surface the
// renewal error.
type renewFallback interface {
	reissueOnRenewFailure(ctx context.Context, obj certIdentity, secret *corev1.Secret, current *x509.Certificate, key *rsa.PrivateKey, now time.Time, tel *telemetry.Telemetry, renewErr error) (bool, ctrl.Result, error)
}

// reconcileCertState runs the renewal/rotation state machine and updates status
// conditions on obj in place (persisted by the caller).
func reconcileCertState(ctx context.Context, d reconcilerDeps, obj certIdentity, secret *corev1.Secret, chain []*x509.Certificate, key *rsa.PrivateKey, now time.Time, tel *telemetry.Telemetry) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	spec := obj.SpecBase()
	status := obj.StatusBase()
	current := chain[0]

	// If a renewed certificate is staged and awaiting propagation in Entra ID,
	// try to promote it. The active tls.crt/tls.key keep serving the current
	// (trusted) certificate until the renewed one can authenticate.
	if hasPendingCert(secret) {
		return promoteIfReady(ctx, d, obj, secret, tel, now)
	}

	remaining := pki.LifetimeFractionRemaining(current, now)
	if remaining > float64(spec.RenewalThreshold) {
		// Not due for renewal. Still clean up any managed credentials that have
		// expired since the last renewal.
		if appConfigured(obj) && hasExpiredManagedCredentials(obj, now) {
			if err := manageApp(ctx, d, obj, current, key, nil, tel, now); err != nil {
				log.Error(err, "Failed to clean up expired app credentials")
			}
		}
		setAvailable(obj, "CertificateValid", "Certificate is valid and not yet due for renewal")
		return ctrl.Result{RequeueAfter: requeueForRenewal(current, spec.RenewalThreshold, now)}, nil
	}

	log.Info("Renewing certificate", "thumbprint", pki.Thumbprint(current), "remainingPercent", int(remaining))
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:    typeProgressingCertIdentity,
		Status:  metav1.ConditionTrue,
		Reason:  "Renewing",
		Message: "Certificate crossed the renewal threshold and is being renewed",
	})

	newChain, newKey, err := renew(ctx, d, obj, current, key, tel)
	if err != nil {
		if fb, ok := d.(renewFallback); ok {
			if handled, res, herr := fb.reissueOnRenewFailure(ctx, obj, secret, current, key, now, tel, err); handled {
				return res, herr
			}
		}
		setDegraded(obj, "RenewalFailed", fmt.Sprintf("Failed to renew certificate: %v", err))
		return ctrl.Result{}, err
	}
	newLeaf := newChain[0]

	// Certificate-only identity: nothing to authenticate against, so promote
	// the renewed certificate immediately.
	if !appConfigured(obj) {
		if err := writeActiveSecret(ctx, d, secret, newChain, newKey); err != nil {
			tel.TrackError(err, "Failed to write renewed certificate Secret", identityProps(obj))
			setDegraded(obj, "SecretWriteFailed", fmt.Sprintf("Failed to write renewed certificate to Secret: %v", err))
			return ctrl.Result{}, err
		}
		setObservedCert(obj, newLeaf)
		status.LastRenewalTime = &metav1.Time{Time: now}
		tel.TrackEvent("CertificateRenewed", identityProps(obj))
		log.Info("Renewed certificate", "thumbprint", pki.Thumbprint(newLeaf), "notAfter", newLeaf.NotAfter)
		setAvailable(obj, "CertificateRenewed", "Certificate renewed successfully")
		return ctrl.Result{RequeueAfter: requeueForRenewal(newLeaf, spec.RenewalThreshold, now)}, nil
	}

	// App identity: add the renewed certificate to the app registration using
	// the current (trusted) certificate, then stage it as pending. It is
	// promoted into the active Secret only once Entra ID can authenticate with
	// it (see promoteIfReady), so the Secret never serves an unusable cert to
	// the controller or to other consumers.
	if err := manageApp(ctx, d, obj, current, key, newLeaf, tel, now); err != nil {
		setDegraded(obj, "AppRotationFailed", fmt.Sprintf("Failed to add renewed certificate to app registration: %v", err))
		return ctrl.Result{}, err
	}
	if err := writePendingSecret(ctx, d, secret, newChain, newKey); err != nil {
		tel.TrackError(err, "Failed to stage renewed certificate Secret", identityProps(obj))
		setDegraded(obj, "SecretWriteFailed", fmt.Sprintf("Failed to stage renewed certificate: %v", err))
		return ctrl.Result{}, err
	}
	status.PendingThumbprint = pki.Thumbprint(newLeaf)
	status.PendingSince = &metav1.Time{Time: now}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:    typeProgressingCertIdentity,
		Status:  metav1.ConditionTrue,
		Reason:  reasonPendingPropagation,
		Message: "Renewed certificate added to the app registration; waiting for Entra ID propagation",
	})
	log.Info("Staged renewed certificate, waiting for Entra ID propagation", "thumbprint", pki.Thumbprint(newLeaf))
	return ctrl.Result{RequeueAfter: propagationRequeueAfter(now, status.PendingSince)}, nil
}

// promoteIfReady checks whether the staged (pending) certificate can now
// authenticate to Entra ID and, if so, promotes it into the active Secret.
// Until then the active certificate is left untouched, so consumers keep using
// a certificate Entra ID already trusts.
func promoteIfReady(ctx context.Context, d reconcilerDeps, obj certIdentity, secret *corev1.Secret, tel *telemetry.Telemetry, now time.Time) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	spec := obj.SpecBase()
	status := obj.StatusBase()

	pendingChain, pendingKey, err := parsePendingSecret(secret)
	if err != nil {
		// The staged data is unusable; drop it and renew again next pass.
		delete(secret.Data, tlsCertPendingKey)
		delete(secret.Data, tlsKeyPendingKey)
		if uerr := d.kubeClient().Update(ctx, secret); uerr != nil {
			return ctrl.Result{}, uerr
		}
		status.PendingThumbprint = ""
		status.PendingSince = nil
		setDegraded(obj, "InvalidPendingCertificate", fmt.Sprintf("Staged certificate is invalid: %v", err))
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	pendingLeaf := pendingChain[0]

	if status.PendingSince != nil && now.Sub(status.PendingSince.Time) < propagationGrace {
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:    typeProgressingCertIdentity,
			Status:  metav1.ConditionTrue,
			Reason:  "Stabilizing",
			Message: fmt.Sprintf("Renewed certificate authenticated; waiting %s for Entra ID propagation to stabilize", propagationGrace),
		})
		return ctrl.Result{RequeueAfter: propagationRequeueAfter(now, status.PendingSince)}, nil
	}

	cl, err := d.newEntraClient(*spec.TenantID, *spec.AppID, cloudFor(spec.Cloud), pendingLeaf, pendingKey)
	if err != nil {
		return ctrl.Result{}, err
	}
	if verr := cl.VerifyCredential(ctx); verr != nil {
		// Past the grace window and still not usable. Poll until the propagation
		// timeout; beyond it, fail loudly (retries continue, more slowly, so the
		// certificate can still self-heal).
		if status.PendingSince != nil && now.Sub(status.PendingSince.Time) > propagationTimeout {
			tel.TrackError(verr, "Renewed certificate has not propagated in Entra ID", identityProps(obj))
			setDegraded(obj, "PropagationTimeout", fmt.Sprintf("Renewed certificate not usable after %s: %v", propagationTimeout, verr))
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:    typeProgressingCertIdentity,
			Status:  metav1.ConditionTrue,
			Reason:  reasonPendingPropagation,
			Message: "Waiting for the renewed certificate to propagate in Entra ID",
		})
		return ctrl.Result{RequeueAfter: propagationRequeue}, nil
	}

	// Usable and past the grace window: promote the staged certificate.
	if err := promoteSecret(ctx, d, secret); err != nil {
		tel.TrackError(err, "Failed to promote renewed certificate Secret", identityProps(obj))
		setDegraded(obj, "SecretWriteFailed", fmt.Sprintf("Failed to promote renewed certificate: %v", err))
		return ctrl.Result{}, err
	}
	setObservedCert(obj, pendingLeaf)
	status.LastRenewalTime = &metav1.Time{Time: now}
	status.PendingThumbprint = ""
	status.PendingSince = nil
	tel.TrackEvent("CertificateRenewed", identityProps(obj))
	log.Info("Promoted renewed certificate", "thumbprint", pki.Thumbprint(pendingLeaf), "notAfter", pendingLeaf.NotAfter)
	setAvailable(obj, "CertificateRenewed", "Certificate renewed successfully")
	return ctrl.Result{RequeueAfter: requeueForRenewal(pendingLeaf, spec.RenewalThreshold, now)}, nil
}

// renew builds a renewal CSR (with a fresh key) and renews the certificate
// through EZCA using the current certificate for authentication.
func renew(ctx context.Context, d reconcilerDeps, obj certIdentity, current *x509.Certificate, key *rsa.PrivateKey, tel *telemetry.Telemetry) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	csrDER, newKey, err := pki.BuildRenewalCSR(current)
	if err != nil {
		return nil, nil, err
	}
	renewer, err := d.newEZCAClient(*obj.SpecBase().EZCAURL)
	if err != nil {
		return nil, nil, err
	}
	newChain, err := renewer.RenewCertificateV3(ctx, current, key, csrDER, pki.ValidityInDays(current))
	if err != nil {
		tel.TrackError(err, "Failed to renew certificate via EZCA", identityProps(obj))
		return nil, nil, err
	}
	return newChain, newKey, nil
}

// manageApp authenticates to Microsoft Graph as the app (using authCert), adds
// newLeaf when non-nil, and removes any managed credentials that have expired.
// It targets the app registration by its directory object ID directly, so no
// directory-read permission is needed: addKey/removeKey succeed with a
// proof-of-possession signed by the app's current certificate.
func manageApp(ctx context.Context, d reconcilerDeps, obj certIdentity, authCert *x509.Certificate, authKey *rsa.PrivateKey, newLeaf *x509.Certificate, tel *telemetry.Telemetry, now time.Time) error {
	spec := obj.SpecBase()
	status := obj.StatusBase()
	cl, err := d.newEntraClient(*spec.TenantID, *spec.AppID, cloudFor(spec.Cloud), authCert, authKey)
	if err != nil {
		return err
	}
	objectID := *spec.AppObjectID

	if newLeaf != nil {
		keyID, err := cl.AddKey(ctx, objectID, newLeaf.Raw)
		if err != nil {
			tel.TrackError(err, "Failed to add renewed certificate to app registration", identityProps(obj))
			return err
		}
		status.ManagedKeyCredentials = append(status.ManagedKeyCredentials, ezcav1.ManagedKeyCredential{
			Thumbprint: pki.Thumbprint(newLeaf),
			KeyID:      keyID,
			NotAfter:   metav1.Time{Time: newLeaf.NotAfter},
		})
		tel.TrackEvent("CertificateAddedToApp", identityProps(obj))
	}

	var remaining []ezcav1.ManagedKeyCredential
	for _, mc := range status.ManagedKeyCredentials {
		if mc.NotAfter.After(now) {
			remaining = append(remaining, mc) // still valid
			continue
		}
		if err := cl.RemoveKey(ctx, objectID, mc.KeyID); err != nil {
			tel.TrackError(err, "Failed to remove expired certificate from app registration", identityProps(obj))
			remaining = append(remaining, mc) // keep to retry next time
			continue
		}
		tel.TrackEvent("ExpiredCertificateRemoved", identityProps(obj))
		// Removed from the app: drop from status.
	}
	status.ManagedKeyCredentials = remaining

	// When a key was just added, persist the tracking immediately. The caller
	// still has to stage/promote the certificate and write the Secret; if any of
	// that fails, this ensures the added credential is already recorded so it is
	// cleaned up on expiry instead of being orphaned on the app registration.
	if newLeaf != nil {
		if err := d.kubeClient().Status().Update(ctx, obj); err != nil {
			return err
		}
	}
	return nil
}

// writeActiveSecret rewrites the active tls.crt/tls.key with the given chain
// and key.
func writeActiveSecret(ctx context.Context, d reconcilerDeps, secret *corev1.Secret, chain []*x509.Certificate, key *rsa.PrivateKey) error {
	if err := setTLSData(secret, tlsCertKey, tlsKeyKey, chain, key); err != nil {
		return err
	}
	return d.kubeClient().Update(ctx, secret)
}

// writePendingSecret stages the renewed chain and key under the pending keys,
// leaving the active certificate untouched.
func writePendingSecret(ctx context.Context, d reconcilerDeps, secret *corev1.Secret, chain []*x509.Certificate, key *rsa.PrivateKey) error {
	if err := setTLSData(secret, tlsCertPendingKey, tlsKeyPendingKey, chain, key); err != nil {
		return err
	}
	return d.kubeClient().Update(ctx, secret)
}

// promoteSecret moves the staged certificate into the active tls.crt/tls.key
// and removes the pending keys.
func promoteSecret(ctx context.Context, d reconcilerDeps, secret *corev1.Secret) error {
	secret.Data[tlsCertKey] = secret.Data[tlsCertPendingKey]
	secret.Data[tlsKeyKey] = secret.Data[tlsKeyPendingKey]
	delete(secret.Data, tlsCertPendingKey)
	delete(secret.Data, tlsKeyPendingKey)
	return d.kubeClient().Update(ctx, secret)
}

// propagationRequeueAfter returns how long to wait before next acting on a
// certificate that became current at since (staged at PendingSince, or issued
// at NotBefore).
func propagationRequeueAfter(now time.Time, since *metav1.Time) time.Duration {
	if since == nil {
		return propagationRequeue
	}
	if remaining := propagationGrace - now.Sub(since.Time); remaining > 0 {
		return remaining
	}
	return propagationRequeue
}

func setTLSData(secret *corev1.Secret, certKey, keyKey string, chain []*x509.Certificate, key *rsa.PrivateKey) error {
	keyPEM, err := pki.EncodeRSAPrivateKeyPEM(key)
	if err != nil {
		return err
	}
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data[certKey] = pki.EncodeCertChainPEM(chain)
	secret.Data[keyKey] = keyPEM
	return nil
}

// syncKeyVaultBestEffort runs the Key Vault sync without letting it override a
// successful core result. It defers while a freshly changed certificate is
// still propagating across Entra ID token replicas, and treats the
// "certificate not yet registered" auth error as a quiet, transient retry
// rather than a hard failure.
func syncKeyVaultBestEffort(ctx context.Context, d reconcilerDeps, obj certIdentity, secret *corev1.Secret, now time.Time, tel *telemetry.Telemetry, result *ctrl.Result, coreErr error) {
	log := logf.FromContext(ctx)
	status := obj.StatusBase()

	// A freshly issued active certificate may not yet be usable on every AAD
	// token replica; give it the propagation grace before authenticating to Key
	// Vault with it. This is measured from the certificate's own NotBefore
	// rather than the last renewal time, so a certificate promoted only after it
	// already authenticated (and waited out the grace since being staged) is not
	// charged the grace a second time — it syncs right away.
	if status.NotBefore != nil && now.Sub(status.NotBefore.Time) < propagationGrace {
		requeueAtMost(result, propagationRequeueAfter(now, status.NotBefore))
		return
	}

	kvErr := syncKeyVault(ctx, d, obj, secret, tel)
	if kvErr == nil {
		return
	}
	// Transient: the certificate is correct but not yet on the replica we
	// reached. Poll quietly until the propagation timeout; past that it is no
	// longer plausibly propagation, so fall through and report it as a failure.
	if isCredentialPropagating(kvErr) &&
		(status.NotBefore == nil || now.Sub(status.NotBefore.Time) <= propagationTimeout) {
		log.Info("Deferring Key Vault sync: certificate still propagating in Entra ID")
		requeueAtMost(result, propagationRequeue)
		return
	}
	log.Error(kvErr, "Failed to sync certificate to Key Vault")
	tel.TrackError(kvErr, "Failed to sync certificate to Key Vault", identityProps(obj))
	if coreErr == nil {
		setDegraded(obj, "KeyVaultSyncFailed", fmt.Sprintf("Failed to sync certificate to Key Vault: %v", kvErr))
		requeueAtMost(result, time.Minute)
	}
}

// syncKeyVault ensures the configured Key Vault certificate matches the active
// Secret certificate, importing the current chain and key when they differ. It
// authenticates to the vault as the identity's app using that certificate, so
// keyVault requires the app fields (enforced by CRD validation).
func syncKeyVault(ctx context.Context, d reconcilerDeps, obj certIdentity, secret *corev1.Secret, tel *telemetry.Telemetry) error {
	spec := obj.SpecBase()
	chain, key, err := parseSecret(secret)
	if err != nil {
		return err
	}
	leaf := chain[0]

	cl, err := d.newKeyVaultClient(spec.KeyVault.VaultName, *spec.TenantID, *spec.AppID, keyVaultCloudFor(spec.Cloud), leaf, key)
	if err != nil {
		return err
	}
	match, err := cl.CertificateMatches(ctx, spec.KeyVault.CertName, pki.Thumbprint(leaf))
	if err != nil {
		return err
	}
	if match {
		return nil
	}

	keyPEM, err := pki.EncodeRSAPrivateKeyPEM(key)
	if err != nil {
		return err
	}
	bundle := append(pki.EncodeCertChainPEM(chain), keyPEM...)
	if err := cl.ImportCertificate(ctx, spec.KeyVault.CertName, bundle); err != nil {
		return err
	}
	logf.FromContext(ctx).Info("Updated Key Vault certificate",
		"vault", spec.KeyVault.VaultName, "certName", spec.KeyVault.CertName, "thumbprint", pki.Thumbprint(leaf))
	tel.TrackEvent("KeyVaultCertificateUpdated", identityProps(obj))
	return nil
}

// requeueAtMost lowers result.RequeueAfter to d if it is currently unset or
// longer than d.
func requeueAtMost(result *ctrl.Result, d time.Duration) {
	if result.RequeueAfter == 0 || result.RequeueAfter > d {
		result.RequeueAfter = d
	}
}

// isCredentialPropagating reports whether err is the transient Entra ID error
// returned while a newly added certificate has not yet propagated to the token
// endpoint replica that served the request.
func isCredentialPropagating(err error) bool {
	return err != nil && strings.Contains(err.Error(), entra.KeyNotFoundOnAppErrorCode)
}

func requeueForRenewal(cert *x509.Certificate, thresholdPct int32, now time.Time) time.Duration {
	d := pki.NextRenewalTime(cert, thresholdPct).Sub(now)
	if d <= 0 {
		d = time.Minute
	}
	if d > maxRequeueAfter {
		d = maxRequeueAfter
	}
	return d
}

func setAvailable(obj certIdentity, reason, message string) {
	status := obj.StatusBase()
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:    typeAvailableCertIdentity,
		Status:  metav1.ConditionTrue,
		Reason:  reason,
		Message: message,
	})
	meta.RemoveStatusCondition(&status.Conditions, typeProgressingCertIdentity)
	meta.RemoveStatusCondition(&status.Conditions, typeDegradedCertIdentity)
}

func setDegraded(obj certIdentity, reason, message string) {
	status := obj.StatusBase()
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:    typeDegradedCertIdentity,
		Status:  metav1.ConditionTrue,
		Reason:  reason,
		Message: message,
	})
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:    typeAvailableCertIdentity,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	})
}

func parseSecret(secret *corev1.Secret) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	return parseTLS(secret, tlsCertKey, tlsKeyKey)
}

func parsePendingSecret(secret *corev1.Secret) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	return parseTLS(secret, tlsCertPendingKey, tlsKeyPendingKey)
}

func hasPendingCert(secret *corev1.Secret) bool {
	return len(secret.Data[tlsCertPendingKey]) > 0 && len(secret.Data[tlsKeyPendingKey]) > 0
}

// isEmptyTLSSecret reports whether the Secret carries no active certificate
// material, so a ManagedCredential can bootstrap into it.
func isEmptyTLSSecret(secret *corev1.Secret) bool {
	return len(secret.Data[tlsCertKey]) == 0 || len(secret.Data[tlsKeyKey]) == 0
}

func parseTLS(secret *corev1.Secret, certKey, keyKey string) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	certData := secret.Data[certKey]
	if len(certData) == 0 {
		return nil, nil, fmt.Errorf("missing %q", certKey)
	}
	keyData := secret.Data[keyKey]
	if len(keyData) == 0 {
		return nil, nil, fmt.Errorf("missing %q", keyKey)
	}
	chain, err := pki.ParseCertChainPEM(certData)
	if err != nil {
		return nil, nil, err
	}
	key, err := pki.ParseRSAPrivateKey(keyData)
	if err != nil {
		return nil, nil, err
	}
	return chain, key, nil
}

func setObservedCert(obj certIdentity, cert *x509.Certificate) {
	status := obj.StatusBase()
	status.NotBefore = &metav1.Time{Time: cert.NotBefore}
	status.NotAfter = &metav1.Time{Time: cert.NotAfter}
	status.Thumbprint = pki.Thumbprint(cert)
}

func appConfigured(obj certIdentity) bool {
	spec := obj.SpecBase()
	return spec.TenantID != nil && spec.AppID != nil && spec.AppObjectID != nil
}

func hasExpiredManagedCredentials(obj certIdentity, now time.Time) bool {
	for _, mc := range obj.StatusBase().ManagedKeyCredentials {
		if !mc.NotAfter.After(now) {
			return true
		}
	}
	return false
}

func cloudFor(c ezcav1.CloudEnvironment) entra.Cloud {
	if c == ezcav1.CloudUSGov {
		return entra.CloudUSGov
	}
	return entra.CloudPublic
}

func keyVaultCloudFor(c ezcav1.CloudEnvironment) keyvault.Cloud {
	if c == ezcav1.CloudUSGov {
		return keyvault.CloudUSGov
	}
	return keyvault.CloudPublic
}

// azureCloudFor maps the CRD cloud selection to the azcore cloud configuration
// used to reach EZCA. It sets the Azure Resource Manager token scope the EZCA
// client requests, so certificate issuance authenticates against the right
// sovereign cloud (the public management endpoint is rejected in Government).
func azureCloudFor(c ezcav1.CloudEnvironment) cloud.Configuration {
	if c == ezcav1.CloudUSGov {
		return cloud.AzureGovernment
	}
	return cloud.AzurePublic
}

func identityProps(obj certIdentity) map[string]string {
	status := obj.StatusBase()
	props := map[string]string{
		"identity":   obj.GetName(),
		"thumbprint": status.Thumbprint,
	}
	if spec := obj.SpecBase(); spec.AppID != nil {
		props["appID"] = *spec.AppID
	}
	return props
}

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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	// reasonAdditionalAppRotationFailed is the Degraded condition reason used
	// while some additional apps do not hold the identity's certificate.
	reasonAdditionalAppRotationFailed = "AdditionalAppRotationFailed"
	// unrotatedAppsRecheck is how often an identity whose additional apps were
	// left without its certificate checks whether they have been fixed.
	unrotatedAppsRecheck = time.Hour

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

	// propagationRequeue is how often the controller retries a Key Vault sync
	// whose certificate has not propagated yet.
	propagationRequeue = 30 * time.Second
	// propagationVerifications is how many consecutive checks, spaced evenly
	// across the propagation grace, a staged certificate must pass before it is
	// promoted. One successful token only shows that one token-endpoint
	// replica holds the new key.
	propagationVerifications = 3
)

const (
	// DefaultPropagationGrace is the default minimum time between adding a key
	// to an app registration and promoting the certificate. A newly added key
	// is not immediately present on every token-endpoint replica, and renewal
	// starts with a fifth of the certificate's lifetime left (the old key stays
	// registered until it expires), so waiting is cheap.
	DefaultPropagationGrace = time.Hour
	// DefaultPropagationTimeout is the default for how long propagation may take
	// before the controller surfaces a Degraded condition (it keeps retrying
	// afterwards).
	DefaultPropagationTimeout = 2 * time.Hour
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
	propagation() PropagationTiming
	holdIssued(uid types.UID, replaces string, chain []*x509.Certificate, key *rsa.PrivateKey)
	heldIssued(uid types.UID, replaces string, now time.Time) ([]*x509.Certificate, *rsa.PrivateKey, bool)
	releaseIssued(uid types.UID)
}

// renewFallback lets a kind (ManagedCredential) recover from a renewal failure
// by re-issuing a fresh certificate. reissueOnRenewFailure returns handled=true
// when it took over, along with the result to return. Kinds that do not
// implement it (ClusterCertIdentity and CertIdentity) simply surface the
// renewal error.
type renewFallback interface {
	reissueOnRenewFailure(ctx context.Context, obj certIdentity, secret *corev1.Secret, current *x509.Certificate, key *rsa.PrivateKey, now time.Time, tel *telemetry.Telemetry, renewErr error) (bool, ctrl.Result, error)
}

// registrationAuthenticator is implemented by reconcilers that choose which
// certificate authenticates registering a staged certificate on the app
// registrations. Kinds that do not implement it (ClusterCertIdentity and
// CertIdentity) use the active certificate.
type registrationAuthenticator interface {
	stagedRegistrationAuth(ctx context.Context, obj certIdentity, active authCredential, now time.Time) []authCredential
}

// authCredential is a certificate and key to authenticate as an app
// registration with.
type authCredential struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// pendingRegistrationAuth returns, in order of preference, the credentials to
// try for registering the staged certificate on the app registrations.
func pendingRegistrationAuth(ctx context.Context, d reconcilerDeps, obj certIdentity, secret *corev1.Secret, now time.Time) ([]authCredential, error) {
	activeChain, activeKey, err := parseSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("parsing active certificate: %w", err)
	}
	active := authCredential{cert: activeChain[0], key: activeKey}
	if ra, ok := d.(registrationAuthenticator); ok {
		return ra.stagedRegistrationAuth(ctx, obj, active, now), nil
	}
	return []authCredential{active}, nil
}

// registerStaged adds the staged certificate to the app registrations that do
// not hold it yet, trying each credential in turn. manageApp is idempotent per
// app, so a later credential only completes what an earlier one could not.
func registerStaged(ctx context.Context, d reconcilerDeps, obj certIdentity, secret *corev1.Secret, pendingLeaf *x509.Certificate, tel *telemetry.Telemetry, now time.Time) error {
	creds, err := pendingRegistrationAuth(ctx, d, obj, secret, now)
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		return errors.New("no valid certificate to authenticate the registration with")
	}
	for _, c := range creds {
		if err = manageApp(ctx, d, obj, c.cert, c.key, pendingLeaf, tel, now); err == nil {
			return nil
		}
	}
	return err
}

// authenticatesAs reports whether cert can obtain a token as the app.
func authenticatesAs(ctx context.Context, d reconcilerDeps, spec *ezcav1.CertIdentitySpecBase, appID string, cert *x509.Certificate, key *rsa.PrivateKey) bool {
	cl, err := d.newEntraClient(*spec.TenantID, appID, cloudFor(spec.Cloud), cert, key)
	return err == nil && cl.VerifyCredential(ctx) == nil
}

// certValidAt reports whether now is within cert's validity window.
func certValidAt(cert *x509.Certificate, now time.Time) bool {
	return !cert.NotBefore.After(now) && cert.NotAfter.After(now)
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
		if apps := unrotatedAdditionalApps(ctx, d, obj, current, key); len(apps) > 0 {
			setAdditionalAppsNotRotated(obj, apps, nil)
			return ctrl.Result{RequeueAfter: unrotatedAppsRequeue(current, spec.RenewalThreshold, now)}, nil
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

	// A certificate renewed on an earlier pass whose Secret write failed is
	// reused, rather than having EZCA issue another on every retry.
	newChain, newKey, held := d.heldIssued(obj.GetUID(), pki.Thumbprint(current), now)
	if held {
		log.Info("Reusing the renewed certificate an earlier pass could not store", "thumbprint", pki.Thumbprint(newChain[0]))
	} else {
		var err error
		newChain, newKey, err = renew(ctx, d, obj, current, key, tel)
		if err != nil {
			if fb, ok := d.(renewFallback); ok {
				if handled, res, herr := fb.reissueOnRenewFailure(ctx, obj, secret, current, key, now, tel, err); handled {
					return res, herr
				}
			}
			setDegraded(obj, "RenewalFailed", fmt.Sprintf("Failed to renew certificate: %v", err))
			return ctrl.Result{}, err
		}
		d.holdIssued(obj.GetUID(), pki.Thumbprint(current), newChain, newKey)
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
		d.releaseIssued(obj.GetUID())
		setObservedCert(obj, newLeaf)
		status.LastRenewalTime = &metav1.Time{Time: now}
		tel.TrackEvent("CertificateRenewed", identityProps(obj))
		log.Info("Renewed certificate", "thumbprint", pki.Thumbprint(newLeaf), "notAfter", newLeaf.NotAfter)
		setAvailable(obj, "CertificateRenewed", "Certificate renewed successfully")
		return ctrl.Result{RequeueAfter: requeueForRenewal(newLeaf, spec.RenewalThreshold, now)}, nil
	}

	// App identity: stage the renewed certificate as pending, then add it to the
	// app registration (and to every additional app) using the current
	// (trusted) certificate. It is promoted into the active Secret only once
	// every app can authenticate with it, or the primary app can after the
	// active certificate has expired (see promoteIfReady), so the Secret
	// never serves an unusable cert to the controller or to other consumers.
	//
	// Staging comes first so that a failed registration never discards the
	// renewed certificate: the next pass finds it staged and retries only the
	// registration (promoteIfReady), instead of renewing — and having EZCA issue
	// another certificate — on every retry while Entra keeps failing.
	if err := writePendingSecret(ctx, d, secret, newChain, newKey); err != nil {
		tel.TrackError(err, "Failed to stage renewed certificate Secret", identityProps(obj))
		setDegraded(obj, "SecretWriteFailed", fmt.Sprintf("Failed to stage renewed certificate: %v", err))
		return ctrl.Result{}, err
	}
	d.releaseIssued(obj.GetUID())
	stagePending(status, newLeaf, now)
	if err := manageApp(ctx, d, obj, current, key, newLeaf, tel, now); err != nil {
		reportRegistrationFailure(ctx, obj, pki.Thumbprint(newLeaf), err)
		if managedCredentialFor(status, pki.Thumbprint(newLeaf)) == nil {
			// Not even the primary app took the certificate. It stays staged;
			// promotion retries the registration.
			return ctrl.Result{}, err
		}
		// The primary app holds the renewed certificate but some additional apps
		// may not yet. The registrations made so far are recorded in status, and
		// promotion retries the missing apps and waits until every app holds the
		// certificate.
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:    typeProgressingCertIdentity,
		Status:  metav1.ConditionTrue,
		Reason:  reasonPendingPropagation,
		Message: "Renewed certificate added to the app registration; waiting for Entra ID propagation",
	})
	log.Info("Staged renewed certificate, waiting for Entra ID propagation", "thumbprint", pki.Thumbprint(newLeaf))
	return ctrl.Result{RequeueAfter: checkBefore(checkInterval(d.propagation(), certValidAt(current, now)), current.NotAfter, now)}, nil
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
		if derr := discardPendingCert(ctx, d, obj, secret); derr != nil {
			return ctrl.Result{}, derr
		}
		setDegraded(obj, "InvalidPendingCertificate", fmt.Sprintf("Staged certificate is invalid: %v", err))
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	pendingLeaf := pendingChain[0]

	// An expired staged certificate can never be promoted — for instance one
	// left behind in the Secret by an earlier rotation after the object's status
	// (and its PendingSince) was reset by a delete/recreate. Drop it and requeue
	// so the active certificate is re-evaluated, rather than polling a dead
	// certificate forever.
	if !pendingLeaf.NotAfter.After(now) {
		log.Info("Discarding staged certificate outside its validity window; falling back to the active certificate",
			"thumbprint", pki.Thumbprint(pendingLeaf), "notBefore", pendingLeaf.NotBefore, "notAfter", pendingLeaf.NotAfter)
		if derr := discardPendingCert(ctx, d, obj, secret); derr != nil {
			return ctrl.Result{}, derr
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	// A staged certificate that is not valid yet means the controller's clock is
	// behind the CA's. Wait for it rather than discarding it, which would have
	// EZCA issue another certificate on every pass.
	if pendingLeaf.NotBefore.After(now) {
		log.Info("Staged certificate is not valid yet; waiting for it", "thumbprint", pki.Thumbprint(pendingLeaf), "notBefore", pendingLeaf.NotBefore)
		return ctrl.Result{RequeueAfter: pendingLeaf.NotBefore.Sub(now) + time.Second}, nil
	}

	// When the active certificate has already expired (or cannot be read),
	// nothing is left to protect by waiting out the propagation grace: the
	// staged certificate is checked often and promoted as soon as it
	// authenticates as the primary app.
	activeValid := false
	var activeExpiry time.Time
	if activeChain, _, perr := parseSecret(secret); perr == nil {
		activeValid = certValidAt(activeChain[0], now)
		activeExpiry = activeChain[0].NotAfter
	}

	// Every pending certificate needs a PendingSince to drive the grace and
	// timeout windows below. If it is missing — the staged certificate outlived
	// the status that tracked it — adopt now, so promotion still makes progress
	// and can time out instead of looping indefinitely.
	if status.PendingSince == nil {
		stagePending(status, pendingLeaf, now)
	}

	// Complete any registrations the rotation could not finish: the staged
	// certificate is promoted only once every configured app holds it, so retry
	// the missing addKey calls. A staged certificate status does not track was
	// never added to the primary app (the rotation's registration failed, or its
	// record was lost); it must be before anything else can happen. A failed
	// registration on any app keeps the identity Degraded with the Graph error,
	// and while the active certificate is valid there is nothing to verify
	// until every app holds the certificate.
	//
	// Once the active certificate has expired, additional apps no longer hold
	// promotion back. An app still missing the staged certificate then can no
	// longer receive it with the active one (Graph's addKey proof must be
	// signed by a certificate the app trusts), and every app sharing the
	// certificate is already failing with the expired one, so waiting would
	// only keep the primary app down too. The registration is still retried
	// first (a ManagedCredential may have its identityRef to authenticate
	// with), and the apps left without the certificate stay named in the
	// Degraded condition after promotion.
	pendingThumbprint := pki.Thumbprint(pendingLeaf)
	onPrimary := managedCredentialFor(status, pendingThumbprint) != nil || adoptUnrecordedPrimaryKey(ctx, d, obj, pendingLeaf, pendingKey)
	var registerErr error
	if !onPrimary || len(missingAdditionalApps(obj, pendingThumbprint)) > 0 {
		registerErr = registerStaged(ctx, d, obj, secret, pendingLeaf, tel, now)
		if registerErr != nil {
			reportRegistrationFailure(ctx, obj, pendingThumbprint, registerErr)
		}
		if managedCredentialFor(status, pendingThumbprint) == nil {
			return ctrl.Result{}, registerErr
		}
		if activeValid && len(missingAdditionalApps(obj, pendingThumbprint)) > 0 {
			// Adding the key later moves the propagation anchor, which restarts
			// the checks, so none are worth making until then.
			return ctrl.Result{RequeueAfter: checkBefore(checkInterval(d.propagation(), activeValid), activeExpiry, now)}, nil
		}
		if registerErr == nil {
			recoverFromDegraded(obj, activeValid)
		}
	}

	// Propagation is measured from the latest moment a key for the staged
	// certificate was added to any app, so an app that only received it on a
	// retry still gets the full grace. The certificate is checked
	// propagationVerifications times, spaced evenly across the grace, and is
	// promoted only after that many consecutive checks in which it
	// authenticated as every app: one successful token only shows that one
	// token-endpoint replica holds the new key.
	timing := d.propagation()
	interval := checkInterval(timing, activeValid)
	anchor := propagationAnchor(obj, pendingThumbprint)
	if status.PendingLastVerified != nil && status.PendingLastVerified.Time.Before(anchor) {
		// Checks made before the latest key was added cannot vouch for it.
		status.PendingVerifications = 0
		status.PendingLastVerified = nil
	}
	nextCheck := anchor.Add(interval)
	if status.PendingLastVerified != nil {
		nextCheck = status.PendingLastVerified.Add(interval)
	}
	if now.Before(nextCheck) {
		if !meta.IsStatusConditionTrue(status.Conditions, typeDegradedCertIdentity) {
			setStabilizing(obj, timing)
		}
		return ctrl.Result{RequeueAfter: nextCheck.Sub(now)}, nil
	}

	for _, appID := range promotionAppIDs(spec, activeValid) {
		cl, err := d.newEntraClient(*spec.TenantID, appID, cloudFor(spec.Cloud), pendingLeaf, pendingKey)
		if err != nil {
			return ctrl.Result{}, err
		}
		verr := cl.VerifyCredential(ctx)
		if verr == nil {
			continue
		}
		// Not usable yet: start the count over. Keep checking until the
		// propagation timeout; beyond it, fail loudly (checks continue, so the
		// certificate can still self-heal).
		status.PendingVerifications = 0
		status.PendingLastVerified = &metav1.Time{Time: now}
		if now.Sub(anchor) > timing.Timeout {
			tel.TrackError(verr, "Renewed certificate has not propagated in Entra ID", identityPropsForApp(obj, appID))
			setDegraded(obj, "PropagationTimeout", fmt.Sprintf("Renewed certificate not usable by app %s after %s: %v", appID, timing.Timeout, verr))
			return ctrl.Result{RequeueAfter: interval}, nil
		}
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:    typeProgressingCertIdentity,
			Status:  metav1.ConditionTrue,
			Reason:  reasonPendingPropagation,
			Message: fmt.Sprintf("Waiting for the renewed certificate to propagate in Entra ID for app %s", appID),
		})
		return ctrl.Result{RequeueAfter: interval}, nil
	}
	status.PendingVerifications++
	status.PendingLastVerified = &metav1.Time{Time: now}
	recoverFromDegraded(obj, activeValid)
	if activeValid && (status.PendingVerifications < propagationVerifications || now.Sub(anchor) < timing.Grace) {
		setStabilizing(obj, timing)
		return ctrl.Result{RequeueAfter: interval}, nil
	}

	// Settled across the grace window (or replacing an expired certificate):
	// promote the staged certificate.
	if err := promoteSecret(ctx, d, secret); err != nil {
		tel.TrackError(err, "Failed to promote renewed certificate Secret", identityProps(obj))
		setDegraded(obj, "SecretWriteFailed", fmt.Sprintf("Failed to promote renewed certificate: %v", err))
		return ctrl.Result{}, err
	}
	setObservedCert(obj, pendingLeaf)
	status.LastRenewalTime = &metav1.Time{Time: now}
	clearPending(status)
	tel.TrackEvent("CertificateRenewed", identityProps(obj))
	log.Info("Promoted renewed certificate", "thumbprint", pki.Thumbprint(pendingLeaf), "notAfter", pendingLeaf.NotAfter)
	setAvailable(obj, "CertificateRenewed", "Certificate renewed successfully")
	if missing := missingAdditionalApps(obj, pendingThumbprint); len(missing) > 0 {
		// Promoted without some additional apps (the active certificate had
		// expired): they cannot authenticate with the identity's certificate
		// until an administrator adds it to them again.
		log.Info("Promoted renewed certificate without some additional app registrations", "thumbprint", pendingThumbprint, "appIDs", additionalAppIDs(missing))
		setAdditionalAppsNotRotated(obj, missing, registerErr)
		return ctrl.Result{RequeueAfter: unrotatedAppsRequeue(pendingLeaf, spec.RenewalThreshold, now)}, nil
	}
	return ctrl.Result{RequeueAfter: requeueForRenewal(pendingLeaf, spec.RenewalThreshold, now)}, nil
}

// checkInterval is how far apart a staged certificate is checked: spread
// across the grace while the active certificate still serves, and at the
// propagation poll interval once it has expired.
func checkInterval(timing PropagationTiming, activeValid bool) time.Duration {
	if !activeValid {
		return propagationRequeue
	}
	return timing.verifyInterval()
}

// adoptUnrecordedPrimaryKey tracks a staged certificate status does not record
// on the primary app when the app already trusts it: it was added, but the
// record of it was lost (every status write after the addKey failed). Adding it
// again would duplicate the key, or fail for good if Graph rejects the
// duplicate. It is tracked without a keyID instead; the controller cannot
// remove a key whose ID it never recorded, so that key stays on the app after
// it expires. It reports whether the certificate was adopted.
func adoptUnrecordedPrimaryKey(ctx context.Context, d reconcilerDeps, obj certIdentity, leaf *x509.Certificate, key *rsa.PrivateKey) bool {
	spec := obj.SpecBase()
	status := obj.StatusBase()
	if !authenticatesAs(ctx, d, spec, *spec.AppID, leaf, key) {
		return false
	}
	thumbprint := pki.Thumbprint(leaf)
	logf.FromContext(ctx).Info("Staged certificate is already registered on the app but was not recorded; it will not be removed automatically when it expires",
		"thumbprint", thumbprint, "appID", *spec.AppID)
	status.ManagedKeyCredentials = append(status.ManagedKeyCredentials, ezcav1.ManagedKeyCredential{
		Thumbprint: thumbprint,
		NotAfter:   metav1.Time{Time: leaf.NotAfter},
	})
	return true
}

// promotionAppIDs returns the apps a staged certificate must authenticate as
// before it is promoted: the primary app and every additional app, since it is
// not "there" until every app that shares it can use it. With the active
// certificate expired, only the primary app: withholding the staged
// certificate cannot help an additional app that does not accept it yet, since
// none of them accepts the expired one.
func promotionAppIDs(spec *ezcav1.CertIdentitySpecBase, activeValid bool) []string {
	appIDs := []string{*spec.AppID}
	if activeValid {
		appIDs = append(appIDs, additionalAppIDs(spec.AdditionalApps)...)
	}
	return appIDs
}

// checkBefore caps the wait d before a staged certificate is next checked at
// the active certificate's expiry, when additional apps still missing the
// staged certificate stop holding its promotion back.
func checkBefore(d time.Duration, expiry, now time.Time) time.Duration {
	if expiry.After(now) && expiry.Sub(now) < d {
		return expiry.Sub(now)
	}
	return d
}

// recoverFromDegraded clears a Degraded condition an earlier pass left behind
// once the rotation makes progress again (a registration or an authentication
// check succeeded). The active certificate keeps serving meanwhile, so the
// identity is Available again; with an expired active certificate it stays
// Degraded until the staged certificate is promoted.
func recoverFromDegraded(obj certIdentity, activeValid bool) {
	status := obj.StatusBase()
	if !activeValid || !meta.IsStatusConditionTrue(status.Conditions, typeDegradedCertIdentity) {
		return
	}
	meta.RemoveStatusCondition(&status.Conditions, typeDegradedCertIdentity)
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:    typeAvailableCertIdentity,
		Status:  metav1.ConditionTrue,
		Reason:  "RotationInProgress",
		Message: "The active certificate is serving while its renewal propagates in Entra ID",
	})
}

// setStabilizing reports a staged certificate that is waiting out the
// propagation grace or still collecting the checks promotion requires.
func setStabilizing(obj certIdentity, timing PropagationTiming) {
	status := obj.StatusBase()
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:   typeProgressingCertIdentity,
		Status: metav1.ConditionTrue,
		Reason: "Stabilizing",
		Message: fmt.Sprintf("Renewed certificate passed %d of %d authentication checks; promoting it once all pass, at least %s after it was added to every app",
			status.PendingVerifications, propagationVerifications, timing.Grace),
	})
}

// stagePending records leaf as the staged certificate, staged at now.
func stagePending(status *ezcav1.CertIdentityStatusBase, leaf *x509.Certificate, now time.Time) {
	status.PendingThumbprint = pki.Thumbprint(leaf)
	status.PendingSince = &metav1.Time{Time: now}
	status.PendingVerifications = 0
	status.PendingLastVerified = nil
}

// clearPending clears the staged-certificate status fields.
func clearPending(status *ezcav1.CertIdentityStatusBase) {
	status.PendingThumbprint = ""
	status.PendingSince = nil
	status.PendingVerifications = 0
	status.PendingLastVerified = nil
}

// propagationAnchor returns when Entra propagation of the staged certificate
// is measured from: the latest moment a key for it was added to any app
// registration, or when it was staged if that is later (for instance when no
// addition recorded its time).
func propagationAnchor(obj certIdentity, thumbprint string) time.Time {
	status := obj.StatusBase()
	anchor := status.PendingSince.Time
	later := func(t *metav1.Time) {
		if t != nil && t.After(anchor) {
			anchor = t.Time
		}
	}
	if entry := managedCredentialFor(status, thumbprint); entry != nil {
		later(entry.AddedAt)
		for _, ak := range entry.AdditionalKeys {
			later(ak.AddedAt)
		}
	}
	return anchor
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
// newLeaf when non-nil — to the primary app registration and to every
// additional app (spec.additionalApps) — and removes any managed credentials
// that have expired. It targets each app registration by its directory object
// ID directly, so no directory-read permission is needed: addKey/removeKey
// succeed with a proof-of-possession signed by a certificate the target app
// already trusts (authCert must be registered on every app).
//
// It is idempotent per app: a certificate already recorded as added to an app
// is not added again, so a retry after a partial failure only completes the
// missing registrations.
func manageApp(ctx context.Context, d reconcilerDeps, obj certIdentity, authCert *x509.Certificate, authKey *rsa.PrivateKey, newLeaf *x509.Certificate, tel *telemetry.Telemetry, now time.Time) error {
	spec := obj.SpecBase()
	status := obj.StatusBase()
	cl, err := d.newEntraClient(*spec.TenantID, *spec.AppID, cloudFor(spec.Cloud), authCert, authKey)
	if err != nil {
		return err
	}
	objectID := *spec.AppObjectID

	var addedKeys bool
	var addErr error
	if newLeaf != nil {
		thumbprint := pki.Thumbprint(newLeaf)
		if managedCredentialFor(status, thumbprint) == nil {
			keyID, err := cl.AddKey(ctx, objectID, newLeaf.Raw)
			if err != nil {
				tel.TrackError(err, "Failed to add renewed certificate to app registration", identityProps(obj))
				return err
			}
			status.ManagedKeyCredentials = append(status.ManagedKeyCredentials, ezcav1.ManagedKeyCredential{
				Thumbprint: thumbprint,
				KeyID:      keyID,
				NotAfter:   metav1.Time{Time: newLeaf.NotAfter},
				AddedAt:    &metav1.Time{Time: now},
			})
			addedKeys = true
			tel.TrackEvent("CertificateAddedToApp", identityProps(obj))
		}

		// Add the certificate to every additional app that does not hold it yet.
		// Keep going on failure so one unreachable app does not block the others;
		// every successful addition is recorded (and persisted below) so no key
		// is orphaned on an app registration.
		entry := managedCredentialFor(status, thumbprint)
		for _, app := range spec.AdditionalApps {
			if hasAdditionalKey(entry, app.AppObjectID) {
				continue
			}
			acl, err := d.newEntraClient(*spec.TenantID, app.AppID, cloudFor(spec.Cloud), authCert, authKey)
			if err != nil {
				addErr = errors.Join(addErr, fmt.Errorf("authenticating as additional app %s: %w", app.AppID, err))
				continue
			}
			keyID, err := acl.AddKey(ctx, app.AppObjectID, newLeaf.Raw)
			if err != nil {
				tel.TrackError(err, "Failed to add renewed certificate to additional app registration", identityPropsForApp(obj, app.AppID))
				addErr = errors.Join(addErr, fmt.Errorf("adding certificate to additional app %s: %w", app.AppID, err))
				continue
			}
			entry.AdditionalKeys = append(entry.AdditionalKeys, ezcav1.AdditionalAppKey{
				AppObjectID: app.AppObjectID,
				AppID:       app.AppID,
				KeyID:       keyID,
				AddedAt:     &metav1.Time{Time: now},
			})
			addedKeys = true
			tel.TrackEvent("CertificateAddedToApp", identityPropsForApp(obj, app.AppID))
		}
	}

	var remaining []ezcav1.ManagedKeyCredential
	for _, mc := range status.ManagedKeyCredentials {
		if mc.NotAfter.After(now) {
			remaining = append(remaining, mc) // still valid
			continue
		}
		// Remove the key from the primary app and from every additional app
		// independently, so a removal that keeps failing on one app does not
		// leave the expired key on the others. The entry is kept, holding only
		// the keys still to remove, until every removal has succeeded.
		mc.AdditionalKeys = removeAdditionalKeys(ctx, d, obj, authCert, authKey, mc.AdditionalKeys, tel)
		if mc.KeyID != "" {
			// A 404 means the key (or the app) is already gone.
			if err := cl.RemoveKey(ctx, objectID, mc.KeyID); err != nil && !entra.IsNotFound(err) {
				tel.TrackError(err, "Failed to remove expired certificate from app registration", identityProps(obj))
				remaining = append(remaining, mc) // keep to retry next time
				continue
			}
			tel.TrackEvent("ExpiredCertificateRemoved", identityProps(obj))
			// An empty keyID records that the primary app no longer holds the key.
			mc.KeyID = ""
		}
		if len(mc.AdditionalKeys) > 0 {
			remaining = append(remaining, mc)
		}
		// Otherwise removed from every app: drop from status.
	}
	status.ManagedKeyCredentials = remaining

	// When a key was just added, persist the tracking immediately. The caller
	// still has to stage/promote the certificate and write the Secret; if any of
	// that fails, this ensures the added credential is already recorded so it is
	// cleaned up on expiry instead of being orphaned on the app registration.
	if addedKeys {
		if err := d.kubeClient().Status().Update(ctx, obj); err != nil {
			return errors.Join(addErr, err)
		}
	}
	return addErr
}

// removeAdditionalKeys removes an expired certificate's keyCredentials from the
// additional apps that hold them, returning the ones still held (removal failed)
// so they can be retried. A key already gone (404) counts as removed. A key on
// an app no longer listed in spec.additionalApps is removed best effort and then
// dropped either way: the controller no longer manages that app, and the active
// certificate it would authenticate with was likely never added there, so
// retrying could never succeed.
func removeAdditionalKeys(ctx context.Context, d reconcilerDeps, obj certIdentity, authCert *x509.Certificate, authKey *rsa.PrivateKey, keys []ezcav1.AdditionalAppKey, tel *telemetry.Telemetry) []ezcav1.AdditionalAppKey {
	log := logf.FromContext(ctx)
	spec := obj.SpecBase()
	var held []ezcav1.AdditionalAppKey
	for _, ak := range keys {
		err := removeAdditionalKey(ctx, d, spec, authCert, authKey, ak)
		switch {
		case err == nil || entra.IsNotFound(err):
			tel.TrackEvent("ExpiredCertificateRemoved", identityPropsForApp(obj, ak.AppID))
		case !additionalAppConfigured(spec, ak):
			tel.TrackError(err, "Failed to remove expired certificate from an app no longer in additionalApps; no longer tracking it", identityPropsForApp(obj, ak.AppID))
			log.Error(err, "Could not remove expired certificate from an app no longer in spec.additionalApps; no longer tracking it",
				"appID", ak.AppID, "appObjectID", ak.AppObjectID, "keyID", ak.KeyID)
		default:
			tel.TrackError(err, "Failed to remove expired certificate from additional app registration", identityPropsForApp(obj, ak.AppID))
			held = append(held, ak)
		}
	}
	return held
}

func removeAdditionalKey(ctx context.Context, d reconcilerDeps, spec *ezcav1.CertIdentitySpecBase, authCert *x509.Certificate, authKey *rsa.PrivateKey, ak ezcav1.AdditionalAppKey) error {
	acl, err := d.newEntraClient(*spec.TenantID, ak.AppID, cloudFor(spec.Cloud), authCert, authKey)
	if err != nil {
		return err
	}
	return acl.RemoveKey(ctx, ak.AppObjectID, ak.KeyID)
}

// additionalAppConfigured reports whether the app holding ak is still listed in
// spec.additionalApps.
func additionalAppConfigured(spec *ezcav1.CertIdentitySpecBase, ak ezcav1.AdditionalAppKey) bool {
	for _, app := range spec.AdditionalApps {
		if app.AppObjectID == ak.AppObjectID && app.AppID == ak.AppID {
			return true
		}
	}
	return false
}

// managedCredentialFor returns the tracked key-credential entry for the given
// certificate thumbprint, or nil when the certificate was never added by the
// controller (for example, it was bootstrapped externally).
func managedCredentialFor(status *ezcav1.CertIdentityStatusBase, thumbprint string) *ezcav1.ManagedKeyCredential {
	for i := range status.ManagedKeyCredentials {
		if status.ManagedKeyCredentials[i].Thumbprint == thumbprint {
			return &status.ManagedKeyCredentials[i]
		}
	}
	return nil
}

// hasAdditionalKey reports whether the tracked entry records a keyCredential on
// the additional app with the given object ID.
func hasAdditionalKey(entry *ezcav1.ManagedKeyCredential, appObjectID string) bool {
	for _, ak := range entry.AdditionalKeys {
		if ak.AppObjectID == appObjectID {
			return true
		}
	}
	return false
}

// missingAdditionalApps returns the spec.additionalApps the controller-tracked
// certificate with the given thumbprint has not been added to yet. It returns
// nil for a certificate the controller does not track (bootstrapped
// externally), whose app registrations are the administrator's to manage.
func missingAdditionalApps(obj certIdentity, thumbprint string) []ezcav1.AdditionalAppSpec {
	spec := obj.SpecBase()
	if len(spec.AdditionalApps) == 0 {
		return nil
	}
	entry := managedCredentialFor(obj.StatusBase(), thumbprint)
	if entry == nil {
		return nil
	}
	var missing []ezcav1.AdditionalAppSpec
	for _, app := range spec.AdditionalApps {
		if !hasAdditionalKey(entry, app.AppObjectID) {
			missing = append(missing, app)
		}
	}
	return missing
}

// reportRegistrationFailure surfaces err, returned by manageApp while adding
// the certificate with the given thumbprint, on the condition the failure
// earns: AppRotationFailed when the primary app does not hold the certificate,
// AdditionalAppRotationFailed (naming the apps) when only some additional apps
// do not. When every app holds it, err only failed to record that in status,
// and is logged.
func reportRegistrationFailure(ctx context.Context, obj certIdentity, thumbprint string, err error) {
	log := logf.FromContext(ctx)
	spec := obj.SpecBase()
	if managedCredentialFor(obj.StatusBase(), thumbprint) == nil {
		log.Error(err, "Failed to add certificate to app registration", "thumbprint", thumbprint, "appID", *spec.AppID)
		setDegraded(obj, "AppRotationFailed", fmt.Sprintf("Failed to add certificate to app registration %s: %s", *spec.AppID, conditionError(err)))
		return
	}
	missing := missingAdditionalApps(obj, thumbprint)
	if len(missing) == 0 {
		log.Error(err, "Failed to record certificate app registrations in status", "thumbprint", thumbprint)
		return
	}
	appIDs := additionalAppIDs(missing)
	log.Error(err, "Failed to add certificate to additional app registrations", "thumbprint", thumbprint, "appIDs", appIDs)
	setDegraded(obj, reasonAdditionalAppRotationFailed, fmt.Sprintf("Failed to add certificate to additional app registrations %s: %s",
		strings.Join(appIDs, ", "), conditionError(err)))
}

// setAdditionalAppsNotRotated reports an active certificate that the given
// additional apps do not hold, so they cannot authenticate with it. err, when
// non-nil, is the last error adding it to them.
func setAdditionalAppsNotRotated(obj certIdentity, apps []ezcav1.AdditionalAppSpec, err error) {
	msg := fmt.Sprintf("Additional app registrations %s do not hold the active certificate and cannot authenticate with it; add the certificate to them or remove them from spec.additionalApps",
		strings.Join(additionalAppIDs(apps), ", "))
	if err != nil {
		msg += ". Last error adding it: " + conditionError(err)
	}
	setDegraded(obj, reasonAdditionalAppRotationFailed, msg)
}

// unrotatedAdditionalApps returns the additional apps a rotation had to leave
// without the active certificate (see promoteIfReady) that still cannot
// authenticate with it. It only looks while the identity reports them, so a
// healthy identity spends no token requests here; an app an administrator has
// since given the certificate (or removed from spec.additionalApps) no longer
// counts.
func unrotatedAdditionalApps(ctx context.Context, d reconcilerDeps, obj certIdentity, cert *x509.Certificate, key *rsa.PrivateKey) []ezcav1.AdditionalAppSpec {
	cond := meta.FindStatusCondition(obj.StatusBase().Conditions, typeDegradedCertIdentity)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != reasonAdditionalAppRotationFailed {
		return nil
	}
	spec := obj.SpecBase()
	var apps []ezcav1.AdditionalAppSpec
	for _, app := range missingAdditionalApps(obj, pki.Thumbprint(cert)) {
		if !authenticatesAs(ctx, d, spec, app.AppID, cert, key) {
			apps = append(apps, app)
		}
	}
	return apps
}

// unrotatedAppsRequeue is when to next check an identity reporting additional
// apps without its certificate: before renewal is due, and at least every
// unrotatedAppsRecheck so the condition clears once they are fixed.
func unrotatedAppsRequeue(cert *x509.Certificate, threshold int32, now time.Time) time.Duration {
	return min(requeueForRenewal(cert, threshold, now), unrotatedAppsRecheck)
}

func additionalAppIDs(apps []ezcav1.AdditionalAppSpec) []string {
	appIDs := make([]string, 0, len(apps))
	for _, app := range apps {
		appIDs = append(appIDs, app.AppID)
	}
	return appIDs
}

// conditionError renders err on a single line for a condition message, since
// errors.Join separates the errors it joins with newlines.
func conditionError(err error) string {
	return strings.ReplaceAll(err.Error(), "\n", "; ")
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

// discardPendingCert removes the staged certificate from the Secret and clears
// the pending status fields, so the next reconcile falls back to the active
// certificate. Used when the staged certificate can never be promoted (its data
// is unusable, or it is outside its validity window).
func discardPendingCert(ctx context.Context, d reconcilerDeps, obj certIdentity, secret *corev1.Secret) error {
	delete(secret.Data, tlsCertPendingKey)
	delete(secret.Data, tlsKeyPendingKey)
	clearPending(obj.StatusBase())
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
// certificate that became current at since (added to the app registration, or
// issued at NotBefore), given the propagation grace.
func propagationRequeueAfter(now time.Time, since *metav1.Time, grace time.Duration) time.Duration {
	if since == nil {
		return propagationRequeue
	}
	if remaining := grace - now.Sub(since.Time); remaining > 0 {
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

	// A freshly registered active certificate may not yet be usable on every
	// AAD token replica; give it the propagation grace before authenticating to
	// Key Vault with it. The window is measured from when the certificate was
	// added to the app registration (falling back to its NotBefore), because
	// NotBefore can predate the registration by hours (EZCA backdates it) or
	// days (a certificate registered only after issuance). A certificate
	// promoted only after it already authenticated (and waited out the grace
	// since being staged) is not charged the grace a second time — it syncs
	// right away.
	timing := d.propagation()
	since := kvPropagationSince(obj)
	if since != nil && now.Sub(since.Time) < timing.Grace {
		requeueAtMost(result, propagationRequeueAfter(now, since, timing.Grace))
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
		(since == nil || now.Sub(since.Time) <= timing.Timeout) {
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

// kvPropagationSince returns the moment Entra propagation of the active
// certificate is measured from: when the controller added it to the app
// registration, falling back to the certificate's own NotBefore for
// certificates registered out of band (or recorded before addedAt existed).
func kvPropagationSince(obj certIdentity) *metav1.Time {
	status := obj.StatusBase()
	since := status.NotBefore
	for _, kc := range status.ManagedKeyCredentials {
		if kc.Thumbprint == status.Thumbprint && kc.AddedAt != nil && (since == nil || kc.AddedAt.After(since.Time)) {
			since = kc.AddedAt
		}
	}
	return since
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

// identityPropsForApp extends identityProps with the app registration an
// operation targeted, for operations against an additional app.
func identityPropsForApp(obj certIdentity, appID string) map[string]string {
	props := identityProps(obj)
	props["targetAppID"] = appID
	return props
}

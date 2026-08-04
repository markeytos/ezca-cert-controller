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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ezca "github.com/markeytos/ezca-go"

	ezcav1 "github.com/markeytos/ezca-cert-controller/api/v1"
	"github.com/markeytos/ezca-cert-controller/internal/entra"
	"github.com/markeytos/ezca-cert-controller/internal/pki"
	"github.com/markeytos/ezca-cert-controller/internal/telemetry"
)

// Definitions to manage status conditions
const (
	// typeAvailableClusterCertIdentity indicates the certificate is present and valid
	typeAvailableClusterCertIdentity = "Available"
	// typeProgressingClusterCertIdentity indicates the certificate is being renewed
	typeProgressingClusterCertIdentity = "Progressing"
	// typeDegradedClusterCertIdentity indicates reconciliation encountered an error
	typeDegradedClusterCertIdentity = "Degraded"

	clusterCertIdentityFinalizer = "ezca.keytos.io/finalizer"

	tlsCertKey = "tls.crt"
	tlsKeyKey  = "tls.key"

	// maxRequeueAfter bounds how long the controller waits before re-checking a
	// certificate, so managed-credential cleanup also runs at least this often.
	maxRequeueAfter = 24 * time.Hour
)

// ezcaRenewer renews a certificate through EZCA. Satisfied by
// *ezca.CertificateClient; overridable in tests.
type ezcaRenewer interface {
	RenewCertificateV3(ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey, csr []byte, validityDays int) ([]*x509.Certificate, error)
}

// entraManager manages certificate credentials on an app registration.
// Satisfied by *entra.Client; overridable in tests.
type entraManager interface {
	AddKey(ctx context.Context, objectID string, newCertDER []byte) (string, error)
	RemoveKey(ctx context.Context, objectID, keyID string) error
}

// ClusterCertIdentityReconciler reconciles a ClusterCertIdentity object
type ClusterCertIdentityReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// DefaultNamespace is the namespace used for the certificate Secret when the
	// spec does not set one (the namespace the controller runs in).
	DefaultNamespace string

	// Now, NewEZCAClient, and NewEntraClient are injection points for tests.
	// When nil, real implementations are used.
	Now            func() time.Time
	NewEZCAClient  func(ezcaURL string) (ezcaRenewer, error)
	NewEntraClient func(tenantID, appID string, cl entra.Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (entraManager, error)
}

// +kubebuilder:rbac:groups=ezca.keytos.io,resources=clustercertidentities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ezca.keytos.io,resources=clustercertidentities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ezca.keytos.io,resources=clustercertidentities/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch

// Reconcile renews the identity's certificate before it expires and rotates it
// onto the configured Entra ID app registration.
func (r *ClusterCertIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var cci ezcav1.ClusterCertIdentity
	if err := r.Get(ctx, req.NamespacedName, &cci); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("ClusterCertIdentity resource not found, must have been deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get ClusterCertIdentity")
		return ctrl.Result{}, err
	}

	// Handle deletion: release the finalizer, leaving any managed app
	// certificates in place (they expire on their own).
	if !cci.DeletionTimestamp.IsZero() {
		if controllerutil.RemoveFinalizer(&cci, clusterCertIdentityFinalizer) {
			if err := r.Update(ctx, &cci); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if controllerutil.AddFinalizer(&cci, clusterCertIdentityFinalizer) {
		if err := r.Update(ctx, &cci); err != nil {
			return ctrl.Result{}, err
		}
	}

	tel := telemetry.New(cci.Spec.AppInsightsConnString)
	defer tel.Flush(10 * time.Second)

	result, reconcileErr := r.reconcile(ctx, &cci, tel)

	if err := r.Status().Update(ctx, &cci); err != nil {
		log.Error(err, "Failed to update ClusterCertIdentity status")
		if reconcileErr == nil {
			reconcileErr = err
		}
	}
	return result, reconcileErr
}

// reconcile performs the core renewal/rotation logic and updates status
// conditions on cci in place (persisted by the caller).
func (r *ClusterCertIdentityReconciler) reconcile(ctx context.Context, cci *ezcav1.ClusterCertIdentity, tel *telemetry.Telemetry) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	secretNS := cci.Spec.CertSecretNamespace
	if secretNS == "" {
		secretNS = r.DefaultNamespace
	}
	if secretNS == "" {
		r.setDegraded(cci, "NamespaceUnresolved", "Could not resolve the certificate Secret namespace; set spec.certSecretNamespace or POD_NAMESPACE")
		return ctrl.Result{}, nil
	}

	var secret corev1.Secret
	secretName := types.NamespacedName{Namespace: secretNS, Name: cci.Spec.CertSecretName}
	if err := r.Get(ctx, secretName, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			r.setDegraded(cci, "CertificateNotBootstrapped",
				fmt.Sprintf("Certificate Secret %s not found; an administrator must bootstrap it", secretName))
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
		return ctrl.Result{}, err
	}

	chain, key, err := parseSecret(&secret)
	if err != nil {
		r.setDegraded(cci, "InvalidCertificate", fmt.Sprintf("Certificate Secret %s is invalid: %v", secretName, err))
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	current := chain[0]
	now := r.now()
	setObservedCert(cci, current)

	remaining := pki.LifetimeFractionRemaining(current, now)
	if remaining > float64(cci.Spec.RenewalThreshold) {
		// Not due for renewal. Still clean up any managed credentials that have
		// expired since the last renewal.
		if appConfigured(cci) && hasExpiredManagedCredentials(cci, now) {
			if err := r.manageApp(ctx, cci, current, key, nil, tel, now); err != nil {
				log.Error(err, "Failed to clean up expired app credentials")
			}
		}
		r.setAvailable(cci, "CertificateValid", "Certificate is valid and not yet due for renewal")
		return ctrl.Result{RequeueAfter: r.requeueForRenewal(current, cci.Spec.RenewalThreshold, now)}, nil
	}

	log.Info("Renewing certificate", "thumbprint", pki.Thumbprint(current), "remainingPercent", int(remaining))
	meta.SetStatusCondition(&cci.Status.Conditions, metav1.Condition{
		Type:    typeProgressingClusterCertIdentity,
		Status:  metav1.ConditionTrue,
		Reason:  "Renewing",
		Message: "Certificate crossed the renewal threshold and is being renewed",
	})

	newChain, newKey, err := r.renew(ctx, cci, current, key, tel)
	if err != nil {
		r.setDegraded(cci, "RenewalFailed", fmt.Sprintf("Failed to renew certificate: %v", err))
		return ctrl.Result{}, err
	}
	newLeaf := newChain[0]

	// Add the renewed certificate to the app registration BEFORE promoting it
	// into the Secret, so the Secret always holds a certificate the app already
	// trusts. Cleanup of expired credentials runs in the same call.
	if appConfigured(cci) {
		if err := r.manageApp(ctx, cci, current, key, newLeaf, tel, now); err != nil {
			r.setDegraded(cci, "AppRotationFailed", fmt.Sprintf("Failed to add renewed certificate to app registration: %v", err))
			return ctrl.Result{}, err
		}
	}

	time.Sleep(time.Minute * 2)

	if err := r.writeSecret(ctx, &secret, newChain, newKey); err != nil {
		tel.TrackError(err, "Failed to write renewed certificate Secret", identityProps(cci))
		r.setDegraded(cci, "SecretWriteFailed", fmt.Sprintf("Failed to write renewed certificate to Secret: %v", err))
		return ctrl.Result{}, err
	}

	setObservedCert(cci, newLeaf)
	cci.Status.LastRenewalTime = &metav1.Time{Time: now}
	tel.TrackEvent("CertificateRenewed", identityProps(cci))
	log.Info("Renewed certificate", "thumbprint", pki.Thumbprint(newLeaf), "notAfter", newLeaf.NotAfter)

	r.setAvailable(cci, "CertificateRenewed", "Certificate renewed successfully")
	return ctrl.Result{RequeueAfter: r.requeueForRenewal(newLeaf, cci.Spec.RenewalThreshold, now)}, nil
}

// renew builds a renewal CSR (with a fresh key) and renews the certificate
// through EZCA using the current certificate for authentication.
func (r *ClusterCertIdentityReconciler) renew(ctx context.Context, cci *ezcav1.ClusterCertIdentity, current *x509.Certificate, key *rsa.PrivateKey, tel *telemetry.Telemetry) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	csrDER, newKey, err := pki.BuildRenewalCSR(current)
	if err != nil {
		return nil, nil, err
	}
	renewer, err := r.newEZCAClient(*cci.Spec.EZCAURL)
	if err != nil {
		return nil, nil, err
	}
	newChain, err := renewer.RenewCertificateV3(ctx, current, key, csrDER, pki.ValidityInDays(current))
	if err != nil {
		tel.TrackError(err, "Failed to renew certificate via EZCA", identityProps(cci))
		return nil, nil, err
	}
	return newChain, newKey, nil
}

// manageApp authenticates to Microsoft Graph as the app (using authCert), adds
// newLeaf when non-nil, and removes any managed credentials that have expired.
// It targets the app registration by its directory object ID directly, so no
// directory-read permission is needed: addKey/removeKey succeed with a
// proof-of-possession signed by the app's current certificate.
func (r *ClusterCertIdentityReconciler) manageApp(ctx context.Context, cci *ezcav1.ClusterCertIdentity, authCert *x509.Certificate, authKey *rsa.PrivateKey, newLeaf *x509.Certificate, tel *telemetry.Telemetry, now time.Time) error {
	cl, err := r.newEntraClient(*cci.Spec.TenantID, *cci.Spec.AppID, cloudFor(cci.Spec.Cloud), authCert, authKey)
	if err != nil {
		return err
	}
	objectID := *cci.Spec.AppObjectID

	if newLeaf != nil {
		keyID, err := cl.AddKey(ctx, objectID, newLeaf.Raw)
		if err != nil {
			tel.TrackError(err, "Failed to add renewed certificate to app registration", identityProps(cci))
			return err
		}
		cci.Status.ManagedKeyCredentials = append(cci.Status.ManagedKeyCredentials, ezcav1.ManagedKeyCredential{
			Thumbprint: pki.Thumbprint(newLeaf),
			KeyID:      keyID,
			NotAfter:   metav1.Time{Time: newLeaf.NotAfter},
		})
		tel.TrackEvent("CertificateAddedToApp", identityProps(cci))
	}

	var remaining []ezcav1.ManagedKeyCredential
	for _, mc := range cci.Status.ManagedKeyCredentials {
		if mc.NotAfter.After(now) {
			remaining = append(remaining, mc) // still valid
			continue
		}
		if err := cl.RemoveKey(ctx, objectID, mc.KeyID); err != nil {
			tel.TrackError(err, "Failed to remove expired certificate from app registration", identityProps(cci))
			remaining = append(remaining, mc) // keep to retry next time
			continue
		}
		tel.TrackEvent("ExpiredCertificateRemoved", identityProps(cci))
		// Removed from the app: drop from status.
	}
	cci.Status.ManagedKeyCredentials = remaining
	return nil
}

// writeSecret rewrites the TLS Secret with the renewed chain and key.
func (r *ClusterCertIdentityReconciler) writeSecret(ctx context.Context, secret *corev1.Secret, chain []*x509.Certificate, key *rsa.PrivateKey) error {
	keyPEM, err := pki.EncodeRSAPrivateKeyPEM(key)
	if err != nil {
		return err
	}
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data[tlsCertKey] = pki.EncodeCertChainPEM(chain)
	secret.Data[tlsKeyKey] = keyPEM
	return r.Update(ctx, secret)
}

func (r *ClusterCertIdentityReconciler) requeueForRenewal(cert *x509.Certificate, thresholdPct int32, now time.Time) time.Duration {
	d := pki.NextRenewalTime(cert, thresholdPct).Sub(now)
	if d <= 0 {
		d = time.Minute
	}
	if d > maxRequeueAfter {
		d = maxRequeueAfter
	}
	return d
}

func (r *ClusterCertIdentityReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *ClusterCertIdentityReconciler) newEZCAClient(ezcaURL string) (ezcaRenewer, error) {
	if r.NewEZCAClient != nil {
		return r.NewEZCAClient(ezcaURL)
	}
	return ezca.NewCertificateClient(ezcaURL)
}

func (r *ClusterCertIdentityReconciler) newEntraClient(tenantID, appID string, cl entra.Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (entraManager, error) {
	if r.NewEntraClient != nil {
		return r.NewEntraClient(tenantID, appID, cl, cert, key)
	}
	return entra.NewClient(tenantID, appID, cl, cert, key)
}

func (r *ClusterCertIdentityReconciler) setAvailable(cci *ezcav1.ClusterCertIdentity, reason, message string) {
	meta.SetStatusCondition(&cci.Status.Conditions, metav1.Condition{
		Type:    typeAvailableClusterCertIdentity,
		Status:  metav1.ConditionTrue,
		Reason:  reason,
		Message: message,
	})
	meta.RemoveStatusCondition(&cci.Status.Conditions, typeProgressingClusterCertIdentity)
	meta.RemoveStatusCondition(&cci.Status.Conditions, typeDegradedClusterCertIdentity)
}

func (r *ClusterCertIdentityReconciler) setDegraded(cci *ezcav1.ClusterCertIdentity, reason, message string) {
	meta.SetStatusCondition(&cci.Status.Conditions, metav1.Condition{
		Type:    typeDegradedClusterCertIdentity,
		Status:  metav1.ConditionTrue,
		Reason:  reason,
		Message: message,
	})
	meta.SetStatusCondition(&cci.Status.Conditions, metav1.Condition{
		Type:    typeAvailableClusterCertIdentity,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterCertIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ezcav1.ClusterCertIdentity{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.secretToRequests)).
		Named("clustercertidentity").
		Complete(r)
}

// secretToRequests maps a changed Secret to the ClusterCertIdentities that
// reference it, so external edits to the bootstrapped certificate trigger a
// reconcile.
func (r *ClusterCertIdentityReconciler) secretToRequests(ctx context.Context, obj client.Object) []reconcile.Request {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	var list ezcav1.ClusterCertIdentityList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		cci := &list.Items[i]
		ns := cci.Spec.CertSecretNamespace
		if ns == "" {
			ns = r.DefaultNamespace
		}
		if ns == secret.Namespace && cci.Spec.CertSecretName == secret.Name {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		}
	}
	return reqs
}

func parseSecret(secret *corev1.Secret) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	certData := secret.Data[tlsCertKey]
	if len(certData) == 0 {
		return nil, nil, fmt.Errorf("missing %q", tlsCertKey)
	}
	keyData := secret.Data[tlsKeyKey]
	if len(keyData) == 0 {
		return nil, nil, fmt.Errorf("missing %q", tlsKeyKey)
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

func setObservedCert(cci *ezcav1.ClusterCertIdentity, cert *x509.Certificate) {
	cci.Status.NotBefore = &metav1.Time{Time: cert.NotBefore}
	cci.Status.NotAfter = &metav1.Time{Time: cert.NotAfter}
	cci.Status.Thumbprint = pki.Thumbprint(cert)
}

func appConfigured(cci *ezcav1.ClusterCertIdentity) bool {
	return cci.Spec.TenantID != nil && cci.Spec.AppID != nil && cci.Spec.AppObjectID != nil
}

func hasExpiredManagedCredentials(cci *ezcav1.ClusterCertIdentity, now time.Time) bool {
	for _, mc := range cci.Status.ManagedKeyCredentials {
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

func identityProps(cci *ezcav1.ClusterCertIdentity) map[string]string {
	props := map[string]string{
		"identity":   cci.Name,
		"thumbprint": cci.Status.Thumbprint,
	}
	if cci.Spec.AppID != nil {
		props["appID"] = *cci.Spec.AppID
	}
	return props
}

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
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	ezca "github.com/markeytos/ezca-go"

	ezcav1 "github.com/markeytos/ezca-cert-controller/api/v1"
	"github.com/markeytos/ezca-cert-controller/internal/entra"
	"github.com/markeytos/ezca-cert-controller/internal/pki"
	"github.com/markeytos/ezca-cert-controller/internal/telemetry"
)

// ezcaIssuer issues a brand-new certificate (new subject/SANs) through EZCA,
// authenticated as an Entra app. Satisfied by *ezca.SSLAuthorityClient;
// overridable in tests.
type ezcaIssuer interface {
	Sign(ctx context.Context, csr []byte, opts *ezca.SignOptions) ([]*x509.Certificate, error)
}

// ManagedCredentialReconciler reconciles a ManagedCredential object
type ManagedCredentialReconciler struct {
	ReconcilerBase

	// DefaultNamespace is the namespace used to resolve the referenced
	// identity's Secret when its spec does not set one (the namespace the
	// controller runs in).
	DefaultNamespace string

	// Injection points for issuing brand-new certificates (beyond the shared
	// factories in ReconcilerBase). When nil, real implementations are used.
	NewEZCAIssuer      func(ctx context.Context, ezcaURL string, cred azcore.TokenCredential, caID, templateID uuid.UUID) (ezcaIssuer, error)
	NewTokenCredential func(tenantID, appID string, cl entra.Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (azcore.TokenCredential, error)
}

// +kubebuilder:rbac:groups=ezca.keytos.io,resources=clustercertidentities,verbs=get;list;watch
// +kubebuilder:rbac:groups=ezca.keytos.io,resources=clustercertidentities/status,verbs=get
// +kubebuilder:rbac:groups=ezca.keytos.io,resources=certidentities,verbs=get;list;watch
// +kubebuilder:rbac:groups=ezca.keytos.io,resources=certidentities/status,verbs=get
// +kubebuilder:rbac:groups=ezca.keytos.io,resources=managedcredentials,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ezca.keytos.io,resources=managedcredentials/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ezca.keytos.io,resources=managedcredentials/finalizers,verbs=update

// Reconcile bootstraps the credential's certificate when its Secret is empty,
// keeps the certificate in sync with the desired subject and domains, and
// otherwise renews and rotates it exactly as a ClusterCertIdentity does.
func (r *ManagedCredentialReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var mc ezcav1.ManagedCredential
	if err := r.Get(ctx, req.NamespacedName, &mc); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("ManagedCredential resource not found, must have been deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get ManagedCredential")
		return ctrl.Result{}, err
	}

	// Handle deletion: release the finalizer, leaving any managed app
	// certificates in place (they expire on their own).
	if !mc.DeletionTimestamp.IsZero() {
		if controllerutil.RemoveFinalizer(&mc, ezcaGroupFinalizer) {
			if err := r.Update(ctx, &mc); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if controllerutil.AddFinalizer(&mc, ezcaGroupFinalizer) {
		if err := r.Update(ctx, &mc); err != nil {
			return ctrl.Result{}, err
		}
	}

	tel := telemetry.New(mc.Spec.AppInsightsConnString)
	defer tel.Flush(10 * time.Second)

	result, reconcileErr := r.reconcile(ctx, &mc, tel)
	// todo: fail here if reconcileErr is not nil?

	if err := r.Status().Update(ctx, &mc); err != nil {
		log.Error(err, "Failed to update ManagedCredential status")
		if reconcileErr == nil {
			reconcileErr = err
		}
	}
	return result, reconcileErr
}

// reconcile bootstraps or re-issues the certificate as needed, then runs the
// shared renewal/rotation/Key Vault state machine.
func (r *ManagedCredentialReconciler) reconcile(ctx context.Context, mc *ezcav1.ManagedCredential, tel *telemetry.Telemetry) (ctrl.Result, error) {
	now := r.now()

	// The desired subject and SANs; used for both issuance and drift detection.
	req, err := certRequestFromSpec(mc)
	if err != nil {
		setDegraded(mc, "InvalidSANs", fmt.Sprintf("Invalid subject alternative names: %v", err))
		return ctrl.Result{}, nil
	}

	var secret corev1.Secret
	secretName := types.NamespacedName{Namespace: mc.Namespace, Name: mc.Spec.CertSecretName}
	if err := r.Get(ctx, secretName, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			if !canSelfBootstrap(mc) {
				return r.requireBootstrap(mc, secretName), nil
			}
			// No Secret yet: bootstrap by issuing the first certificate.
			return r.issueAndStore(ctx, mc, nil, nil, nil, req, now, tel, "Bootstrapped")
		}
		return ctrl.Result{}, err
	}

	// Tolerate an empty Secret (present but without certificate material) as a
	// bootstrap trigger, unless a rotation is already staged in it.
	if isEmptyTLSSecret(&secret) && !hasPendingCert(&secret) {
		if !canSelfBootstrap(mc) {
			return r.requireBootstrap(mc, secretName), nil
		}
		return r.issueAndStore(ctx, mc, &secret, nil, nil, req, now, tel, "Bootstrapped")
	}

	chain, key, err := parseSecret(&secret)
	if err != nil {
		setDegraded(mc, "InvalidCertificate", fmt.Sprintf("Certificate Secret %s is invalid: %v", secretName, err))
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	setObservedCert(mc, chain[0])

	// Re-issue when the certificate has drifted from the desired subject or SANs,
	// unless a rotation is mid-flight (the pending cert is handled by the shared
	// state machine). Re-issuance needs an issuance credential, so a credential
	// with no spec.identityRef only renews the externally provisioned certificate
	// and ignores drift.
	if canSelfBootstrap(mc) && !hasPendingCert(&secret) && !pki.LeafMatchesSpec(chain[0], req) {
		logf.FromContext(ctx).Info("Certificate no longer matches spec; re-issuing",
			"subjectName", mc.Spec.SubjectName)
		return r.issueAndStore(ctx, mc, &secret, chain[0], key, req, now, tel, "Reissued")
	}

	result, coreErr := reconcileCertState(ctx, r, mc, &secret, chain, key, now, tel)

	if mc.Spec.KeyVault != nil {
		syncKeyVaultBestEffort(ctx, r, mc, &secret, now, tel, &result, coreErr)
	}
	return result, coreErr
}

// issueAndStore issues a fresh certificate for the desired subject and domains
// and writes it into the credential's Secret. secret is nil when it does not yet
// exist (bootstrap); currentLeaf/currentKey carry the existing certificate when
// re-issuing, so the credential can authenticate as its own app if that cert is
// already registered in Entra.
func (r *ManagedCredentialReconciler) issueAndStore(ctx context.Context, mc *ezcav1.ManagedCredential, secret *corev1.Secret, currentLeaf *x509.Certificate, currentKey *rsa.PrivateKey, req pki.CertRequest, now time.Time, tel *telemetry.Telemetry, successReason string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	caID, err := uuid.Parse(mc.Spec.CAID)
	if err != nil {
		setDegraded(mc, "InvalidCAID", fmt.Sprintf("spec.caID is not a valid UUID: %v", err))
		return ctrl.Result{}, nil
	}
	templateID, err := uuid.Parse(mc.Spec.TemplateID)
	if err != nil {
		setDegraded(mc, "InvalidTemplateID", fmt.Sprintf("spec.templateID is not a valid UUID: %v", err))
		return ctrl.Result{}, nil
	}

	signOpts, err := signOptions(mc, req)
	if err != nil {
		setDegraded(mc, "InvalidSignOptions", fmt.Sprintf("Invalid certificate options: %v", err))
		return ctrl.Result{}, nil
	}

	cred, err := r.issuanceCredential(ctx, mc, currentLeaf, currentKey)
	if err != nil {
		tel.TrackError(err, "Failed to obtain issuance credential", identityProps(mc))
		setDegraded(mc, "IssuanceCredentialUnavailable", fmt.Sprintf("Could not obtain a credential to issue the certificate: %v", err))
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	issuer, err := r.newEZCAIssuer(ctx, *mc.Spec.EZCAURL, cred, caID, templateID)
	if err != nil {
		setDegraded(mc, "IssuerUnavailable", fmt.Sprintf("Could not create EZCA issuer: %v", err))
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	csrDER, newKey, err := pki.BuildIssuanceCSR(req)
	if err != nil {
		setDegraded(mc, "CSRFailed", fmt.Sprintf("Could not build issuance CSR: %v", err))
		return ctrl.Result{}, err
	}

	chain, err := issuer.Sign(ctx, csrDER, signOpts)
	if err != nil {
		tel.TrackError(err, "Failed to issue certificate via EZCA", identityProps(mc))
		setDegraded(mc, "IssuanceFailed", fmt.Sprintf("Failed to issue certificate: %v", err))
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	newLeaf := chain[0]
	tel.TrackEvent("CertificateIssued", identityProps(mc))
	log.Info("Issued certificate", "thumbprint", pki.Thumbprint(newLeaf), "notAfter", newLeaf.NotAfter, "reason", successReason)

	// Guard against a re-issue loop: if the certificate EZCA returned does not
	// match the desired subject/SANs, surface Degraded (and do not store or
	// register it) instead of re-issuing on the next pass.
	if !pki.LeafMatchesSpec(newLeaf, req) {
		setDegraded(mc, "IssuedCertificateMismatch",
			"Issued certificate does not match spec.subjectName and SANs; check the CA and template configuration")
		return ctrl.Result{RequeueAfter: maxRequeueAfter}, nil
	}

	return r.installIssuedCert(ctx, mc, secret, currentLeaf, currentKey, chain, newKey, now, tel, successReason)
}

// installIssuedCert writes a freshly issued certificate into the Secret and,
// when the credential has its own Entra app, registers the certificate on that
// app so it can authenticate as itself. Mirroring renewal, when a certificate is
// already being served the new one is staged as pending and promoted only once
// Entra can authenticate with it; on first issuance (nothing to keep serving) it
// is written active immediately.
func (r *ManagedCredentialReconciler) installIssuedCert(ctx context.Context, mc *ezcav1.ManagedCredential, secret *corev1.Secret, currentLeaf *x509.Certificate, currentKey *rsa.PrivateKey, chain []*x509.Certificate, newKey *rsa.PrivateKey, now time.Time, tel *telemetry.Telemetry, successReason string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	newLeaf := chain[0]

	// Certificate-only credential: no app to register with; serve immediately.
	if !appConfigured(mc) {
		if err := r.storeIssuedCert(ctx, mc, secret, chain, newKey); err != nil {
			tel.TrackError(err, "Failed to store issued certificate", identityProps(mc))
			setDegraded(mc, "SecretWriteFailed", fmt.Sprintf("Failed to write issued certificate to Secret: %v", err))
			return ctrl.Result{}, err
		}
		return r.finishIssuance(mc, newLeaf, now, successReason), nil
	}

	// App credential: add the issued certificate to the app registration,
	// authenticated by a certificate the app already trusts — the current
	// certificate once it is registered, otherwise the referenced master
	// identity's certificate on first issuance.
	authCert, authKey, err := r.appAuthCert(ctx, mc, currentLeaf, currentKey)
	if err != nil {
		tel.TrackError(err, "Failed to obtain a credential to register the certificate on the app", identityProps(mc))
		setDegraded(mc, "AppAuthUnavailable", fmt.Sprintf("Could not obtain a credential to register the certificate on the app registration: %v", err))
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	if err := manageApp(ctx, r, mc, authCert, authKey, newLeaf, tel, now); err != nil {
		setDegraded(mc, "AppRotationFailed", fmt.Sprintf("Failed to add issued certificate to app registration: %v", err))
		return ctrl.Result{}, err
	}

	// If a certificate is already being served, keep serving it and stage the new
	// one as pending; the shared promotion flow swaps it in once Entra can
	// authenticate with it.
	if currentLeaf != nil {
		if err := writePendingSecret(ctx, r, secret, chain, newKey); err != nil {
			tel.TrackError(err, "Failed to stage issued certificate", identityProps(mc))
			setDegraded(mc, "SecretWriteFailed", fmt.Sprintf("Failed to stage issued certificate: %v", err))
			return ctrl.Result{}, err
		}
		mc.Status.PendingThumbprint = pki.Thumbprint(newLeaf)
		mc.Status.PendingSince = &metav1.Time{Time: now}
		meta.SetStatusCondition(&mc.Status.Conditions, metav1.Condition{
			Type:    typeProgressingCertIdentity,
			Status:  metav1.ConditionTrue,
			Reason:  reasonPendingPropagation,
			Message: "Issued certificate added to the app registration; waiting for Entra ID propagation",
		})
		log.Info("Staged issued certificate, waiting for Entra ID propagation", "thumbprint", pki.Thumbprint(newLeaf))
		return ctrl.Result{RequeueAfter: propagationRequeue}, nil
	}

	// First issuance: nothing to keep serving, so write the certificate active. It
	// is registered on the app; Key Vault sync and app authentication wait out
	// propagation.
	if err := r.storeIssuedCert(ctx, mc, secret, chain, newKey); err != nil {
		tel.TrackError(err, "Failed to store issued certificate", identityProps(mc))
		setDegraded(mc, "SecretWriteFailed", fmt.Sprintf("Failed to write issued certificate to Secret: %v", err))
		return ctrl.Result{}, err
	}
	return r.finishIssuance(mc, newLeaf, now, successReason), nil
}

// finishIssuance records the freshly issued certificate as active and returns
// the next requeue.
func (r *ManagedCredentialReconciler) finishIssuance(mc *ezcav1.ManagedCredential, newLeaf *x509.Certificate, now time.Time, successReason string) ctrl.Result {
	setObservedCert(mc, newLeaf)
	mc.Status.LastRenewalTime = &metav1.Time{Time: now}
	mc.Status.PendingThumbprint = ""
	mc.Status.PendingSince = nil
	setAvailable(mc, successReason, "Certificate issued successfully")
	if mc.Spec.KeyVault != nil {
		// Hand off to the steady-state path soon so the new certificate syncs to
		// Key Vault once it is usable.
		return ctrl.Result{RequeueAfter: propagationRequeue}
	}
	return ctrl.Result{RequeueAfter: requeueForRenewal(newLeaf, mc.Spec.RenewalThreshold, now)}
}

// appAuthCert returns the certificate and key used to authenticate addKey/
// removeKey against the credential's own app registration: the current
// certificate when it is already registered, otherwise the referenced master
// identity's certificate (which is trusted on the app registration to bootstrap
// the first certificate).
func (r *ManagedCredentialReconciler) appAuthCert(ctx context.Context, mc *ezcav1.ManagedCredential, currentLeaf *x509.Certificate, currentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	if currentLeaf != nil && currentKey != nil && leafRegisteredInEntra(mc, currentLeaf) {
		return currentLeaf, currentKey, nil
	}
	cert, key, _, err := r.identityRefCertKey(ctx, mc)
	return cert, key, err
}

// storeIssuedCert writes the issued chain and key into the credential's Secret,
// creating an owned Secret when one does not yet exist.
func (r *ManagedCredentialReconciler) storeIssuedCert(ctx context.Context, mc *ezcav1.ManagedCredential, secret *corev1.Secret, chain []*x509.Certificate, key *rsa.PrivateKey) error {
	if secret != nil {
		// Overwrite the active material and drop any stale staged certificate.
		delete(secret.Data, tlsCertPendingKey)
		delete(secret.Data, tlsKeyPendingKey)
		return writeActiveSecret(ctx, r, secret, chain, key)
	}

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      mc.Spec.CertSecretName,
			Namespace: mc.Namespace,
		},
		Type: corev1.SecretTypeTLS,
	}
	if err := setTLSData(newSecret, tlsCertKey, tlsKeyKey, chain, key); err != nil {
		return err
	}
	if err := controllerutil.SetControllerReference(mc, newSecret, r.Scheme); err != nil {
		return err
	}
	return r.Create(ctx, newSecret)
}

// issuanceCredential selects the Azure credential used to authenticate the
// issuance request: the credential's own app when it already has a certificate
// registered in Entra, otherwise the referenced bootstrap identity's app.
func (r *ManagedCredentialReconciler) issuanceCredential(ctx context.Context, mc *ezcav1.ManagedCredential, currentLeaf *x509.Certificate, currentKey *rsa.PrivateKey) (azcore.TokenCredential, error) {
	if appConfigured(mc) && currentLeaf != nil && currentKey != nil && leafRegisteredInEntra(mc, currentLeaf) {
		return r.newTokenCredential(*mc.Spec.TenantID, *mc.Spec.AppID, cloudFor(mc.Spec.Cloud), currentLeaf, currentKey)
	}
	return r.identityRefCredential(ctx, mc)
}

// identityRefCredential builds an Azure token credential (for EZCA issuance)
// that authenticates as the referenced master identity's app using its
// certificate.
func (r *ManagedCredentialReconciler) identityRefCredential(ctx context.Context, mc *ezcav1.ManagedCredential) (azcore.TokenCredential, error) {
	cert, key, base, err := r.identityRefCertKey(ctx, mc)
	if err != nil {
		return nil, err
	}
	return r.newTokenCredential(*base.TenantID, *base.AppID, cloudFor(base.Cloud), cert, key)
}

// canSelfBootstrap reports whether the credential can issue its own first
// certificate. Issuance must be authenticated as an Entra app, and before the
// credential has any certificate of its own the only identity available for
// that is the referenced one (spec.identityRef). Without it, the first
// certificate must be provisioned into the Secret externally; the controller
// then only renews and rotates it.
func canSelfBootstrap(mc *ezcav1.ManagedCredential) bool {
	return mc.Spec.IdentityRef != nil && mc.Spec.IdentityRef.Name != ""
}

// requireBootstrap marks the credential Degraded because it has no certificate
// and no identityRef to issue one, so an administrator must provision the
// Secret. It mirrors how ClusterCertIdentity/CertIdentity treat a missing
// certificate.
func (r *ManagedCredentialReconciler) requireBootstrap(mc *ezcav1.ManagedCredential, secretName types.NamespacedName) ctrl.Result {
	setDegraded(mc, "CertificateNotBootstrapped",
		fmt.Sprintf("Certificate Secret %s has no certificate and spec.identityRef is not set to bootstrap one; an administrator must provision it", secretName))
	return ctrl.Result{RequeueAfter: time.Minute}
}

// identityRefCertKey resolves the referenced identity's certificate, key, and
// shared spec from its bootstrapped Secret. A ClusterCertIdentity is
// cluster-scoped and its Secret may live in any namespace; a CertIdentity is
// namespaced, so it is only ever resolved in the credential's own namespace and
// its Secret is read there too — the credential can never reach across
// namespaces to it.
func (r *ManagedCredentialReconciler) identityRefCertKey(ctx context.Context, mc *ezcav1.ManagedCredential) (*x509.Certificate, *rsa.PrivateKey, *ezcav1.CertIdentitySpecBase, error) {
	if mc.Spec.IdentityRef == nil || mc.Spec.IdentityRef.Name == "" {
		return nil, nil, nil, errors.New("spec.identityRef is required to bootstrap the certificate")
	}
	ref := mc.Spec.IdentityRef

	var base *ezcav1.CertIdentitySpecBase
	var secretNS string
	switch ref.Kind {
	case ezcav1.IdentityKindClusterCertIdentity:
		var cci ezcav1.ClusterCertIdentity
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name}, &cci); err != nil {
			return nil, nil, nil, fmt.Errorf("getting referenced ClusterCertIdentity %q: %w", ref.Name, err)
		}
		base = &cci.Spec.CertIdentitySpecBase
		secretNS = cci.Spec.CertSecretNamespace
		if secretNS == "" {
			secretNS = r.DefaultNamespace
		}
	case ezcav1.IdentityKindCertIdentity:
		var ci ezcav1.CertIdentity
		if err := r.Get(ctx, types.NamespacedName{Namespace: mc.Namespace, Name: ref.Name}, &ci); err != nil {
			return nil, nil, nil, fmt.Errorf("getting referenced CertIdentity %q: %w", ref.Name, err)
		}
		base = &ci.Spec.CertIdentitySpecBase
		secretNS = mc.Namespace
	default:
		return nil, nil, nil, fmt.Errorf("unsupported identityRef kind %q", ref.Kind)
	}

	if base.TenantID == nil || base.AppID == nil || base.AppObjectID == nil {
		return nil, nil, nil, fmt.Errorf("referenced identity %q has no Entra app to authenticate as", ref.Name)
	}
	if secretNS == "" {
		return nil, nil, nil, errors.New("could not resolve the referenced identity's Secret namespace")
	}
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: secretNS, Name: base.CertSecretName}, &s); err != nil {
		return nil, nil, nil, fmt.Errorf("getting referenced identity's Secret: %w", err)
	}
	chain, key, err := parseSecret(&s)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing referenced identity's certificate: %w", err)
	}
	return chain[0], key, base, nil
}

// leafRegisteredInEntra reports whether the given certificate has been recorded
// as added to the credential's own Entra app registration.
func leafRegisteredInEntra(mc *ezcav1.ManagedCredential, leaf *x509.Certificate) bool {
	thumbprint := pki.Thumbprint(leaf)
	for _, kc := range mc.Status.ManagedKeyCredentials {
		if kc.Thumbprint == thumbprint {
			return true
		}
	}
	return false
}

// reissueOnRenewFailure implements renewFallback: when renewal fails (for
// example because EZCA no longer has the domains), fall back to issuing a fresh
// certificate. A credential with no spec.identityRef has no way to issue, so it
// declines the fallback and lets the renewal error surface.
func (r *ManagedCredentialReconciler) reissueOnRenewFailure(ctx context.Context, obj certIdentity, secret *corev1.Secret, current *x509.Certificate, key *rsa.PrivateKey, now time.Time, tel *telemetry.Telemetry, renewErr error) (bool, ctrl.Result, error) {
	mc, ok := obj.(*ezcav1.ManagedCredential)
	if !ok {
		return false, ctrl.Result{}, nil
	}
	if !canSelfBootstrap(mc) {
		return false, ctrl.Result{}, nil
	}
	req, err := certRequestFromSpec(mc)
	if err != nil {
		setDegraded(mc, "InvalidSANs", fmt.Sprintf("Invalid subject alternative names: %v", err))
		return true, ctrl.Result{}, nil
	}
	logf.FromContext(ctx).Info("Renewal failed; falling back to re-issuance", "error", renewErr)
	tel.TrackError(renewErr, "Renewal failed; falling back to re-issuance", identityProps(mc))
	result, err := r.issueAndStore(ctx, mc, secret, current, key, req, now, tel, "Reissued")
	return true, result, err
}

// certRequestFromSpec builds the desired subject, parsed SANs, and (when set)
// key usages from the spec. The key usages are carried in a form the pki drift
// check can compare against an issued certificate.
func certRequestFromSpec(mc *ezcav1.ManagedCredential) (pki.CertRequest, error) {
	ips, err := pki.ParseIPAddresses(mc.Spec.IPAddresses)
	if err != nil {
		return pki.CertRequest{}, err
	}
	uris, err := pki.ParseURIs(mc.Spec.URIs)
	if err != nil {
		return pki.CertRequest{}, err
	}

	var keyUsage x509.KeyUsage
	for _, ku := range mc.Spec.KeyUsages {
		bit, ok := keyUsageToX509[ku]
		if !ok {
			return pki.CertRequest{}, fmt.Errorf("unknown key usage %q", ku)
		}
		keyUsage |= bit
	}
	var ekuOIDs []string
	for _, eku := range mc.Spec.ExtendedKeyUsages {
		mapped, ok := extKeyUsageToEZCA[eku]
		if !ok {
			return pki.CertRequest{}, fmt.Errorf("unknown extended key usage %q", eku)
		}
		// ezca-go's ExtKeyUsage values are the dotted OID strings.
		ekuOIDs = append(ekuOIDs, string(mapped))
	}

	return pki.CertRequest{
		SubjectName:     mc.Spec.SubjectName,
		DNSNames:        mc.Spec.DNSNames,
		IPAddresses:     ips,
		URIs:            uris,
		EmailAddresses:  mc.Spec.EmailAddresses,
		KeyUsage:        keyUsage,
		ExtKeyUsageOIDs: ekuOIDs,
	}, nil
}

// keyUsageToX509 maps the CRD's key-usage enum to the x509 key-usage bits, so an
// issued certificate can be compared against the request for drift.
var keyUsageToX509 = map[ezcav1.KeyUsage]x509.KeyUsage{
	ezcav1.KeyUsageDigitalSignature: x509.KeyUsageDigitalSignature,
	ezcav1.KeyUsageKeyEncipherment:  x509.KeyUsageKeyEncipherment,
	ezcav1.KeyUsageDataEncipherment: x509.KeyUsageDataEncipherment,
	ezcav1.KeyUsageKeyAgreement:     x509.KeyUsageKeyAgreement,
	ezcav1.KeyUsageNonRepudiation:   x509.KeyUsageContentCommitment,
}

// keyUsageToEZCA and extKeyUsageToEZCA map the CRD's key-usage enums to the
// values ezca-go sends to EZCA.
var keyUsageToEZCA = map[ezcav1.KeyUsage]ezca.KeyUsage{
	ezcav1.KeyUsageDigitalSignature: ezca.KeyUsageDigitalSignature,
	ezcav1.KeyUsageKeyEncipherment:  ezca.KeyUsageKeyEncipherment,
	ezcav1.KeyUsageDataEncipherment: ezca.KeyUsageDataEncipherment,
	ezcav1.KeyUsageKeyAgreement:     ezca.KeyUsageKeyAgreement,
	ezcav1.KeyUsageNonRepudiation:   ezca.KeyUsageNonRepudiation,
}

var extKeyUsageToEZCA = map[ezcav1.ExtKeyUsage]ezca.ExtKeyUsage{
	ezcav1.ExtKeyUsageAny:                            ezca.ExtKeyUsageAny,
	ezcav1.ExtKeyUsageServerAuth:                     ezca.ExtKeyUsageServerAuth,
	ezcav1.ExtKeyUsageClientAuth:                     ezca.ExtKeyUsageClientAuth,
	ezcav1.ExtKeyUsageCodeSigning:                    ezca.ExtKeyUsageCodeSigning,
	ezcav1.ExtKeyUsageEmailProtection:                ezca.ExtKeyUsageEmailProtection,
	ezcav1.ExtKeyUsageIPSECEndSystem:                 ezca.ExtKeyUsageIPSECEndSystem,
	ezcav1.ExtKeyUsageIPSECTunnel:                    ezca.ExtKeyUsageIPSECTunnel,
	ezcav1.ExtKeyUsageIPSECUser:                      ezca.ExtKeyUsageIPSECUser,
	ezcav1.ExtKeyUsageTimeStamping:                   ezca.ExtKeyUsageTimeStamping,
	ezcav1.ExtKeyUsageOCSPSigning:                    ezca.ExtKeyUsageOCSPSigning,
	ezcav1.ExtKeyUsageMicrosoftServerGatedCrypto:     ezca.ExtKeyUsageMicrosoftServerGatedCrypto,
	ezcav1.ExtKeyUsageNetscapeServerGatedCrypto:      ezca.ExtKeyUsageNetscapeServerGatedCrypto,
	ezcav1.ExtKeyUsageMicrosoftCommercialCodeSigning: ezca.ExtKeyUsageMicrosoftCommercialCodeSigning,
	ezcav1.ExtKeyUsageMicrosoftKernelCodeSigning:     ezca.ExtKeyUsageMicrosoftKernelCodeSigning,
}

// signOptions builds the EZCA sign options from the spec: SANs, key usages,
// extended key usages, and requested validity. Empty key-usage lists let EZCA
// apply its defaults.
func signOptions(mc *ezcav1.ManagedCredential, req pki.CertRequest) (*ezca.SignOptions, error) {
	opts := &ezca.SignOptions{
		SubjectName:    mc.Spec.SubjectName,
		DNSNames:       req.DNSNames,
		IPAddresses:    req.IPAddresses,
		URIs:           req.URIs,
		EmailAddresses: req.EmailAddresses,
	}

	for _, ku := range mc.Spec.KeyUsages {
		mapped, ok := keyUsageToEZCA[ku]
		if !ok {
			return nil, fmt.Errorf("unknown key usage %q", ku)
		}
		opts.KeyUsages = append(opts.KeyUsages, mapped)
	}
	for _, eku := range mc.Spec.ExtendedKeyUsages {
		mapped, ok := extKeyUsageToEZCA[eku]
		if !ok {
			return nil, fmt.Errorf("unknown extended key usage %q", eku)
		}
		opts.ExtendedKeyUsages = append(opts.ExtendedKeyUsages, mapped)
	}
	if mc.Spec.ValidityInDays > 0 {
		opts.Duration = time.Duration(mc.Spec.ValidityInDays) * 24 * time.Hour
	}
	return opts, nil
}

func (r *ManagedCredentialReconciler) newEZCAIssuer(ctx context.Context, ezcaURL string, cred azcore.TokenCredential, caID, templateID uuid.UUID) (ezcaIssuer, error) {
	if r.NewEZCAIssuer != nil {
		return r.NewEZCAIssuer(ctx, ezcaURL, cred, caID, templateID)
	}
	c, err := ezca.NewClient(ezcaURL, cred)
	if err != nil {
		return nil, err
	}
	return ezca.NewSSLAuthorityClient(ctx, c, caID, templateID)
}

func (r *ManagedCredentialReconciler) newTokenCredential(tenantID, appID string, cl entra.Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (azcore.TokenCredential, error) {
	if r.NewTokenCredential != nil {
		return r.NewTokenCredential(tenantID, appID, cl, cert, key)
	}
	return entra.NewTokenCredential(tenantID, appID, cl, cert, key)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ManagedCredentialReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ezcav1.ManagedCredential{}).
		Owns(&corev1.Secret{}).
		Named("managedcredential").
		Complete(r)
}

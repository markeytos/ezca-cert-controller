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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	randv2 "math/rand/v2"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ezcav1 "github.com/markeytos/ezca-cert-controller/api/v1"
	"github.com/markeytos/ezca-cert-controller/internal/entra"
	"github.com/markeytos/ezca-cert-controller/internal/keyvault"
	"github.com/markeytos/ezca-cert-controller/internal/pki"
)

// Shared test fixtures used across the controller test suite.
const (
	testEZCAURL  = "https://portal.ezca.io"
	testUUID0    = "00000000-0000-0000-0000-000000000000"
	testUUID1    = "11111111-1111-1111-1111-111111111111"
	testObjectID = "obj-1"
	day          = 24 * time.Hour
	year         = 365 * day
	certName     = "mycert"
	vaultName    = "myvault"
)

type fakeEZCA struct {
	newChain []*x509.Certificate
	called   bool
	err      error
}

func (f *fakeEZCA) RenewCertificateV3(_ context.Context, _ *x509.Certificate, _ *rsa.PrivateKey, _ []byte, _ int) ([]*x509.Certificate, error) {
	f.called = true
	if f.err != nil {
		return nil, f.err
	}
	return f.newChain, nil
}

type fakeEntra struct {
	verifyErr   error
	verifyCalls int
	added       [][]byte
	addErr      error
	removed     []string
	removeErr   error
}

func (f *fakeEntra) VerifyCredential(_ context.Context) error {
	f.verifyCalls++
	return f.verifyErr
}

func (f *fakeEntra) AddKey(_ context.Context, _ string, der []byte) (string, error) {
	if len(der) <= 0 {
		return "", f.addErr
	}
	f.added = append(f.added, der)
	return "new-key-id", nil
}

func (f *fakeEntra) RemoveKey(_ context.Context, _, keyID string) error {
	if len(keyID) <= 0 {
		return f.removeErr
	}
	f.removed = append(f.removed, keyID)
	return nil
}

type fakeKeyVault struct {
	matches    bool
	matchErr   error
	matchCalls int
	imported   [][]byte
	importErr  error
}

func (f *fakeKeyVault) CertificateMatches(_ context.Context, _, _ string) (bool, error) {
	f.matchCalls++
	return f.matches, f.matchErr
}

func (f *fakeKeyVault) ImportCertificate(_ context.Context, _ string, bundle []byte) error {
	if len(bundle) <= 0 {
		return f.importErr
	}
	f.imported = append(f.imported, bundle)
	return nil
}

func genCert(cn string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err = x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}

var _ = Describe("ClusterCertIdentity Controller", func() {
	const namespace = "default"
	now := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	ctx := context.Background()

	var (
		reconciler  *ClusterCertIdentityReconciler
		ezcaClient  *fakeEZCA
		entraClient *fakeEntra
		kvClient    *fakeKeyVault
		clockNow    time.Time
	)

	newReconciler := func() *ClusterCertIdentityReconciler {
		return &ClusterCertIdentityReconciler{
			ReconcilerBase: ReconcilerBase{
				Client:        k8sClient,
				Scheme:        k8sClient.Scheme(),
				Now:           func() time.Time { return clockNow },
				NewEZCAClient: func(string) (ezcaRenewer, error) { return ezcaClient, nil },
				NewEntraClient: func(_, _ string, _ entra.Cloud, _ *x509.Certificate, _ *rsa.PrivateKey) (entraManager, error) {
					return entraClient, nil
				},
				NewKeyVaultClient: func(_, _, _ string, _ keyvault.Cloud, _ *x509.Certificate, _ *rsa.PrivateKey) (keyVaultManager, error) {
					return kvClient, nil
				},
			},
			DefaultNamespace: namespace,
		}
	}

	createSecret := func(name string, certPEM, keyPEM []byte) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{tlsCertKey: certPEM, tlsKeyKey: keyPEM},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	}

	createIdentity := func(name, secretName string, cloud ezcav1.CloudEnvironment, withApp bool) *ezcav1.ClusterCertIdentity {
		ezcaURL := testEZCAURL
		cci := &ezcav1.ClusterCertIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: ezcav1.ClusterCertIdentitySpec{
				CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
					EZCAURL:          &ezcaURL,
					CertSecretName:   secretName,
					Cloud:            cloud,
					RenewalThreshold: 20,
				},
				CertSecretNamespace: namespace,
				AllowedNamespaces:   []string{namespace},
			},
		}
		if withApp {
			tenant := testUUID0
			app := testUUID1
			objectID := testObjectID
			cci.Spec.TenantID = &tenant
			cci.Spec.AppID = &app
			cci.Spec.AppObjectID = &objectID
		}
		Expect(k8sClient.Create(ctx, cci)).To(Succeed())
		return cci
	}

	BeforeEach(func() {
		clockNow = now
		ezcaClient = &fakeEZCA{}
		entraClient = &fakeEntra{}
		kvClient = &fakeKeyVault{}
		reconciler = newReconciler()
	})

	It("does not renew a healthy certificate", func() {
		certPEM, keyPEM, _ := genCert("healthy.ezca.io", now.Add(-10*day), now.Add(90*day))
		createSecret("healthy-secret", certPEM, keyPEM)
		cci := createIdentity("healthy", "healthy-secret", ezcav1.CloudPublic, false)

		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))
		Expect(ezcaClient.called).To(BeFalse())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		Expect(cci.Status.NotAfter).NotTo(BeNil())
	})

	It("renews a certificate past the threshold", func() {
		certPEM, keyPEM, _ := genCert("renew.ezca.io", now.Add(-90*day), now.Add(10*day))
		createSecret("renew-secret", certPEM, keyPEM)
		cci := createIdentity("renew", "renew-secret", ezcav1.CloudPublic, false)

		_, _, parsedNew := genCert("renew.ezca.io", now, now.Add(100*day))
		ezcaClient.newChain = []*x509.Certificate{parsedNew}

		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(ezcaClient.called).To(BeTrue())

		// Secret was rewritten with the renewed certificate.
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "renew-secret", Namespace: namespace}, &secret)).To(Succeed())
		chain, err := pki.ParseCertChainPEM(secret.Data[tlsCertKey])
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].Equal(parsedNew)).To(BeTrue())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(cci.Status.LastRenewalTime).NotTo(BeNil())
		Expect(cci.Status.Thumbprint).To(Equal(pki.Thumbprint(parsedNew)))
	})

	It("does not touch the app registration or Key Vault for a certificate-only identity", func() {
		certPEM, keyPEM, _ := genCert("certonly.ezca.io", now.Add(-90*day), now.Add(10*day))
		createSecret("certonly-secret", certPEM, keyPEM)
		cci := createIdentity("certonly", "certonly-secret", ezcav1.CloudPublic, false)

		_, _, parsedNew := genCert("certonly.ezca.io", now, now.Add(100*day))
		ezcaClient.newChain = []*x509.Certificate{parsedNew}

		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(ezcaClient.called).To(BeTrue())

		// No app registration configured: it must never be touched.
		Expect(entraClient.added).To(BeEmpty())
		Expect(entraClient.removed).To(BeEmpty())
		Expect(entraClient.verifyCalls).To(Equal(0))

		// No Key Vault configured: it must never be touched either.
		Expect(kvClient.matchCalls).To(Equal(0))
		Expect(kvClient.imported).To(BeEmpty())

		// The renewed certificate is still promoted straight into the Secret.
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "certonly-secret", Namespace: namespace}, &secret)).To(Succeed())
		chain, err := pki.ParseCertChainPEM(secret.Data[tlsCertKey])
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].Equal(parsedNew)).To(BeTrue())
	})

	It("adds the renewed cert to the app, waits for propagation, then promotes it", func() {
		certPEM, keyPEM, oldCert := genCert("app.ezca.io", now.Add(-90*day), now.Add(10*day))
		createSecret("app-secret", certPEM, keyPEM)
		cci := createIdentity("app-identity", "app-secret", ezcav1.CloudPublic, true)

		_, _, parsedNew := genCert("app.ezca.io", now, now.Add(100*day))
		ezcaClient.newChain = []*x509.Certificate{parsedNew}

		secretName := types.NamespacedName{Name: "app-secret", Namespace: namespace}
		activeLeaf := func() *x509.Certificate {
			var s corev1.Secret
			Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
			chain, err := pki.ParseCertChainPEM(s.Data[tlsCertKey])
			Expect(err).NotTo(HaveOccurred())
			return chain[0]
		}
		hasPending := func() bool {
			var s corev1.Secret
			Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
			return len(s.Data["tls.crt.pending"]) > 0
		}

		// Reconcile #1: renew + addKey + stage pending. Active cert unchanged.
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(entraClient.added).To(HaveLen(1))
		Expect(entraClient.added[0]).To(Equal(parsedNew.Raw))
		Expect(activeLeaf().Equal(oldCert)).To(BeTrue(), "active cert must remain the old one while pending")
		Expect(hasPending()).To(BeTrue())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(cci.Status.PendingThumbprint).To(Equal(pki.Thumbprint(parsedNew)))
		Expect(cci.Status.ManagedKeyCredentials).To(HaveLen(1))
		Expect(cci.Status.ManagedKeyCredentials[0].KeyID).To(Equal("new-key-id"))

		reconcileNow := func() reconcile.Result {
			res, e := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
			Expect(e).NotTo(HaveOccurred())
			return res
		}

		// Reconcile #2: inside the grace window -> the controller must not even
		// try to authenticate with the staged certificate, and must wait out the
		// remainder of the grace in one go rather than polling.
		clockNow = now.Add(2 * time.Minute)
		entraClient.verifyCalls = 0
		res := reconcileNow()
		Expect(entraClient.verifyCalls).To(Equal(0), "must not authenticate with the staged cert during the grace window")
		Expect(res.RequeueAfter).To(Equal(propagationGrace - 2*time.Minute))
		Expect(hasPending()).To(BeTrue())
		Expect(activeLeaf().Equal(oldCert)).To(BeTrue())

		// Reconcile #3: past the grace window, auth still failing -> now it does
		// check, stays staged, and polls at propagationRequeue until the timeout.
		clockNow = now.Add(6 * time.Minute)
		entraClient.verifyErr = errors.New("AADSTS700027: key not found")
		entraClient.verifyCalls = 0
		res = reconcileNow()
		Expect(entraClient.verifyCalls).To(Equal(1), "must check the staged cert once the grace window has elapsed")
		Expect(res.RequeueAfter).To(Equal(propagationRequeue))
		Expect(hasPending()).To(BeTrue())
		Expect(activeLeaf().Equal(oldCert)).To(BeTrue())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedCertIdentity)).To(BeFalse())

		// Reconcile #4: auth succeeds and grace window elapsed -> promote.
		clockNow = now.Add(6 * time.Minute)
		entraClient.verifyErr = nil
		reconcileNow()
		Expect(hasPending()).To(BeFalse())
		Expect(activeLeaf().Equal(parsedNew)).To(BeTrue(), "renewed cert must be promoted after propagation")

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(cci.Status.PendingThumbprint).To(BeEmpty())
		Expect(cci.Status.LastRenewalTime).NotTo(BeNil())
		Expect(cci.Status.Thumbprint).To(Equal(pki.Thumbprint(parsedNew)))
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		// addKey happened exactly once across the whole flow.
		Expect(entraClient.added).To(HaveLen(1))
	})

	It("degrades once a staged certificate has not propagated by the timeout", func() {
		certPEM, keyPEM, oldCert := genCert("timeout.ezca.io", now.Add(-90*day), now.Add(10*day))
		createSecret("timeout-secret", certPEM, keyPEM)
		cci := createIdentity("timeout-identity", "timeout-secret", ezcav1.CloudPublic, true)

		_, _, parsedNew := genCert("timeout.ezca.io", now, now.Add(100*day))
		ezcaClient.newChain = []*x509.Certificate{parsedNew}

		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}
		secretName := types.NamespacedName{Name: "timeout-secret", Namespace: namespace}
		activeLeaf := func() *x509.Certificate {
			var s corev1.Secret
			Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
			chain, err := pki.ParseCertChainPEM(s.Data[tlsCertKey])
			Expect(err).NotTo(HaveOccurred())
			return chain[0]
		}

		// Stage the renewed certificate.
		_, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		// Still not authenticating well past the propagation timeout.
		entraClient.verifyErr = errors.New("AADSTS700027: key not found")
		clockNow = now.Add(propagationTimeout + time.Minute)
		res, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedCertIdentity)).To(BeTrue())
		cond := meta.FindStatusCondition(cci.Status.Conditions, typeDegradedCertIdentity)
		Expect(cond.Reason).To(Equal("PropagationTimeout"))

		// It keeps retrying (so it can still self-heal) but backs off past the
		// propagation poll interval, and the old certificate keeps serving.
		Expect(res.RequeueAfter).To(Equal(time.Minute))
		Expect(activeLeaf().Equal(oldCert)).To(BeTrue())
	})

	It("removes expired managed credentials from the app", func() {
		certPEM, keyPEM, _ := genCert("cleanup.ezca.io", now.Add(-10*day), now.Add(90*day))
		createSecret("cleanup-secret", certPEM, keyPEM)
		cci := createIdentity("cleanup", "cleanup-secret", ezcav1.CloudPublic, true)

		// Seed an expired managed credential that still exists on the app.
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		cci.Status.ManagedKeyCredentials = []ezcav1.ManagedKeyCredential{{
			Thumbprint: "OLD",
			KeyID:      "expired-key",
			NotAfter:   metav1.Time{Time: now.Add(-time.Hour)},
		}}
		Expect(k8sClient.Status().Update(ctx, cci)).To(Succeed())

		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(ezcaClient.called).To(BeFalse()) // healthy cert, not renewed
		Expect(entraClient.removed).To(ConsistOf("expired-key"))

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(cci.Status.ManagedKeyCredentials).To(BeEmpty())
	})

	It("removes many expired managed credentials from the app", func() {
		secretName := "cleanup-many-secret"
		certPEM, keyPEM, _ := genCert("cleanup.ezca.io", now.Add(-10*day), now.Add(90*day))
		createSecret(secretName, certPEM, keyPEM)
		cci := createIdentity(secretName, secretName, ezcav1.CloudPublic, true)

		// Seed an expired managed credential that still exists on the app.
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		numExpired := randv2.IntN(6) + 5

		managedKeys := make([]ezcav1.ManagedKeyCredential, 0, numExpired)
		keyIDs := make([]string, 0, numExpired)
		for i := range numExpired {
			amountExpired := time.Duration(i+1) * day
			keyID := "expired-key-" + fmt.Sprint(i)
			managedKeys = append(managedKeys, ezcav1.ManagedKeyCredential{
				Thumbprint: "OLD-" + fmt.Sprint(i),
				KeyID:      keyID,
				NotAfter:   metav1.Time{Time: now.Add(-amountExpired)},
			})
			keyIDs = append(keyIDs, keyID)
		}
		cci.Status.ManagedKeyCredentials = managedKeys
		Expect(k8sClient.Status().Update(ctx, cci)).To(Succeed())

		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(ezcaClient.called).To(BeFalse()) // healthy cert, not renewed
		Expect(entraClient.removed).To(ConsistOf(keyIDs))

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(cci.Status.ManagedKeyCredentials).To(BeEmpty())
	})

	It("does not touch Key Vault when it is not configured", func() {
		certPEM, keyPEM, _ := genCert("noapp-kv.ezca.io", now.Add(-90*day), now.Add(10*day))
		createSecret("noapp-kv-secret", certPEM, keyPEM)
		// App is configured, but KeyVault is left unset.
		cci := createIdentity("noapp-kv", "noapp-kv-secret", ezcav1.CloudPublic, true)

		_, _, parsedNew := genCert("noapp-kv.ezca.io", now, now.Add(100*day))
		ezcaClient.newChain = []*x509.Certificate{parsedNew}
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}

		// Reconcile #1: stage the renewed cert against the app registration.
		_, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(entraClient.added).To(HaveLen(1), "app registration is configured, so it must be used")

		// Reconcile #2: past the grace window and authenticating -> promote.
		clockNow = now.Add(propagationGrace)
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "noapp-kv-secret", Namespace: namespace}, &secret)).To(Succeed())
		chain, err := pki.ParseCertChainPEM(secret.Data[tlsCertKey])
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].Equal(parsedNew)).To(BeTrue())

		// Key Vault was never configured, so it must never be touched even though
		// the app-registration flow ran to completion.
		Expect(kvClient.matchCalls).To(Equal(0))
		Expect(kvClient.imported).To(BeEmpty())
	})

	It("imports the certificate into Key Vault when it differs, and skips when it matches", func() {
		certPEM, keyPEM, _ := genCert("kv.ezca.io", now.Add(-10*day), now.Add(90*day))
		createSecret("kv-secret", certPEM, keyPEM)

		ezcaURL := testEZCAURL
		tenant := testUUID0
		app := testUUID1
		objectID := testObjectID
		cci := &ezcav1.ClusterCertIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: "kv-identity"},
			Spec: ezcav1.ClusterCertIdentitySpec{
				CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
					EZCAURL:          &ezcaURL,
					CertSecretName:   "kv-secret",
					Cloud:            ezcav1.CloudPublic,
					RenewalThreshold: 20,
					// keyVault requires the app fields (cert authenticates as the app).
					TenantID:    &tenant,
					AppID:       &app,
					AppObjectID: &objectID,
					KeyVault:    &ezcav1.KeyVaultSpec{VaultName: vaultName, CertName: certName},
				},
				CertSecretNamespace: namespace,
				AllowedNamespaces:   []string{namespace},
			},
		}
		Expect(k8sClient.Create(ctx, cci)).To(Succeed())
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}

		// Key Vault differs -> import a PEM bundle (cert chain + key).
		kvClient.matches = false
		_, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(kvClient.imported).To(HaveLen(1))
		Expect(string(kvClient.imported[0])).To(ContainSubstring("BEGIN CERTIFICATE"))
		Expect(string(kvClient.imported[0])).To(ContainSubstring("PRIVATE KEY"))

		// Key Vault already matches -> no further import.
		kvClient.matches = true
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(kvClient.imported).To(HaveLen(1))
	})

	It("defers Key Vault sync (no error) while the certificate is still propagating", func() {
		// NotBefore sits past the grace window but inside the propagation
		// timeout, so a "key not found" from the vault is still plausibly
		// propagation and must be retried quietly rather than reported.
		certPEM, keyPEM, _ := genCert("kv2.ezca.io", now.Add(-10*time.Minute), now.Add(90*day))
		createSecret("kv2-secret", certPEM, keyPEM)

		ezcaURL := testEZCAURL
		tenant := testUUID0
		app := testUUID1
		objectID := testObjectID
		cci := &ezcav1.ClusterCertIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: "kv2-identity"},
			Spec: ezcav1.ClusterCertIdentitySpec{
				CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
					EZCAURL:          &ezcaURL,
					CertSecretName:   "kv2-secret",
					Cloud:            ezcav1.CloudPublic,
					RenewalThreshold: 20,
					TenantID:         &tenant,
					AppID:            &app,
					AppObjectID:      &objectID,
					KeyVault:         &ezcav1.KeyVaultSpec{VaultName: vaultName, CertName: certName},
				},
				CertSecretNamespace: namespace,
				AllowedNamespaces:   []string{namespace},
			},
		}
		Expect(k8sClient.Create(ctx, cci)).To(Succeed())

		// Vault auth fails with the propagation error -> transient, not Degraded.
		kvClient.matchErr = errors.New("ClientCertificateCredential authentication failed: AADSTS700027: key not found")
		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(propagationRequeue))
		Expect(kvClient.imported).To(BeEmpty())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedCertIdentity)).To(BeFalse())

		// Past the propagation timeout the same error is no longer plausibly
		// propagation, so it is reported instead of retried quietly.
		clockNow = now.Add(20 * time.Minute)
		res, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(time.Minute))
		Expect(kvClient.imported).To(BeEmpty())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedCertIdentity)).To(BeTrue())
	})

	It("does not touch Key Vault until the propagation grace has elapsed", func() {
		// A certificate that has only just become valid must not be used to
		// authenticate to Key Vault at all; the sync waits out the remainder of
		// the grace window in one go.
		certPEM, keyPEM, _ := genCert("kv4.ezca.io", now.Add(-1*time.Minute), now.Add(90*day))
		createSecret("kv4-secret", certPEM, keyPEM)

		ezcaURL := testEZCAURL
		tenant := testUUID0
		app := testUUID1
		objectID := testObjectID
		cci := &ezcav1.ClusterCertIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: "kv4-identity"},
			Spec: ezcav1.ClusterCertIdentitySpec{
				CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
					EZCAURL:          &ezcaURL,
					CertSecretName:   "kv4-secret",
					Cloud:            ezcav1.CloudPublic,
					RenewalThreshold: 20,
					TenantID:         &tenant,
					AppID:            &app,
					AppObjectID:      &objectID,
					KeyVault:         &ezcav1.KeyVaultSpec{VaultName: vaultName, CertName: certName},
				},
				CertSecretNamespace: namespace,
				AllowedNamespaces:   []string{namespace},
			},
		}
		Expect(k8sClient.Create(ctx, cci)).To(Succeed())

		kvClient.matchCalls = 0
		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvClient.matchCalls).To(Equal(0), "must not authenticate to Key Vault during the grace window")
		Expect(kvClient.imported).To(BeEmpty())
		Expect(res.RequeueAfter).To(Equal(propagationGrace - time.Minute))

		// Once the grace has elapsed the sync proceeds.
		clockNow = now.Add(6 * time.Minute)
		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvClient.matchCalls).To(Equal(1))
		Expect(kvClient.imported).To(HaveLen(1))
	})

	It("degrades when the certificate Secret is missing", func() {
		cci := createIdentity("missing", "nonexistent-secret", ezcav1.CloudPublic, false)

		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedCertIdentity)).To(BeTrue())
	})

	It("does not rewrite status on a steady-state reconcile", func() {
		certPEM, keyPEM, _ := genCert("noop.ezca.io", now.Add(-10*day), now.Add(90*day))
		createSecret("noop-secret", certPEM, keyPEM)
		cci := createIdentity("noop", "noop-secret", ezcav1.CloudPublic, false)
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}

		_, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		rv := cci.ResourceVersion

		// A second reconcile of an unchanged, healthy certificate must not write
		// status again — otherwise it would re-trigger itself through its own watch.
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(cci.ResourceVersion).To(Equal(rv), "steady-state reconcile must not bump the object")
	})

	It("does not re-charge the Key Vault propagation grace after a promotion", func() {
		// A cert whose NotBefore is well in the past has already propagated, even
		// if it was only just promoted (recent LastRenewalTime). The grace is keyed
		// off NotBefore, so Key Vault sync must proceed rather than defer.
		certPEM, keyPEM, _ := genCert("kv3.ezca.io", now.Add(-10*day), now.Add(90*day))
		createSecret("kv3-secret", certPEM, keyPEM)

		ezcaURL := testEZCAURL
		tenant := testUUID0
		app := testUUID1
		objectID := testObjectID
		cci := &ezcav1.ClusterCertIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: "kv3-identity"},
			Spec: ezcav1.ClusterCertIdentitySpec{
				CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
					EZCAURL:          &ezcaURL,
					CertSecretName:   "kv3-secret",
					Cloud:            ezcav1.CloudPublic,
					RenewalThreshold: 20,
					TenantID:         &tenant,
					AppID:            &app,
					AppObjectID:      &objectID,
					KeyVault:         &ezcav1.KeyVaultSpec{VaultName: vaultName, CertName: certName},
				},
				CertSecretNamespace: namespace,
				AllowedNamespaces:   []string{namespace},
			},
		}
		Expect(k8sClient.Create(ctx, cci)).To(Succeed())

		// Simulate a just-promoted certificate: LastRenewalTime is now.
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		cci.Status.LastRenewalTime = &metav1.Time{Time: now}
		Expect(k8sClient.Status().Update(ctx, cci)).To(Succeed())

		kvClient.matches = false
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvClient.imported).To(HaveLen(1), "must sync to Key Vault immediately, not defer on a recent LastRenewalTime")
	})
})

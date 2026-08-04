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
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ezcav1 "github.com/markeytos/ezca-cert-controller/api/v1"
	"github.com/markeytos/ezca-cert-controller/internal/entra"
	"github.com/markeytos/ezca-cert-controller/internal/pki"
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
	verifyErr error
	added     [][]byte
	removed   []string
}

func (f *fakeEntra) VerifyCredential(_ context.Context) error { return f.verifyErr }

func (f *fakeEntra) AddKey(_ context.Context, _ string, der []byte) (string, error) {
	f.added = append(f.added, der)
	return "new-key-id", nil
}

func (f *fakeEntra) RemoveKey(_ context.Context, _, keyID string) error {
	f.removed = append(f.removed, keyID)
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
		clockNow    time.Time
	)

	newReconciler := func() *ClusterCertIdentityReconciler {
		return &ClusterCertIdentityReconciler{
			Client:           k8sClient,
			Scheme:           k8sClient.Scheme(),
			DefaultNamespace: namespace,
			Now:              func() time.Time { return clockNow },
			NewEZCAClient:    func(string) (ezcaRenewer, error) { return ezcaClient, nil },
			NewEntraClient: func(_, _ string, _ entra.Cloud, _ *x509.Certificate, _ *rsa.PrivateKey) (entraManager, error) {
				return entraClient, nil
			},
		}
	}

	createSecret := func(name string, certPEM, keyPEM []byte) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	}

	createIdentity := func(name, secretName string, withApp bool) *ezcav1.ClusterCertIdentity {
		ezcaURL := "https://portal.ezca.io"
		friendly := name
		cci := &ezcav1.ClusterCertIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: ezcav1.ClusterCertIdentitySpec{
				Name:                &friendly,
				EZCAURL:             &ezcaURL,
				CertSecretName:      secretName,
				CertSecretNamespace: namespace,
				Cloud:               ezcav1.CloudPublic,
				RenewalThreshold:    20,
			},
		}
		if withApp {
			tenant := "00000000-0000-0000-0000-000000000000"
			app := "11111111-1111-1111-1111-111111111111"
			objectID := "obj-1"
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
		reconciler = newReconciler()
	})

	It("does not renew a healthy certificate", func() {
		certPEM, keyPEM, _ := genCert("healthy.ezca.io", now.Add(-10*24*time.Hour), now.Add(90*24*time.Hour))
		createSecret("healthy-secret", certPEM, keyPEM)
		cci := createIdentity("healthy", "healthy-secret", false)

		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))
		Expect(ezcaClient.called).To(BeFalse())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeAvailableClusterCertIdentity)).To(BeTrue())
		Expect(cci.Status.NotAfter).NotTo(BeNil())
	})

	It("renews a certificate past the threshold", func() {
		certPEM, keyPEM, _ := genCert("renew.ezca.io", now.Add(-90*24*time.Hour), now.Add(10*24*time.Hour))
		createSecret("renew-secret", certPEM, keyPEM)
		cci := createIdentity("renew", "renew-secret", false)

		_, _, parsedNew := genCert("renew.ezca.io", now, now.Add(100*24*time.Hour))
		ezcaClient.newChain = []*x509.Certificate{parsedNew}

		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(ezcaClient.called).To(BeTrue())

		// Secret was rewritten with the renewed certificate.
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "renew-secret", Namespace: namespace}, &secret)).To(Succeed())
		chain, err := pki.ParseCertChainPEM(secret.Data["tls.crt"])
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].Equal(parsedNew)).To(BeTrue())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(cci.Status.LastRenewalTime).NotTo(BeNil())
		Expect(cci.Status.Thumbprint).To(Equal(pki.Thumbprint(parsedNew)))
	})

	It("adds the renewed cert to the app, waits for propagation, then promotes it", func() {
		certPEM, keyPEM, oldCert := genCert("app.ezca.io", now.Add(-90*24*time.Hour), now.Add(10*24*time.Hour))
		createSecret("app-secret", certPEM, keyPEM)
		cci := createIdentity("app-identity", "app-secret", true)

		_, _, parsedNew := genCert("app.ezca.io", now, now.Add(100*24*time.Hour))
		ezcaClient.newChain = []*x509.Certificate{parsedNew}

		secretName := types.NamespacedName{Name: "app-secret", Namespace: namespace}
		activeLeaf := func() *x509.Certificate {
			var s corev1.Secret
			Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
			chain, err := pki.ParseCertChainPEM(s.Data["tls.crt"])
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

		reconcileNow := func() {
			_, e := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
			Expect(e).NotTo(HaveOccurred())
		}

		// Reconcile #2: auth still failing (even past the grace window) -> staged.
		clockNow = now.Add(6 * time.Minute)
		entraClient.verifyErr = errors.New("AADSTS700027: key not found")
		reconcileNow()
		Expect(hasPending()).To(BeTrue())
		Expect(activeLeaf().Equal(oldCert)).To(BeTrue())

		// Reconcile #3: auth succeeds but grace window has NOT elapsed -> still
		// staged (guards against a false positive from one propagated replica).
		clockNow = now
		entraClient.verifyErr = nil
		reconcileNow()
		Expect(hasPending()).To(BeTrue(), "must not promote before the grace window even if auth succeeds")
		Expect(activeLeaf().Equal(oldCert)).To(BeTrue())

		// Reconcile #4: auth succeeds and grace window elapsed -> promote.
		clockNow = now.Add(6 * time.Minute)
		reconcileNow()
		Expect(hasPending()).To(BeFalse())
		Expect(activeLeaf().Equal(parsedNew)).To(BeTrue(), "renewed cert must be promoted after propagation")

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(cci.Status.PendingThumbprint).To(BeEmpty())
		Expect(cci.Status.LastRenewalTime).NotTo(BeNil())
		Expect(cci.Status.Thumbprint).To(Equal(pki.Thumbprint(parsedNew)))
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeAvailableClusterCertIdentity)).To(BeTrue())
		// addKey happened exactly once across the whole flow.
		Expect(entraClient.added).To(HaveLen(1))
	})

	It("removes expired managed credentials from the app", func() {
		certPEM, keyPEM, _ := genCert("cleanup.ezca.io", now.Add(-10*24*time.Hour), now.Add(90*24*time.Hour))
		createSecret("cleanup-secret", certPEM, keyPEM)
		cci := createIdentity("cleanup", "cleanup-secret", true)

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

	It("degrades when the certificate Secret is missing", func() {
		cci := createIdentity("missing", "nonexistent-secret", false)

		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedClusterCertIdentity)).To(BeTrue())
	})
})

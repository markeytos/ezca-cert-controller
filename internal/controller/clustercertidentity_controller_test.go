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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
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
	if f.addErr != nil {
		return "", f.addErr
	}
	if len(der) <= 0 {
		return "", errors.New("fakeEntra: empty certificate DER")
	}
	f.added = append(f.added, der)
	return "new-key-id", nil
}

func (f *fakeEntra) RemoveKey(_ context.Context, _, keyID string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	if len(keyID) <= 0 {
		return errors.New("fakeEntra: empty keyID")
	}
	f.removed = append(f.removed, keyID)
	return nil
}

// secretWriteFailingClient fails Secret creates and updates while *fail is
// set, as an admission policy, quota or RBAC problem would.
type secretWriteFailingClient struct {
	client.Client
	fail *bool
}

func (c secretWriteFailingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*corev1.Secret); ok && *c.fail {
		return errors.New("admission webhook denied the request")
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c secretWriteFailingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if _, ok := obj.(*corev1.Secret); ok && *c.fail {
		return errors.New("admission webhook denied the request")
	}
	return c.Client.Update(ctx, obj, opts...)
}

// trustingEntra models an app registration's keyCredentials: a client
// certificate can authenticate (and sign addKey/removeKey proofs) only when its
// thumbprint is in trusted, and AddKey trusts the added certificate.
type trustingEntra struct {
	*fakeEntra
	trusted map[string]bool
}

// as returns a client for the app authenticated with cert, for a test's
// NewEntraClient.
func (t *trustingEntra) as(cert *x509.Certificate) entraManager {
	return &trustingEntraConn{t: t, cert: cert}
}

type trustingEntraConn struct {
	t    *trustingEntra
	cert *x509.Certificate
}

func (c *trustingEntraConn) authErr() error {
	if !c.t.trusted[pki.Thumbprint(c.cert)] {
		return errors.New("AADSTS700027: client certificate is not registered on the app")
	}
	return nil
}

func (c *trustingEntraConn) VerifyCredential(ctx context.Context) error {
	if err := c.authErr(); err != nil {
		c.t.verifyCalls++
		return err
	}
	return c.t.VerifyCredential(ctx)
}

func (c *trustingEntraConn) AddKey(ctx context.Context, objectID string, der []byte) (string, error) {
	if err := c.authErr(); err != nil {
		return "", err
	}
	keyID, err := c.t.AddKey(ctx, objectID, der)
	if err != nil {
		return "", err
	}
	added, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	c.t.trusted[pki.Thumbprint(added)] = true
	return keyID, nil
}

func (c *trustingEntraConn) RemoveKey(ctx context.Context, objectID, keyID string) error {
	if err := c.authErr(); err != nil {
		return err
	}
	return c.t.RemoveKey(ctx, objectID, keyID)
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

	// verifyInterval is how far apart the controller checks a staged
	// certificate under the default propagation timing.
	const verifyInterval = DefaultPropagationGrace / propagationVerifications

	// settle runs the checks promotion requires, the last of them a full grace
	// after addedAt (when the staged certificate's latest key was added).
	settle := func(req reconcile.Request, addedAt time.Time) {
		for i := 1; i <= propagationVerifications; i++ {
			clockNow = addedAt.Add(time.Duration(i) * verifyInterval)
			_, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
		}
	}

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

		// Reconcile #2: before the first check is due -> the controller must not
		// even try to authenticate with the staged certificate, and waits for the
		// check in one go rather than polling.
		clockNow = now.Add(2 * time.Minute)
		entraClient.verifyCalls = 0
		res := reconcileNow()
		Expect(entraClient.verifyCalls).To(Equal(0), "must not authenticate with the staged cert before the first check")
		Expect(res.RequeueAfter).To(Equal(verifyInterval - 2*time.Minute))
		Expect(hasPending()).To(BeTrue())
		Expect(activeLeaf().Equal(oldCert)).To(BeTrue())

		// Reconcile #3: first check, auth still failing -> stays staged, not
		// Degraded before the timeout, and the next check is an interval away.
		clockNow = now.Add(verifyInterval)
		entraClient.verifyErr = errors.New("AADSTS700027: key not found")
		res = reconcileNow()
		Expect(entraClient.verifyCalls).To(Equal(1), "must check the staged cert once a check is due")
		Expect(res.RequeueAfter).To(Equal(verifyInterval))
		Expect(hasPending()).To(BeTrue())
		Expect(activeLeaf().Equal(oldCert)).To(BeTrue())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedCertIdentity)).To(BeFalse())

		// The certificate authenticates from now on. A reconcile between checks
		// (for instance from a Secret event) does not check early.
		entraClient.verifyErr = nil
		clockNow = now.Add(verifyInterval + time.Minute)
		reconcileNow()
		Expect(entraClient.verifyCalls).To(Equal(1))

		// The failed check reset the count: although the grace has elapsed by the
		// third check overall, promotion needs three consecutive passes.
		for i := 2; i <= propagationVerifications+1; i++ {
			Expect(hasPending()).To(BeTrue(), "must not promote before %d consecutive checks pass", propagationVerifications)
			clockNow = now.Add(time.Duration(i) * verifyInterval)
			reconcileNow()
		}
		Expect(entraClient.verifyCalls).To(Equal(propagationVerifications + 1))
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

	It("honors a configured propagation grace", func() {
		certPEM, keyPEM, _ := genCert("grace.ezca.io", now.Add(-90*day), now.Add(10*day))
		createSecret("grace-secret", certPEM, keyPEM)
		cci := createIdentity("grace-identity", "grace-secret", ezcav1.CloudPublic, true)
		_, _, parsedNew := genCert("grace.ezca.io", now, now.Add(100*day))
		ezcaClient.newChain = []*x509.Certificate{parsedNew}
		reconciler.Propagation = PropagationTiming{Grace: 30 * time.Minute, Timeout: 45 * time.Minute}
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}
		promoted := func() bool {
			var s corev1.Secret
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "grace-secret", Namespace: namespace}, &s)).To(Succeed())
			chain, err := pki.ParseCertChainPEM(s.Data[tlsCertKey])
			Expect(err).NotTo(HaveOccurred())
			return chain[0].Equal(parsedNew)
		}

		// Checks are spaced a third of the configured grace apart.
		res, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(10 * time.Minute))
		for _, at := range []time.Duration{10 * time.Minute, 20 * time.Minute} {
			clockNow = now.Add(at)
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(promoted()).To(BeFalse())
		}
		clockNow = now.Add(30 * time.Minute)
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(promoted()).To(BeTrue())
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
		clockNow = now.Add(DefaultPropagationTimeout + time.Minute)
		res, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedCertIdentity)).To(BeTrue())
		cond := meta.FindStatusCondition(cci.Status.Conditions, typeDegradedCertIdentity)
		Expect(cond.Reason).To(Equal("PropagationTimeout"))

		// It keeps checking (so it can still self-heal), and the old certificate
		// keeps serving.
		Expect(res.RequeueAfter).To(Equal(verifyInterval))
		Expect(activeLeaf().Equal(oldCert)).To(BeTrue())

		// The next check passes: Degraded clears right away rather than lingering
		// until promotion, while promotion still waits for the full set of checks.
		entraClient.verifyErr = nil
		clockNow = clockNow.Add(verifyInterval)
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedCertIdentity)).To(BeFalse())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		Expect(cci.Status.PendingVerifications).To(Equal(int32(1)))
		Expect(activeLeaf().Equal(oldCert)).To(BeTrue())
	})

	It("promotes as soon as the staged certificate authenticates when the active one has expired", func() {
		certPEM, keyPEM, _ := genCert("dead.ezca.io", now.Add(-91*day), now.Add(-time.Hour))
		createSecret("dead-secret", certPEM, keyPEM)
		cci := createIdentity("dead-identity", "dead-secret", ezcav1.CloudPublic, true)
		_, _, parsedNew := genCert("dead.ezca.io", now, now.Add(100*day))
		ezcaClient.newChain = []*x509.Certificate{parsedNew}
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}

		// Nothing is left to protect, so it is checked at the short poll interval
		// instead of being spread across the grace.
		res, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(propagationRequeue))

		// The first passing check promotes it.
		clockNow = now.Add(propagationRequeue)
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		var s corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "dead-secret", Namespace: namespace}, &s)).To(Succeed())
		chain, err := pki.ParseCertChainPEM(s.Data[tlsCertKey])
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].Equal(parsedNew)).To(BeTrue())
		Expect(entraClient.verifyCalls).To(Equal(1))
	})

	It("waits for a staged certificate that is not valid yet instead of discarding it", func() {
		// The controller's clock is behind the CA's: discarding the staged cert
		// would have EZCA issue another on every pass.
		activePEM, activeKeyPEM, _ := genCert("skew.ezca.io", now.Add(-10*day), now.Add(90*day))
		pendingPEM, pendingKeyPEM, _ := genCert("skew.ezca.io", now.Add(10*time.Minute), now.Add(100*day))
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "skew-secret", Namespace: namespace},
			Type:       corev1.SecretTypeTLS,
			Data: map[string][]byte{
				tlsCertKey: activePEM, tlsKeyKey: activeKeyPEM,
				tlsCertPendingKey: pendingPEM, tlsKeyPendingKey: pendingKeyPEM,
			},
		})).To(Succeed())
		cci := createIdentity("skew", "skew-secret", ezcav1.CloudPublic, true)

		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(10*time.Minute + time.Second))
		Expect(ezcaClient.called).To(BeFalse())
		var s corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "skew-secret", Namespace: namespace}, &s)).To(Succeed())
		Expect(s.Data).To(HaveKey(tlsCertPendingKey))
	})

	It("reuses a renewed certificate while the Secret write keeps failing", func() {
		certPEM, keyPEM, _ := genCert("wfail.ezca.io", now.Add(-90*day), now.Add(10*day))
		createSecret("wfail-secret", certPEM, keyPEM)
		cci := createIdentity("wfail-identity", "wfail-secret", ezcav1.CloudPublic, true)
		_, _, parsedNew := genCert("wfail.ezca.io", now, now.Add(100*day))
		ezcaClient.newChain = []*x509.Certificate{parsedNew}
		failing := true
		reconciler.Client = secretWriteFailingClient{Client: k8sClient, fail: &failing}
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}

		_, err := reconciler.Reconcile(ctx, req)
		Expect(err).To(HaveOccurred())
		Expect(ezcaClient.called).To(BeTrue())

		// Every retry while the write keeps failing reuses the certificate.
		for i := 1; i <= 3; i++ {
			ezcaClient.called = false
			clockNow = now.Add(time.Duration(i) * time.Hour)
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).To(HaveOccurred())
			Expect(ezcaClient.called).To(BeFalse(), "must not renew again while the Secret write keeps failing")
		}

		// The write succeeds: the same certificate is staged.
		failing = false
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(ezcaClient.called).To(BeFalse())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(cci.Status.PendingThumbprint).To(Equal(pki.Thumbprint(parsedNew)))
	})

	It("discards an expired staged certificate that outlived its status and recovers the active cert", func() {
		// A staged (pending) certificate can survive in the Secret across a CR
		// delete/recreate, which wipes status — including PendingSince. If that
		// staged cert is already expired it can never be promoted, so the
		// controller must drop it and fall back to the healthy active certificate
		// instead of polling a dead cert forever.
		activePEM, activeKeyPEM, activeCert := genCert("stale.ezca.io", now.Add(-10*day), now.Add(90*day))
		pendingPEM, pendingKeyPEM, _ := genCert("stale.ezca.io", now.Add(-30*day), now.Add(-10*day)) // expired

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "stale-secret", Namespace: namespace},
			Type:       corev1.SecretTypeTLS,
			Data: map[string][]byte{
				tlsCertKey:        activePEM,
				tlsKeyKey:         activeKeyPEM,
				tlsCertPendingKey: pendingPEM,
				tlsKeyPendingKey:  pendingKeyPEM,
			},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		// Fresh identity: its status carries no PendingSince, mirroring a recreate.
		cci := createIdentity("stale", "stale-secret", ezcav1.CloudPublic, true)

		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}
		secretName := types.NamespacedName{Name: "stale-secret", Namespace: namespace}

		// Reconcile #1: the expired staged cert is dropped without any attempt to
		// authenticate with it, and the controller requeues promptly.
		res, err := reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(entraClient.verifyCalls).To(Equal(0), "must not authenticate with an expired staged cert")
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))
		var s corev1.Secret
		Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
		Expect(s.Data).NotTo(HaveKey(tlsCertPendingKey))
		Expect(s.Data).NotTo(HaveKey(tlsKeyPendingKey))

		// Reconcile #2: with the pending gone, the healthy active cert goes Available
		// and is never renewed away.
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(ezcaClient.called).To(BeFalse())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		Expect(cci.Status.Thumbprint).To(Equal(pki.Thumbprint(activeCert)))
	})

	It("adopts a PendingSince for a staged cert whose status was lost, then waits out the grace", func() {
		// Same delete/recreate scenario, but the staged cert is still valid: the
		// controller must adopt a fresh PendingSince and enter the grace window,
		// rather than looping with a nil PendingSince that can never time out.
		activePEM, activeKeyPEM, oldCert := genCert("adopt.ezca.io", now.Add(-10*day), now.Add(90*day))
		pendingPEM, pendingKeyPEM, pendingCert := genCert("adopt.ezca.io", now, now.Add(100*day))

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "adopt-secret", Namespace: namespace},
			Type:       corev1.SecretTypeTLS,
			Data: map[string][]byte{
				tlsCertKey:        activePEM,
				tlsKeyKey:         activeKeyPEM,
				tlsCertPendingKey: pendingPEM,
				tlsKeyPendingKey:  pendingKeyPEM,
			},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		cci := createIdentity("adopt", "adopt-secret", ezcav1.CloudPublic, true)

		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}})
		Expect(err).NotTo(HaveOccurred())
		// PendingSince adopted as now. The only sign-in finds the staged cert
		// already registered on the app (its record was lost with the status), so
		// it is tracked rather than added again, and the controller waits for the
		// first check, keeping the staged cert.
		Expect(entraClient.verifyCalls).To(Equal(1))
		Expect(entraClient.added).To(BeEmpty(), "must not add a certificate the app already trusts")
		Expect(res.RequeueAfter).To(Equal(verifyInterval))

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(cci.Status.PendingSince).NotTo(BeNil())
		Expect(cci.Status.PendingThumbprint).To(Equal(pki.Thumbprint(pendingCert)))

		var s corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "adopt-secret", Namespace: namespace}, &s)).To(Succeed())
		Expect(s.Data).To(HaveKey(tlsCertPendingKey))
		chain, err := pki.ParseCertChainPEM(s.Data[tlsCertKey])
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].Equal(oldCert)).To(BeTrue(), "active cert must keep serving during the grace")
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

		// Authenticating across the grace window -> promote.
		settle(req, now)

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
		certPEM, keyPEM, _ := genCert("kv2.ezca.io", now.Add(-DefaultPropagationGrace-10*time.Minute), now.Add(90*day))
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
		clockNow = now.Add(DefaultPropagationTimeout)
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
		Expect(res.RequeueAfter).To(Equal(DefaultPropagationGrace - time.Minute))

		// Once the grace has elapsed the sync proceeds.
		clockNow = now.Add(DefaultPropagationGrace)
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

	It("keeps a renewed certificate staged and does not renew again while the app keeps rejecting it", func() {
		certPEM, keyPEM, oldCert := genCert("loop.ezca.io", now.Add(-90*day), now.Add(10*day))
		createSecret("loop-secret", certPEM, keyPEM)
		cci := createIdentity("loop-identity", "loop-secret", ezcav1.CloudPublic, true)
		_, _, parsedNew := genCert("loop.ezca.io", now, now.Add(100*day))
		ezcaClient.newChain = []*x509.Certificate{parsedNew}
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}
		secretName := types.NamespacedName{Name: "loop-secret", Namespace: namespace}
		primary := &trustingEntra{fakeEntra: entraClient, trusted: map[string]bool{pki.Thumbprint(oldCert): true}}
		reconciler.NewEntraClient = func(_, _ string, _ entra.Cloud, cert *x509.Certificate, _ *rsa.PrivateKey) (entraManager, error) {
			return primary.as(cert), nil
		}

		// The app registration rejects the renewed certificate: it is staged, not
		// thrown away, and the old certificate keeps serving.
		entraClient.addErr = errors.New("graph is down")
		_, err := reconciler.Reconcile(ctx, req)
		Expect(err).To(HaveOccurred())
		Expect(ezcaClient.called).To(BeTrue())
		var s corev1.Secret
		Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
		Expect(s.Data).To(HaveKey(tlsCertPendingKey))
		chain, err := pki.ParseCertChainPEM(s.Data[tlsCertKey])
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].Equal(oldCert)).To(BeTrue())

		// Every retry while Entra keeps failing retries only the registration.
		for i := 1; i <= 3; i++ {
			ezcaClient.called = false
			clockNow = now.Add(time.Duration(i) * time.Hour)
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).To(HaveOccurred())
			Expect(ezcaClient.called).To(BeFalse(), "must not renew while the staged certificate awaits registration")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(cci.Status.PendingThumbprint).To(Equal(pki.Thumbprint(parsedNew)))
			Expect(meta.FindStatusCondition(cci.Status.Conditions, typeDegradedCertIdentity).Reason).To(Equal("AppRotationFailed"))
		}

		// Entra recovers: the staged certificate is registered, propagation is
		// measured from then, and it is promoted only after the grace window.
		entraClient.addErr = nil
		registeredAt := now.Add(4 * time.Hour)
		clockNow = registeredAt
		_, err = reconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(entraClient.added).To(Equal([][]byte{parsedNew.Raw}))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
		Expect(cci.Status.ManagedKeyCredentials[0].AddedAt.Time).To(BeTemporally("==", registeredAt))
		// The registration succeeding clears the Degraded it caused: the old
		// certificate is serving while the new one propagates.
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedCertIdentity)).To(BeFalse())
		Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
		Expect(s.Data).To(HaveKey(tlsCertPendingKey))

		settle(req, registeredAt)
		Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
		chain, err = pki.ParseCertChainPEM(s.Data[tlsCertKey])
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].Equal(parsedNew)).To(BeTrue())
		Expect(ezcaClient.called).To(BeFalse())
	})

	It("ignores status-only updates but not spec changes or deletion", func() {
		obj := &ezcav1.ClusterCertIdentity{ObjectMeta: metav1.ObjectMeta{Name: "p", Generation: 1}}
		statusOnly := obj.DeepCopy()
		statusOnly.Status.PendingThumbprint = "X"
		specChange := obj.DeepCopy()
		specChange.Generation = 2
		deleting := obj.DeepCopy()
		deleting.DeletionTimestamp = &metav1.Time{Time: now}

		Expect(specOrDeletionChanged.Update(event.UpdateEvent{ObjectOld: obj, ObjectNew: statusOnly})).To(BeFalse())
		Expect(specOrDeletionChanged.Update(event.UpdateEvent{ObjectOld: obj, ObjectNew: specChange})).To(BeTrue())
		Expect(specOrDeletionChanged.Update(event.UpdateEvent{ObjectOld: obj, ObjectNew: deleting})).To(BeTrue())
		Expect(specOrDeletionChanged.Create(event.CreateEvent{Object: obj})).To(BeTrue())
	})

	Describe("additional apps", func() {
		const (
			extraAppID2 = "22222222-2222-2222-2222-222222222222"
			extraObjID2 = "obj-2"
			extraAppID3 = "33333333-3333-3333-3333-333333333333"
			extraObjID3 = "obj-3"
		)

		var extra2, extra3 *fakeEntra

		BeforeEach(func() {
			extra2 = &fakeEntra{}
			extra3 = &fakeEntra{}
			reconciler.NewEntraClient = func(_, appID string, _ entra.Cloud, _ *x509.Certificate, _ *rsa.PrivateKey) (entraManager, error) {
				switch appID {
				case extraAppID2:
					return extra2, nil
				case extraAppID3:
					return extra3, nil
				default:
					return entraClient, nil
				}
			}
		})

		createMultiAppIdentity := func(name, secretName string) *ezcav1.ClusterCertIdentity {
			ezcaURL := testEZCAURL
			tenant := testUUID0
			app := testUUID1
			objectID := testObjectID
			cci := &ezcav1.ClusterCertIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: ezcav1.ClusterCertIdentitySpec{
					CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
						EZCAURL:          &ezcaURL,
						CertSecretName:   secretName,
						Cloud:            ezcav1.CloudPublic,
						RenewalThreshold: 20,
						TenantID:         &tenant,
						AppID:            &app,
						AppObjectID:      &objectID,
						AdditionalApps: []ezcav1.AdditionalAppSpec{
							{AppID: extraAppID2, AppObjectID: extraObjID2},
							{AppID: extraAppID3, AppObjectID: extraObjID3},
						},
					},
					CertSecretNamespace: namespace,
					AllowedNamespaces:   []string{namespace},
				},
			}
			Expect(k8sClient.Create(ctx, cci)).To(Succeed())
			return cci
		}

		It("adds the renewed cert to every app and promotes only once all of them authenticate", func() {
			certPEM, keyPEM, oldCert := genCert("multi.ezca.io", now.Add(-90*day), now.Add(10*day))
			createSecret("multi-secret", certPEM, keyPEM)
			cci := createMultiAppIdentity("multi-identity", "multi-secret")

			_, _, parsedNew := genCert("multi.ezca.io", now, now.Add(100*day))
			ezcaClient.newChain = []*x509.Certificate{parsedNew}
			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}
			secretName := types.NamespacedName{Name: "multi-secret", Namespace: namespace}

			// Renew: the certificate lands on the primary and both additional apps.
			_, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(entraClient.added).To(HaveLen(1))
			Expect(extra2.added).To(HaveLen(1))
			Expect(extra3.added).To(HaveLen(1))
			Expect(extra2.added[0]).To(Equal(parsedNew.Raw))

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(cci.Status.ManagedKeyCredentials).To(HaveLen(1))
			Expect(cci.Status.ManagedKeyCredentials[0].AdditionalKeys).To(HaveLen(2))

			// At the first check one additional app still cannot authenticate: the
			// check fails as a whole.
			clockNow = now.Add(verifyInterval)
			extra3.verifyErr = errors.New("AADSTS700027: key not found")
			res, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(Equal(verifyInterval))
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(cci.Status.PendingVerifications).To(BeZero())
			var s corev1.Secret
			Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
			Expect(s.Data).To(HaveKey(tlsCertPendingKey))
			chain, err := pki.ParseCertChainPEM(s.Data[tlsCertKey])
			Expect(err).NotTo(HaveOccurred())
			Expect(chain[0].Equal(oldCert)).To(BeTrue(), "must keep serving the old cert while an additional app cannot authenticate")

			// Every app authenticates from then on: promoted after three
			// consecutive passing checks.
			extra3.verifyErr = nil
			settle(req, now.Add(verifyInterval))
			Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
			Expect(s.Data).NotTo(HaveKey(tlsCertPendingKey))
			chain, err = pki.ParseCertChainPEM(s.Data[tlsCertKey])
			Expect(err).NotTo(HaveOccurred())
			Expect(chain[0].Equal(parsedNew)).To(BeTrue())
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
			// No duplicate additions across the whole flow.
			Expect(entraClient.added).To(HaveLen(1))
			Expect(extra2.added).To(HaveLen(1))
			Expect(extra3.added).To(HaveLen(1))
		})

		It("stages on a partial additional-app failure and completes the registration before promoting", func() {
			certPEM, keyPEM, _ := genCert("partial.ezca.io", now.Add(-90*day), now.Add(10*day))
			createSecret("partial-secret", certPEM, keyPEM)
			cci := createMultiAppIdentity("partial-identity", "partial-secret")

			_, _, parsedNew := genCert("partial.ezca.io", now, now.Add(100*day))
			ezcaClient.newChain = []*x509.Certificate{parsedNew}
			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}
			secretName := types.NamespacedName{Name: "partial-secret", Namespace: namespace}

			// One additional app rejects the addition: the renewed certificate is
			// still staged (it is on the primary app) rather than thrown away and
			// re-issued on the next pass.
			extra3.addErr = errors.New("graph is down")
			_, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(ezcaClient.called).To(BeTrue())
			var s corev1.Secret
			Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
			Expect(s.Data).To(HaveKey(tlsCertPendingKey))
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(cci.Status.ManagedKeyCredentials).To(HaveLen(1))
			Expect(cci.Status.ManagedKeyCredentials[0].AdditionalKeys).To(HaveLen(1))
			expectAdditionalAppFailure := func() {
				GinkgoHelper()
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
				cond := meta.FindStatusCondition(cci.Status.Conditions, typeDegradedCertIdentity)
				Expect(cond).NotTo(BeNil())
				Expect(cond.Reason).To(Equal("AdditionalAppRotationFailed"))
				Expect(cond.Message).To(ContainSubstring(extraAppID3))
				Expect(cond.Message).To(ContainSubstring("graph is down"))
				Expect(cond.Message).NotTo(ContainSubstring(extraAppID2), "only the app missing the certificate is named")
			}
			expectAdditionalAppFailure()

			// Still failing past the propagation timeout: the condition keeps
			// reporting the registration error, not a propagation timeout, and no
			// token checks are spent on a certificate an app does not hold.
			verifyCallsBefore := extra3.verifyCalls
			clockNow = now.Add(DefaultPropagationTimeout + time.Minute)
			res, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(Equal(verifyInterval))
			expectAdditionalAppFailure()
			Expect(extra3.verifyCalls).To(Equal(verifyCallsBefore))

			// The app recovers well after staging: the next pass completes the
			// missing registration, but that app only now holds the key, so
			// propagation starts over from here rather than promoting right away.
			extra3.addErr = nil
			recoveredAt := now.Add(DefaultPropagationTimeout + 2*time.Minute)
			clockNow = recoveredAt
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(extra3.added).To(HaveLen(1))
			Expect(extra3.added[0]).To(Equal(parsedNew.Raw))
			Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
			Expect(s.Data).To(HaveKey(tlsCertPendingKey), "a late-registered app must get the full grace")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedCertIdentity)).To(BeFalse())

			// Promoted only after a full grace for that app.
			settle(req, recoveredAt)
			Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
			Expect(s.Data).NotTo(HaveKey(tlsCertPendingKey))
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(cci.Status.ManagedKeyCredentials[0].AdditionalKeys).To(HaveLen(2))
			Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		})

		It("promotes for the primary app alone once the active certificate expires while an additional app cannot take the key", func() {
			certPEM, keyPEM, oldCert := genCert("stuck.ezca.io", now.Add(-90*day), now.Add(30*time.Minute))
			createSecret("stuck-secret", certPEM, keyPEM)
			cci := createMultiAppIdentity("stuck-identity", "stuck-secret")

			_, _, parsedNew := genCert("stuck.ezca.io", now, now.Add(100*day))
			ezcaClient.newChain = []*x509.Certificate{parsedNew}
			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}
			secretName := types.NamespacedName{Name: "stuck-secret", Namespace: namespace}
			expectServing := func(want *x509.Certificate) {
				GinkgoHelper()
				var s corev1.Secret
				Expect(k8sClient.Get(ctx, secretName, &s)).To(Succeed())
				chain, err := pki.ParseCertChainPEM(s.Data[tlsCertKey])
				Expect(err).NotTo(HaveOccurred())
				Expect(chain[0].Equal(want)).To(BeTrue())
			}
			expectUnrotated := func() {
				GinkgoHelper()
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
				cond := meta.FindStatusCondition(cci.Status.Conditions, typeDegradedCertIdentity)
				Expect(cond).NotTo(BeNil())
				Expect(cond.Reason).To(Equal("AdditionalAppRotationFailed"))
				Expect(cond.Message).To(ContainSubstring(extraAppID3))
				Expect(cond.Message).NotTo(ContainSubstring(extraAppID2))
			}

			// The app registration was deleted: every addition fails.
			extra3.addErr = errors.New("404 Request_ResourceNotFound")
			res, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(Equal(verifyInterval))

			// While the active certificate is valid, the missing app holds
			// promotion back, but the next pass comes no later than its expiry.
			clockNow = now.Add(verifyInterval)
			res, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(Equal(30*time.Minute - verifyInterval))
			expectServing(oldCert)
			expectUnrotated()

			// Once it expires the primary app alone decides: it already holds the
			// staged certificate, so the first passing check promotes it.
			clockNow = oldCert.NotAfter
			extra3VerifyCalls := extra3.verifyCalls
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			expectServing(parsedNew)
			Expect(extra3.verifyCalls).To(Equal(extra3VerifyCalls), "a missing app must not hold the promotion back")
			expectUnrotated()
			Expect(meta.FindStatusCondition(cci.Status.Conditions, typeDegradedCertIdentity).Message).To(ContainSubstring("Request_ResourceNotFound"))
			Expect(cci.Status.PendingThumbprint).To(BeEmpty())

			// The condition holds on steady-state passes while the app still
			// cannot authenticate with the certificate...
			extra3.verifyErr = errors.New("AADSTS700027: key not found")
			clockNow = oldCert.NotAfter.Add(time.Hour)
			res, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(Equal(unrotatedAppsRecheck))
			expectUnrotated()

			// ...and clears once an administrator has added it to the app.
			extra3.verifyErr = nil
			clockNow = clockNow.Add(unrotatedAppsRecheck)
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeDegradedCertIdentity)).To(BeFalse())
			Expect(meta.IsStatusConditionTrue(cci.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		})

		It("tracks a staged certificate already on the primary app without adding it again", func() {
			activePEM, activeKeyPEM, _ := genCert("lost.ezca.io", now.Add(-10*day), now.Add(90*day))
			pendingPEM, pendingKeyPEM, pendingCert := genCert("lost.ezca.io", now, now.Add(100*day))
			Expect(k8sClient.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "lost-secret", Namespace: namespace},
				Type:       corev1.SecretTypeTLS,
				Data: map[string][]byte{
					tlsCertKey: activePEM, tlsKeyKey: activeKeyPEM,
					tlsCertPendingKey: pendingPEM, tlsKeyPendingKey: pendingKeyPEM,
				},
			})).To(Succeed())
			// The staged cert was added to the primary app, but every status write
			// recording it failed: status does not know about it.
			cci := createMultiAppIdentity("lost-identity", "lost-secret")
			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}

			_, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(entraClient.added).To(BeEmpty(), "must not add a certificate the primary app already trusts")
			Expect(extra2.added).To(Equal([][]byte{pendingCert.Raw}))
			Expect(extra3.added).To(Equal([][]byte{pendingCert.Raw}))
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			entry := managedCredentialFor(cci.StatusBase(), pki.Thumbprint(pendingCert))
			Expect(entry).NotTo(BeNil())
			Expect(entry.KeyID).To(BeEmpty(), "its primary keyID was never recorded")
			Expect(entry.AdditionalKeys).To(HaveLen(2))

			settle(req, now)
			var s corev1.Secret
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "lost-secret", Namespace: namespace}, &s)).To(Succeed())
			Expect(s.Data).NotTo(HaveKey(tlsCertPendingKey))
		})

		// seedExpiredKey records an expired certificate held by the primary app
		// and by both additional apps.
		seedExpiredKey := func(cci *ezcav1.ClusterCertIdentity) reconcile.Request {
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			cci.Status.ManagedKeyCredentials = []ezcav1.ManagedKeyCredential{{
				Thumbprint: "OLD",
				KeyID:      "expired-key",
				NotAfter:   metav1.Time{Time: now.Add(-time.Hour)},
				AdditionalKeys: []ezcav1.AdditionalAppKey{
					{AppObjectID: extraObjID2, AppID: extraAppID2, KeyID: "extra-key-2"},
					{AppObjectID: extraObjID3, AppID: extraAppID3, KeyID: "extra-key-3"},
				},
			}}
			Expect(k8sClient.Status().Update(ctx, cci)).To(Succeed())
			return reconcile.Request{NamespacedName: types.NamespacedName{Name: cci.Name}}
		}

		It("removes an expired certificate from every app, retrying only the removals that failed", func() {
			certPEM, keyPEM, _ := genCert("multiclean.ezca.io", now.Add(-10*day), now.Add(90*day))
			createSecret("multiclean-secret", certPEM, keyPEM)
			cci := createMultiAppIdentity("multiclean-identity", "multiclean-secret")
			req := seedExpiredKey(cci)

			// One additional app fails the removal: the key still leaves the primary
			// app and the other additional app, and only the failed one is retried.
			extra3.removeErr = errors.New("graph is down")
			_, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(extra2.removed).To(ConsistOf("extra-key-2"))
			Expect(entraClient.removed).To(ConsistOf("expired-key"), "a failing additional app must not keep the expired key on the primary app")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(cci.Status.ManagedKeyCredentials).To(HaveLen(1))
			Expect(cci.Status.ManagedKeyCredentials[0].KeyID).To(BeEmpty())
			Expect(cci.Status.ManagedKeyCredentials[0].AdditionalKeys).To(ConsistOf(
				ezcav1.AdditionalAppKey{AppObjectID: extraObjID3, AppID: extraAppID3, KeyID: "extra-key-3"},
			))

			// The app recovers: its key is removed and the entry dropped, without
			// removing the primary key a second time.
			extra3.removeErr = nil
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(extra3.removed).To(ConsistOf("extra-key-3"))
			Expect(entraClient.removed).To(ConsistOf("expired-key"))
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(cci.Status.ManagedKeyCredentials).To(BeEmpty())
		})

		It("treats an expired key already gone from an app as removed", func() {
			certPEM, keyPEM, _ := genCert("gone.ezca.io", now.Add(-10*day), now.Add(90*day))
			createSecret("gone-secret", certPEM, keyPEM)
			cci := createMultiAppIdentity("gone-identity", "gone-secret")
			req := seedExpiredKey(cci)

			// The key was removed by hand from the primary app, and one additional
			// app registration was deleted: Graph answers 404 for both.
			notFound := &entra.GraphError{StatusCode: 404, Body: "Resource does not exist"}
			entraClient.removeErr = notFound
			extra3.removeErr = notFound
			_, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(extra2.removed).To(ConsistOf("extra-key-2"))
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(cci.Status.ManagedKeyCredentials).To(BeEmpty())
		})

		It("stops tracking an expired key on an app removed from additionalApps", func() {
			certPEM, keyPEM, _ := genCert("dropped.ezca.io", now.Add(-10*day), now.Add(90*day))
			createSecret("dropped-secret", certPEM, keyPEM)
			cci := createMultiAppIdentity("dropped-identity", "dropped-secret")
			req := seedExpiredKey(cci)

			// The administrator removes app 3. The active certificate was never added
			// there, so the removal cannot authenticate; it is tried once, then the
			// key is no longer tracked instead of being retried forever.
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			cci.Spec.AdditionalApps = []ezcav1.AdditionalAppSpec{{AppID: extraAppID2, AppObjectID: extraObjID2}}
			Expect(k8sClient.Update(ctx, cci)).To(Succeed())
			extra3.removeErr = errors.New("AADSTS700027: client certificate is not registered on the app")

			_, err := reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(extra2.removed).To(ConsistOf("extra-key-2"))
			Expect(entraClient.removed).To(ConsistOf("expired-key"))
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cci.Name}, cci)).To(Succeed())
			Expect(cci.Status.ManagedKeyCredentials).To(BeEmpty())
		})

		It("rejects additionalApps without the Entra app fields or repeating the primary app", func() {
			ezcaURL := testEZCAURL
			cci := &ezcav1.ClusterCertIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: "invalid-additional"},
				Spec: ezcav1.ClusterCertIdentitySpec{
					CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
						EZCAURL:          &ezcaURL,
						CertSecretName:   "invalid-additional-secret",
						RenewalThreshold: 20,
						AdditionalApps:   []ezcav1.AdditionalAppSpec{{AppID: extraAppID2, AppObjectID: extraObjID2}},
					},
					CertSecretNamespace: namespace,
					AllowedNamespaces:   []string{namespace},
				},
			}
			err := k8sClient.Create(ctx, cci)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("additionalApps requires the Entra app fields"))

			tenant := testUUID0
			app := testUUID1
			objectID := testObjectID
			cci.Spec.TenantID = &tenant
			cci.Spec.AppID = &app
			cci.Spec.AppObjectID = &objectID
			cci.Spec.AdditionalApps = []ezcav1.AdditionalAppSpec{{AppID: extraAppID2, AppObjectID: testObjectID}}
			err = k8sClient.Create(ctx, cci)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must not repeat the primary appObjectID"))
		})
	})
})

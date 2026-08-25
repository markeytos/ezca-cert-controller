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
	"errors"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ezca "github.com/markeytos/ezca-go"

	ezcav1 "github.com/markeytos/ezca-cert-controller/api/v1"
	"github.com/markeytos/ezca-cert-controller/internal/entra"
	"github.com/markeytos/ezca-cert-controller/internal/keyvault"
	"github.com/markeytos/ezca-cert-controller/internal/pki"
)

type fakeIssuer struct {
	chain  []*x509.Certificate
	called bool
	opts   *ezca.SignOptions
	err    error
}

func (f *fakeIssuer) Sign(_ context.Context, _ []byte, opts *ezca.SignOptions) ([]*x509.Certificate, error) {
	f.called = true
	f.opts = opts
	if f.err != nil {
		return nil, f.err
	}
	return f.chain, nil
}

// genCertSANs builds a self-signed certificate with an explicit DNS SAN list, so
// tests can produce a leaf that matches a ManagedCredential's spec.domains.
func genCertSANs(cn string, dnsNames []string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err = x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	certPEM = pki.EncodeCertChainPEM([]*x509.Certificate{cert})
	keyPEM, err = pki.EncodeRSAPrivateKeyPEM(key)
	Expect(err).NotTo(HaveOccurred())
	return
}

// genCertRich builds a self-signed certificate with every SAN type plus key
// usages, so tests can produce a leaf that matches a ManagedCredential's full
// spec.
func genCertRich(cn string, dns []string, ips []net.IP, uris []*url.URL, emails []string, keyUsage x509.KeyUsage, ekus []x509.ExtKeyUsage, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		DNSNames:       dns,
		IPAddresses:    ips,
		URIs:           uris,
		EmailAddresses: emails,
		KeyUsage:       keyUsage,
		ExtKeyUsage:    ekus,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err = x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	certPEM = pki.EncodeCertChainPEM([]*x509.Certificate{cert})
	keyPEM, err = pki.EncodeRSAPrivateKeyPEM(key)
	Expect(err).NotTo(HaveOccurred())
	return
}

var _ = Describe("ManagedCredential Controller", func() {
	const (
		namespace    = "default"
		caID         = testUUID0
		templateID   = testUUID1
		parentTntID  = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		parentAppID  = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
		parentObjID  = "parent-obj"
		noRefDomain  = "noref.ezca.io"
		sharedSecret = "mc-shared-sec"
		ownTntID     = "cccccccc-cccc-cccc-cccc-cccccccccccc"
		ownAppID     = "dddddddd-dddd-dddd-dddd-dddddddddddd"
		dnOld        = "old.ezca.io"
		dnNew        = "new.ezca.io"
		dnRenew      = "renew.ezca.io"
		dnFB         = "fb.ezca.io"
		dnKU         = "ku.ezca.io"
	)
	now := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	ctx := context.Background()

	var (
		reconciler   *ManagedCredentialReconciler
		ezcaClient   *fakeEZCA
		issuerClient *fakeIssuer
		entraClient  *fakeEntra
		kvClient     *fakeKeyVault
		clockNow     time.Time
		credTenant   string
	)

	newReconciler := func() *ManagedCredentialReconciler {
		return &ManagedCredentialReconciler{
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
			NewEZCAIssuer: func(_ context.Context, _ string, _ azcore.TokenCredential, _ cloud.Configuration, _, _ uuid.UUID) (ezcaIssuer, error) {
				return issuerClient, nil
			},
			NewTokenCredential: func(tenantID, _ string, _ entra.Cloud, _ *x509.Certificate, _ *rsa.PrivateKey) (azcore.TokenCredential, error) {
				credTenant = tenantID
				return nil, nil
			},
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

	// createParent creates a ClusterCertIdentity with an Entra app and a
	// bootstrapped certificate Secret, usable as a ManagedCredential's
	// identityRef.
	createParent := func(name, secretName string) {
		certPEM, keyPEM, _ := genCert("parent.ezca.io", now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
		createSecret(secretName, certPEM, keyPEM)
		ezcaURL := testEZCAURL
		tnt, app, obj := parentTntID, parentAppID, parentObjID
		cci := &ezcav1.ClusterCertIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: ezcav1.ClusterCertIdentitySpec{
				CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
					EZCAURL:          &ezcaURL,
					CertSecretName:   secretName,
					Cloud:            ezcav1.CloudPublic,
					RenewalThreshold: 20,
					TenantID:         &tnt,
					AppID:            &app,
					AppObjectID:      &obj,
				},
				CertSecretNamespace: namespace,
				AllowedNamespaces:   []string{namespace},
			},
		}
		Expect(k8sClient.Create(ctx, cci)).To(Succeed())
	}

	// createParentCertIdentity creates a namespaced CertIdentity (with an Entra
	// app and a bootstrapped Secret) in the credential's namespace.
	createParentCertIdentity := func(name, secretName string) {
		certPEM, keyPEM, _ := genCert("parent.ezca.io", now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
		createSecret(secretName, certPEM, keyPEM)
		ezcaURL := testEZCAURL
		tnt, app, obj := parentTntID, parentAppID, parentObjID
		ci := &ezcav1.CertIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: ezcav1.CertIdentitySpec{
				CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
					EZCAURL:          &ezcaURL,
					CertSecretName:   secretName,
					Cloud:            ezcav1.CloudPublic,
					RenewalThreshold: 20,
					TenantID:         &tnt,
					AppID:            &app,
					AppObjectID:      &obj,
				},
			},
		}
		Expect(k8sClient.Create(ctx, ci)).To(Succeed())
	}

	newManagedCredential := func(name, secretName, parentName, subjectName string, domains []string) *ezcav1.ManagedCredential {
		ezcaURL := testEZCAURL
		return &ezcav1.ManagedCredential{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: ezcav1.ManagedCredentialSpec{
				CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
					EZCAURL:          &ezcaURL,
					CertSecretName:   secretName,
					Cloud:            ezcav1.CloudPublic,
					RenewalThreshold: 20,
				},
				SubjectName: subjectName,
				DNSNames:    domains,
				CAID:        caID,
				TemplateID:  templateID,
				IdentityRef: &ezcav1.IdentityRefSpec{
					Name: parentName,
					Kind: ezcav1.IdentityKindClusterCertIdentity,
				},
			},
		}
	}

	reconcileMC := func(name string) reconcile.Result {
		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}})
		Expect(err).NotTo(HaveOccurred())
		return res
	}

	BeforeEach(func() {
		clockNow = now
		ezcaClient = &fakeEZCA{}
		issuerClient = &fakeIssuer{}
		entraClient = &fakeEntra{}
		kvClient = &fakeKeyVault{}
		credTenant = ""
		reconciler = newReconciler()
	})

	It("bootstraps by issuing a certificate when the Secret is missing", func() {
		createParent("mcp-boot", "mcp-boot-sec")
		_, _, issued := genCertSANs("sub.ezca.io", []string{"sub.ezca.io", "api.sub.ezca.io"}, now, now.Add(90*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}

		mc := newManagedCredential("mc-boot", "mc-boot-sec", "mcp-boot", "CN=sub.ezca.io", []string{"sub.ezca.io", "api.sub.ezca.io"})
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-boot")

		Expect(issuerClient.called).To(BeTrue())
		Expect(issuerClient.opts.SubjectName).To(Equal("CN=sub.ezca.io"))
		Expect(issuerClient.opts.DNSNames).To(ConsistOf("sub.ezca.io", "api.sub.ezca.io"))
		// Bootstrap uses the parent identity's app (no own cert yet).
		Expect(credTenant).To(Equal(parentTntID))

		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-boot-sec"}, &secret)).To(Succeed())
		Expect(secret.Data).To(HaveKey(tlsCertKey))
		Expect(secret.Data).To(HaveKey(tlsKeyKey))

		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-boot"}, mc)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		Expect(mc.Status.NotAfter).NotTo(BeNil())
	})

	It("bootstraps from a namespaced CertIdentity in the same namespace", func() {
		createParentCertIdentity("ci-parent", "ci-parent-sec")
		_, _, issued := genCertSANs("cisub.ezca.io", []string{"cisub.ezca.io"}, now, now.Add(90*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}

		mc := newManagedCredential("mc-ci", "mc-ci-sec", "ci-parent", "CN=cisub.ezca.io", []string{"cisub.ezca.io"})
		mc.Spec.IdentityRef.Kind = ezcav1.IdentityKindCertIdentity
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-ci")

		Expect(issuerClient.called).To(BeTrue())
		// Authenticated as the CertIdentity's app, resolved in the MC's namespace.
		Expect(credTenant).To(Equal(parentTntID))

		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-ci-sec"}, &secret)).To(Succeed())
		Expect(secret.Data).To(HaveKey(tlsCertKey))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-ci"}, mc)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
	})

	It("passes typed SANs, key usages, and validity to the issuer", func() {
		createParent("mcp-opts", "mcp-opts-sec")
		ip := net.ParseIP("192.0.2.10")
		uri, err := url.Parse("spiffe://cluster.local/ns/default/sa/app")
		Expect(err).NotTo(HaveOccurred())
		_, _, issued := genCertRich("opts.ezca.io", []string{"opts.ezca.io"}, []net.IP{ip}, []*url.URL{uri}, []string{"admin@example.com"},
			x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now, now.Add(90*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}

		mc := newManagedCredential("mc-opts", "mc-opts-sec", "mcp-opts", "CN=opts.ezca.io", []string{"opts.ezca.io"})
		mc.Spec.IPAddresses = []string{"192.0.2.10"}
		mc.Spec.URIs = []string{"spiffe://cluster.local/ns/default/sa/app"}
		mc.Spec.EmailAddresses = []string{"admin@example.com"}
		mc.Spec.ValidityInDays = 30
		mc.Spec.KeyUsages = []ezcav1.KeyUsage{ezcav1.KeyUsageDigitalSignature, ezcav1.KeyUsageKeyEncipherment}
		mc.Spec.ExtendedKeyUsages = []ezcav1.ExtKeyUsage{ezcav1.ExtKeyUsageServerAuth}
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-opts")

		Expect(issuerClient.called).To(BeTrue())
		Expect(issuerClient.opts.DNSNames).To(ConsistOf("opts.ezca.io"))
		Expect(issuerClient.opts.IPAddresses).To(HaveLen(1))
		Expect(issuerClient.opts.IPAddresses[0].String()).To(Equal("192.0.2.10"))
		Expect(issuerClient.opts.URIs).To(HaveLen(1))
		Expect(issuerClient.opts.URIs[0].String()).To(Equal("spiffe://cluster.local/ns/default/sa/app"))
		Expect(issuerClient.opts.EmailAddresses).To(ConsistOf("admin@example.com"))
		Expect(issuerClient.opts.KeyUsages).To(ConsistOf(ezca.KeyUsageDigitalSignature, ezca.KeyUsageKeyEncipherment))
		Expect(issuerClient.opts.ExtendedKeyUsages).To(ConsistOf(ezca.ExtKeyUsageServerAuth))
		Expect(issuerClient.opts.Duration).To(Equal(30 * 24 * time.Hour))

		// The issued cert matches the full spec, so the credential is Available.
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-opts"}, mc)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
	})

	It("re-issues when the certificate drifts from the desired subject/domains", func() {
		createParent("mcp-drift", "mcp-drift-sec")
		oldPEM, oldKeyPEM, _ := genCertSANs(dnOld, []string{dnOld}, now.Add(-24*time.Hour), now.Add(90*24*time.Hour))
		createSecret("mc-drift-sec", oldPEM, oldKeyPEM)
		_, _, issued := genCertSANs(dnNew, []string{dnNew}, now, now.Add(90*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}

		mc := newManagedCredential("mc-drift", "mc-drift-sec", "mcp-drift", "CN=new.ezca.io", []string{dnNew})
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-drift")

		Expect(issuerClient.called).To(BeTrue())
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-drift-sec"}, &secret)).To(Succeed())
		chain, _, err := parseSecret(&secret)
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].Subject.CommonName).To(Equal(dnNew))
	})

	It("re-issues to heal drifted key usages while subject and SANs match", func() {
		createParent("mcp-ku", "mcp-ku-sec")
		// Current cert has the wrong EKU (ClientAuth) but the right subject/SANs.
		oldPEM, oldKeyPEM, _ := genCertRich(dnKU, []string{dnKU}, nil, nil, nil,
			x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-24*time.Hour), now.Add(90*24*time.Hour))
		createSecret("mc-ku-sec", oldPEM, oldKeyPEM)
		// The re-issued cert has the desired EKU (ServerAuth).
		_, _, issued := genCertRich(dnKU, []string{dnKU}, nil, nil, nil,
			x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now, now.Add(90*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}

		mc := newManagedCredential("mc-ku", "mc-ku-sec", "mcp-ku", "CN=ku.ezca.io", []string{dnKU})
		mc.Spec.KeyUsages = []ezcav1.KeyUsage{ezcav1.KeyUsageDigitalSignature}
		mc.Spec.ExtendedKeyUsages = []ezcav1.ExtKeyUsage{ezcav1.ExtKeyUsageServerAuth}
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-ku")

		// Only the EKU differed, yet the certificate is re-issued and healed.
		Expect(issuerClient.called).To(BeTrue())
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-ku-sec"}, &secret)).To(Succeed())
		chain, _, err := parseSecret(&secret)
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageServerAuth))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-ku"}, mc)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
	})

	It("renews a matching certificate via the shared state machine (not issuance)", func() {
		certPEM, keyPEM, _ := genCertSANs(dnRenew, []string{dnRenew}, now.Add(-90*24*time.Hour), now.Add(10*24*time.Hour))
		createSecret("mc-renew-sec", certPEM, keyPEM)
		_, _, renewed := genCertSANs(dnRenew, []string{dnRenew}, now, now.Add(365*24*time.Hour))
		ezcaClient.newChain = []*x509.Certificate{renewed}

		mc := newManagedCredential("mc-renew", "mc-renew-sec", "mcp-none", "CN=renew.ezca.io", []string{dnRenew})
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-renew")

		Expect(ezcaClient.called).To(BeTrue())
		Expect(issuerClient.called).To(BeFalse())
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-renew-sec"}, &secret)).To(Succeed())
		chain, _, err := parseSecret(&secret)
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].NotAfter).To(BeTemporally("==", renewed.NotAfter))
	})

	It("renews an externally provisioned certificate with no identityRef", func() {
		// The Secret is bootstrapped by an administrator; with no identityRef the
		// controller renews it (the certificate authenticates its own renewal to
		// EZCA) and never issues.
		certPEM, keyPEM, _ := genCertSANs(noRefDomain, []string{noRefDomain}, now.Add(-90*24*time.Hour), now.Add(10*24*time.Hour))
		createSecret("mc-noref-sec", certPEM, keyPEM)
		_, _, renewed := genCertSANs(noRefDomain, []string{noRefDomain}, now, now.Add(365*24*time.Hour))
		ezcaClient.newChain = []*x509.Certificate{renewed}

		mc := newManagedCredential("mc-noref", "mc-noref-sec", "", "CN=noref.ezca.io", []string{noRefDomain})
		mc.Spec.IdentityRef = nil
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-noref")

		Expect(ezcaClient.called).To(BeTrue())
		Expect(issuerClient.called).To(BeFalse())
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-noref-sec"}, &secret)).To(Succeed())
		chain, _, err := parseSecret(&secret)
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].NotAfter).To(BeTemporally("==", renewed.NotAfter))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-noref"}, mc)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
	})

	It("ignores drift and just renews when no identityRef is set", func() {
		// The bootstrapped certificate's SANs do not match the spec, but with no
		// identityRef there is no way to re-issue, so it is renewed as-is rather
		// than treated as drift.
		certPEM, keyPEM, _ := genCertSANs("stale.ezca.io", []string{"stale.ezca.io"}, now.Add(-90*24*time.Hour), now.Add(10*24*time.Hour))
		createSecret("mc-norefdrift-sec", certPEM, keyPEM)
		_, _, renewed := genCertSANs("stale.ezca.io", []string{"stale.ezca.io"}, now, now.Add(365*24*time.Hour))
		ezcaClient.newChain = []*x509.Certificate{renewed}

		mc := newManagedCredential("mc-norefdrift", "mc-norefdrift-sec", "", "CN=desired.ezca.io", []string{"desired.ezca.io"})
		mc.Spec.IdentityRef = nil
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-norefdrift")

		Expect(issuerClient.called).To(BeFalse())
		Expect(ezcaClient.called).To(BeTrue())
	})

	It("degrades as not-bootstrapped when the Secret is missing and no identityRef is set", func() {
		mc := newManagedCredential("mc-noboot", "mc-noboot-sec", "", "CN=noboot.ezca.io", []string{"noboot.ezca.io"})
		mc.Spec.IdentityRef = nil
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		res := reconcileMC("mc-noboot")

		// Nothing is issued or renewed; the admin must provision the certificate.
		Expect(issuerClient.called).To(BeFalse())
		Expect(ezcaClient.called).To(BeFalse())
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-noboot"}, mc)).To(Succeed())
		cond := meta.FindStatusCondition(mc.Status.Conditions, typeDegradedCertIdentity)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal("CertificateNotBootstrapped"))
		// No Secret was created on the credential's behalf.
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-noboot-sec"}, &secret)).ShouldNot(Succeed())
	})

	It("degrades as not-bootstrapped when the Secret is empty and no identityRef is set", func() {
		empty := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "mc-empty-sec", Namespace: namespace},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{tlsCertKey: {}, tlsKeyKey: {}},
		}
		Expect(k8sClient.Create(ctx, empty)).To(Succeed())

		mc := newManagedCredential("mc-empty", "mc-empty-sec", "", "CN=empty.ezca.io", []string{"empty.ezca.io"})
		mc.Spec.IdentityRef = nil
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-empty")

		Expect(issuerClient.called).To(BeFalse())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-empty"}, mc)).To(Succeed())
		cond := meta.FindStatusCondition(mc.Status.Conditions, typeDegradedCertIdentity)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal("CertificateNotBootstrapped"))
	})

	It("falls back to issuance when renewal fails", func() {
		createParent("mcp-fb", "mcp-fb-sec")
		certPEM, keyPEM, _ := genCertSANs(dnFB, []string{dnFB}, now.Add(-90*24*time.Hour), now.Add(10*24*time.Hour))
		createSecret("mc-fb-sec", certPEM, keyPEM)
		ezcaClient.err = errors.New("EZCA no longer has the domains")
		_, _, issued := genCertSANs(dnFB, []string{dnFB}, now, now.Add(365*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}

		mc := newManagedCredential("mc-fb", "mc-fb-sec", "mcp-fb", "CN=fb.ezca.io", []string{dnFB})
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-fb")

		Expect(ezcaClient.called).To(BeTrue())
		Expect(issuerClient.called).To(BeTrue())
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-fb-sec"}, &secret)).To(Succeed())
		chain, _, err := parseSecret(&secret)
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].NotAfter).To(BeTemporally("==", issued.NotAfter))
	})

	It("uses its own app credential for re-issuance when its cert is registered in Entra", func() {
		createParent("mcp-own", "mcp-own-sec")
		oldPEM, oldKeyPEM, oldCert := genCertSANs(dnOld, []string{dnOld}, now.Add(-24*time.Hour), now.Add(90*24*time.Hour))
		createSecret("mc-own-sec", oldPEM, oldKeyPEM)
		_, _, issued := genCertSANs(dnNew, []string{dnNew}, now, now.Add(90*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}

		mc := newManagedCredential("mc-own", "mc-own-sec", "mcp-own", "CN=new.ezca.io", []string{dnNew})
		tnt, app, obj := ownTntID, ownAppID, "own-obj"
		mc.Spec.TenantID = &tnt
		mc.Spec.AppID = &app
		mc.Spec.AppObjectID = &obj
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		// Record the current cert as registered in the credential's own app.
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-own"}, mc)).To(Succeed())
		mc.Status.ManagedKeyCredentials = []ezcav1.ManagedKeyCredential{{
			Thumbprint: pki.Thumbprint(oldCert),
			KeyID:      "key-1",
			NotAfter:   metav1.Time{Time: oldCert.NotAfter},
		}}
		Expect(k8sClient.Status().Update(ctx, mc)).To(Succeed())

		reconcileMC("mc-own")

		Expect(issuerClient.called).To(BeTrue())
		// Own app was used, not the parent identity.
		Expect(credTenant).To(Equal(ownTntID))

		// The re-issued cert was added to the app, authenticated by the current
		// (registered) cert, and staged as pending while the old cert keeps
		// serving.
		Expect(entraClient.added).To(HaveLen(1))
		Expect(entraClient.added[0]).To(Equal(issued.Raw))
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-own-sec"}, &secret)).To(Succeed())
		Expect(secret.Data).To(HaveKey("tls.crt.pending"))
		activeChain, _, err := parseSecret(&secret)
		Expect(err).NotTo(HaveOccurred())
		Expect(activeChain[0].Subject.CommonName).To(Equal(dnOld))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-own"}, mc)).To(Succeed())
		Expect(mc.Status.PendingThumbprint).To(Equal(pki.Thumbprint(issued)))
	})

	It("falls back to the identityRef when renewal fails and its own registered cert is expired", func() {
		createParent("mcp-exp", "mcp-exp-sec")
		// The current cert matches the spec and is still recorded as registered on
		// the credential's own app, but it has expired — so it can no longer
		// authenticate. Renewal fails, and the fallback re-issuance must NOT try to
		// authenticate as the own app with the dead cert; it must use the identityRef
		// so the credential can self-heal instead of deadlocking.
		expPEM, expKeyPEM, expCert := genCertSANs(dnFB, []string{dnFB}, now.Add(-90*24*time.Hour), now.Add(-24*time.Hour))
		createSecret("mc-exp-sec", expPEM, expKeyPEM)
		ezcaClient.err = errors.New("cannot authenticate with an expired certificate")
		_, _, issued := genCertSANs(dnFB, []string{dnFB}, now, now.Add(365*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}

		mc := newManagedCredential("mc-exp", "mc-exp-sec", "mcp-exp", "CN=fb.ezca.io", []string{dnFB})
		tnt, app, obj := ownTntID, ownAppID, "exp-obj"
		mc.Spec.TenantID = &tnt
		mc.Spec.AppID = &app
		mc.Spec.AppObjectID = &obj
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		// Record the (now expired) current cert as registered in the own app.
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-exp"}, mc)).To(Succeed())
		mc.Status.ManagedKeyCredentials = []ezcav1.ManagedKeyCredential{{
			Thumbprint: pki.Thumbprint(expCert),
			KeyID:      "key-1",
			NotAfter:   metav1.Time{Time: expCert.NotAfter},
		}}
		Expect(k8sClient.Status().Update(ctx, mc)).To(Succeed())

		reconcileMC("mc-exp")

		Expect(ezcaClient.called).To(BeTrue())
		Expect(issuerClient.called).To(BeTrue())
		// The expired own cert must not be used; issuance falls back to the parent.
		Expect(credTenant).To(Equal(parentTntID))
	})

	It("persists a bootstrapped certificate even when app registration fails, and does not re-issue", func() {
		createParent("mcp-storm", "mcp-storm-sec")
		_, _, issued := genCertSANs("storm.ezca.io", []string{"storm.ezca.io"}, now, now.Add(90*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}
		// addKey to the own app fails (e.g. the Graph 401 seen in the field).
		entraClient.addErr = errors.New("addKey failed with status 401")

		mc := newManagedCredential("mc-storm", "mc-storm-sec", "mcp-storm", "CN=storm.ezca.io", []string{"storm.ezca.io"})
		tnt, app, obj := ownTntID, ownAppID, "storm-obj"
		mc.Spec.TenantID = &tnt
		mc.Spec.AppID = &app
		mc.Spec.AppObjectID = &obj
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		// Reconcile #1: bootstrap issues, registration fails — but the certificate
		// must be persisted rather than discarded.
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: "mc-storm"}})
		Expect(err).To(HaveOccurred(), "addKey failure surfaces as a reconcile error/backoff")
		Expect(issuerClient.called).To(BeTrue())

		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-storm-sec"}, &secret)).To(Succeed())
		chain, _, perr := parseSecret(&secret)
		Expect(perr).NotTo(HaveOccurred())
		Expect(chain[0].Equal(issued)).To(BeTrue(), "the issued cert must be persisted despite the addKey failure")

		// Reconcile #2: the Secret now holds the cert, so we must NOT bootstrap and
		// issue a brand-new certificate again (no issuance storm).
		issuerClient.called = false
		_, _ = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: "mc-storm"}})
		Expect(issuerClient.called).To(BeFalse(), "must not re-issue once the certificate is persisted")

		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-storm-sec"}, &secret)).To(Succeed())
		chain2, _, perr := parseSecret(&secret)
		Expect(perr).NotTo(HaveOccurred())
		Expect(chain2[0].Equal(issued)).To(BeTrue(), "the persisted cert is unchanged (not replaced by a fresh issuance)")
	})

	It("retries app registration for a persisted but unregistered certificate", func() {
		const mcName = "mc-rereg"
		createParent("mcp-rereg", "mcp-rereg-sec")
		_, _, issued := genCertSANs("rereg.ezca.io", []string{"rereg.ezca.io"}, now, now.Add(90*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}
		entraClient.addErr = errors.New("addKey failed with status 401")

		mc := newManagedCredential(mcName, "mc-rereg-sec", "mcp-rereg", "CN=rereg.ezca.io", []string{"rereg.ezca.io"})
		tnt, app, obj := ownTntID, ownAppID, "rereg-obj"
		mc.Spec.TenantID = &tnt
		mc.Spec.AppID = &app
		mc.Spec.AppObjectID = &obj
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		// Bootstrap: issuance succeeds, registration fails.
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: mcName}})
		Expect(err).To(HaveOccurred())

		// While the certificate is unregistered, later reconciles must retry the
		// registration and keep the credential unavailable — not report it healthy.
		issuerClient.called = false
		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: mcName}})
		Expect(err).To(HaveOccurred(), "the registration failure must keep surfacing")
		Expect(issuerClient.called).To(BeFalse(), "the retry must not issue a new certificate")
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: mcName}, mc)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeFalse(),
			"must not report Available while the certificate is unregistered")
		cond := meta.FindStatusCondition(mc.Status.Conditions, typeDegradedCertIdentity)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal("AppRotationFailed"))

		// Entra recovers: the persisted certificate is registered, the credential
		// becomes Available, and still nothing is re-issued.
		entraClient.addErr = nil
		reconcileMC(mcName)

		Expect(entraClient.added).To(HaveLen(1))
		Expect(entraClient.added[0]).To(Equal(issued.Raw))
		Expect(issuerClient.called).To(BeFalse())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: mcName}, mc)).To(Succeed())
		Expect(mc.Status.ManagedKeyCredentials).To(HaveLen(1))
		Expect(mc.Status.ManagedKeyCredentials[0].Thumbprint).To(Equal(pki.Thumbprint(issued)))
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
	})

	It("measures Key Vault propagation from the app registration, not the certificate's NotBefore", func() {
		const mcName = "mc-kvprop"
		createParent("mcp-kvprop", "mcp-kvprop-sec")
		cn := "kvprop.ezca.io"
		// The active certificate long predates the registration performed below,
		// so a NotBefore-based propagation window would already be exhausted.
		certPEM, keyPEM, _ := genCertSANs(cn, []string{cn}, now.Add(-24*time.Hour), now.Add(90*24*time.Hour))
		createSecret("mc-kvprop-sec", certPEM, keyPEM)

		mc := newManagedCredential(mcName, "mc-kvprop-sec", "mcp-kvprop", "CN="+cn, []string{cn})
		tnt, app, obj := ownTntID, ownAppID, "kvprop-obj"
		mc.Spec.TenantID = &tnt
		mc.Spec.AppID = &app
		mc.Spec.AppObjectID = &obj
		mc.Spec.KeyVault = &ezcav1.KeyVaultSpec{VaultName: vaultName, CertName: certName}
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		// Reconcile #1 registers the certificate on the app; Key Vault must then
		// wait out the propagation grace measured from that registration.
		reconcileMC(mcName)
		Expect(entraClient.added).To(HaveLen(1))
		Expect(kvClient.matchCalls).To(Equal(0), "the grace runs from the registration, not NotBefore")

		// Within the propagation window a key-not-found vault error is transient:
		// polled quietly, not Degraded.
		clockNow = now.Add(6 * time.Minute)
		kvClient.matchErr = errors.New("ClientCertificateCredential authentication failed: AADSTS700027: key not found")
		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: mcName}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(propagationRequeue))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: mcName}, mc)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeDegradedCertIdentity)).To(BeFalse())

		// Past the propagation timeout (still measured from the registration) the
		// same error is no longer plausibly propagation and is reported.
		clockNow = now.Add(20 * time.Minute)
		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: mcName}})
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: mcName}, mc)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeDegradedCertIdentity)).To(BeTrue())
		Expect(meta.FindStatusCondition(mc.Status.Conditions, typeDegradedCertIdentity).Reason).To(Equal("KeyVaultSyncFailed"))
	})

	It("skips Key Vault sync when its certificate is not registered on the app", func() {
		createParent("mcp-kvguard", "mcp-kvguard-sec")
		cn := "kvguard.ezca.io"
		certPEM, keyPEM, _ := genCertSANs(cn, []string{cn}, now.Add(-24*time.Hour), now.Add(90*24*time.Hour))
		createSecret("mc-kvguard-sec", certPEM, keyPEM)

		mc := newManagedCredential("mc-kvguard", "mc-kvguard-sec", "mcp-kvguard", "CN="+cn, []string{cn})
		tnt, app, obj := ownTntID, ownAppID, "kvguard-obj"
		mc.Spec.TenantID = &tnt
		mc.Spec.AppID = &app
		mc.Spec.AppObjectID = &obj
		mc.Spec.KeyVault = &ezcav1.KeyVaultSpec{VaultName: vaultName, CertName: certName}
		// Externally provisioned: with an identityRef the controller would register
		// the certificate itself (see the registration-retry spec) and then sync.
		mc.Spec.IdentityRef = nil
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-kvguard")

		// The cert is not in status.ManagedKeyCredentials (never registered), so Key
		// Vault must be left untouched and the real reason surfaced.
		Expect(entraClient.added).To(BeEmpty(), "nothing to authenticate a registration with")
		Expect(kvClient.matchCalls).To(Equal(0), "Key Vault must not be touched with an unregistered cert")
		Expect(kvClient.imported).To(BeEmpty())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-kvguard"}, mc)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeDegradedCertIdentity)).To(BeTrue())
		Expect(meta.FindStatusCondition(mc.Status.Conditions, typeDegradedCertIdentity).Reason).To(Equal("CertificateNotRegisteredOnApp"))
	})

	It("syncs Key Vault once its certificate is registered on the app", func() {
		createParent("mcp-kvok", "mcp-kvok-sec")
		cn := "kvok.ezca.io"
		certPEM, keyPEM, cert := genCertSANs(cn, []string{cn}, now.Add(-24*time.Hour), now.Add(90*24*time.Hour))
		createSecret("mc-kvok-sec", certPEM, keyPEM)

		mc := newManagedCredential("mc-kvok", "mc-kvok-sec", "mcp-kvok", "CN="+cn, []string{cn})
		tnt, app, obj := ownTntID, ownAppID, "kvok-obj"
		mc.Spec.TenantID = &tnt
		mc.Spec.AppID = &app
		mc.Spec.AppObjectID = &obj
		mc.Spec.KeyVault = &ezcav1.KeyVaultSpec{VaultName: vaultName, CertName: certName}
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		// Record the active cert as registered on the app.
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-kvok"}, mc)).To(Succeed())
		mc.Status.ManagedKeyCredentials = []ezcav1.ManagedKeyCredential{{
			Thumbprint: pki.Thumbprint(cert),
			KeyID:      "k1",
			NotAfter:   metav1.Time{Time: cert.NotAfter},
		}}
		Expect(k8sClient.Status().Update(ctx, mc)).To(Succeed())

		kvClient.matches = false
		reconcileMC("mc-kvok")

		// Registered -> Key Vault sync proceeds (cert differs from vault -> imported).
		Expect(kvClient.imported).To(HaveLen(1))
	})

	It("registers a bootstrapped certificate on its own app via the master cert", func() {
		createParent("mcp-app", "mcp-app-sec")
		_, _, issued := genCertSANs("appboot.ezca.io", []string{"appboot.ezca.io"}, now, now.Add(90*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}

		mc := newManagedCredential("mc-appboot", "mc-appboot-sec", "mcp-app", "CN=appboot.ezca.io", []string{"appboot.ezca.io"})
		tnt, app, obj := ownTntID, ownAppID, "appboot-obj"
		mc.Spec.TenantID = &tnt
		mc.Spec.AppID = &app
		mc.Spec.AppObjectID = &obj
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-appboot")

		Expect(issuerClient.called).To(BeTrue())
		// Bootstrap: no own cert yet, so the master identity's app authenticates
		// both the EZCA issuance and the addKey.
		Expect(credTenant).To(Equal(parentTntID))
		Expect(entraClient.added).To(HaveLen(1))
		Expect(entraClient.added[0]).To(Equal(issued.Raw))

		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-appboot"}, mc)).To(Succeed())
		Expect(mc.Status.ManagedKeyCredentials).To(HaveLen(1))
		Expect(mc.Status.ManagedKeyCredentials[0].Thumbprint).To(Equal(pki.Thumbprint(issued)))
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())

		// No prior serving cert, so the bootstrapped cert is written active.
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-appboot-sec"}, &secret)).To(Succeed())
		Expect(secret.Data).To(HaveKey(tlsCertKey))
		Expect(secret.Data).NotTo(HaveKey("tls.crt.pending"))
	})

	It("refuses to bootstrap from a ClusterCertIdentity that does not allow its namespace", func() {
		// The parent allows only some other namespace, not the credential's.
		certPEM, keyPEM, _ := genCert("parent.ezca.io", now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
		createSecret("mcp-deny-sec", certPEM, keyPEM)
		ezcaURL := testEZCAURL
		tnt, app, obj := parentTntID, parentAppID, parentObjID
		cci := &ezcav1.ClusterCertIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: "mcp-deny"},
			Spec: ezcav1.ClusterCertIdentitySpec{
				CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
					EZCAURL:          &ezcaURL,
					CertSecretName:   "mcp-deny-sec",
					Cloud:            ezcav1.CloudPublic,
					RenewalThreshold: 20,
					TenantID:         &tnt,
					AppID:            &app,
					AppObjectID:      &obj,
				},
				CertSecretNamespace: namespace,
				AllowedNamespaces:   []string{"some-other-namespace"},
			},
		}
		Expect(k8sClient.Create(ctx, cci)).To(Succeed())

		_, _, issued := genCertSANs("deny.ezca.io", []string{"deny.ezca.io"}, now, now.Add(90*24*time.Hour))
		issuerClient.chain = []*x509.Certificate{issued}

		mc := newManagedCredential("mc-deny", "mc-deny-sec", "mcp-deny", "CN=deny.ezca.io", []string{"deny.ezca.io"})
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		reconcileMC("mc-deny")

		// Nothing is issued; the credential is Degraded because the referenced
		// ClusterCertIdentity does not allow this namespace to reference it.
		Expect(issuerClient.called).To(BeFalse())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-deny"}, mc)).To(Succeed())
		cond := meta.FindStatusCondition(mc.Status.Conditions, typeDegradedCertIdentity)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal("IssuanceCredentialUnavailable"))
		// No Secret was written on the credential's behalf.
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "mc-deny-sec"}, &secret)).ShouldNot(Succeed())
	})

	It("maps a Secret change only to ManagedCredentials in the same namespace", func() {
		mc := newManagedCredential("mc-map", sharedSecret, "", "CN=map.ezca.io", []string{"map.ezca.io"})
		mc.Spec.IdentityRef = nil
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())
		want := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: "mc-map"}}

		same := reconciler.secretToRequests(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: sharedSecret}})
		Expect(same).To(ContainElement(want))

		other := reconciler.secretToRequests(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "mc-other-ns", Name: sharedSecret}})
		Expect(other).NotTo(ContainElement(want))
	})

	It("heals when a Secret is not found at first and no identityRef is set", func() {
		mcName := "mc-heals"
		mc := newManagedCredential(mcName, sharedSecret, "", "CN=map.ezca.io", []string{"map.ezca.io"})
		mc.Spec.IdentityRef = nil
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		// First pass: the Secret is missing and the credential cannot
		// self-bootstrap (no identityRef), so it takes the requireBootstrap
		// branch: nothing is issued, it requeues, and it goes Degraded.
		res := reconcileMC(mcName)
		Expect(issuerClient.called).To(BeFalse())
		Expect(ezcaClient.called).To(BeFalse())
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))
		// The controller must not create the Secret on the credential's behalf.
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: sharedSecret}, &secret)).ShouldNot(Succeed())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: mcName}, mc)).To(Succeed())
		cond := meta.FindStatusCondition(mc.Status.Conditions, typeDegradedCertIdentity)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal("CertificateNotBootstrapped"))
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeFalse())
		Expect(mc.Status.Thumbprint).To(BeEmpty())

		// An administrator provisions the certificate into the Secret.
		certPEM, keyPEM, issued := genCert("CN=map.ezca.io", now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
		createSecret(sharedSecret, certPEM, keyPEM)

		// Second pass: the Secret now exists with a valid certificate. Because the
		// credential still has no identityRef it does not re-issue; it adopts the
		// externally provisioned certificate and goes Available.
		reconcileMC(mcName)
		Expect(issuerClient.called).To(BeFalse())
		Expect(ezcaClient.called).To(BeFalse())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: mcName}, mc)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeDegradedCertIdentity)).To(BeFalse())
		// The observed certificate is the one the administrator provisioned.
		Expect(mc.Status.Thumbprint).To(Equal(pki.Thumbprint(issued)))
		Expect(mc.Status.PendingThumbprint).To(BeEmpty())
	})

	It("does not renew when we have not hit the renewal threshold but does when we have", func() {
		mcName := "mc-hits"
		domain := "hits.ezca.io"
		secretName := "mc-secret-hits"
		cn := "CN=" + domain
		mc := newManagedCredential(mcName, secretName, "", cn, []string{domain})
		mc.Spec.IdentityRef = nil
		Expect(k8sClient.Create(ctx, mc)).To(Succeed())

		certPEM, keyPEM, issued := genCert(cn, now.Add(-day), now.Add(year))
		createSecret(secretName, certPEM, keyPEM)

		res := reconcileMC(mcName)
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: mcName}, mc)).To(Succeed())
		Expect(issuerClient.called).To(BeFalse())
		Expect(ezcaClient.called).To(BeFalse())
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))

		// the certificate has not been renewed, no pending
		Expect(mc.Status.Thumbprint).To(Equal(pki.Thumbprint(issued)))
		Expect(mc.Status.PendingThumbprint).To(BeEmpty())

		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())

		// jump forward 364 days
		clockNow = clockNow.Add(364 * day)

		_, _, renewed := genCert(cn, clockNow.Add(-day), clockNow.Add(year))
		ezcaClient.newChain = []*x509.Certificate{renewed}

		reconcileMC(mcName)
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: mcName}, mc)).To(Succeed())
		Expect(issuerClient.called).To(BeFalse())
		Expect(ezcaClient.called).To(BeTrue())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		Expect(meta.IsStatusConditionTrue(mc.Status.Conditions, typeDegradedCertIdentity)).To(BeFalse())
		Expect(mc.Status.Thumbprint).To(Equal(pki.Thumbprint(renewed)))
		Expect(mc.Status.PendingThumbprint).To(BeEmpty())

		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: secretName}, &secret)).Should(Succeed())
		Expect(secret.Data).To(HaveKey(tlsCertKey))
		Expect(secret.Data).To(HaveKey(tlsKeyKey))

		secretPEM := secret.Data[tlsCertKey]
		certs, err := pki.ParseCertChainPEM(secretPEM)
		thumbInSecret := pki.Thumbprint(certs[0])
		renewedThumb := pki.Thumbprint(renewed)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(thumbInSecret).To(Equal(renewedThumb))

		Expect(secret.Data).NotTo(HaveKey(tlsCertPendingKey))
		Expect(secret.Data).NotTo(HaveKey(tlsKeyPendingKey))
	})
})

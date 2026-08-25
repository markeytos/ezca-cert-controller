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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ezcav1 "github.com/markeytos/ezca-cert-controller/api/v1"
	"github.com/markeytos/ezca-cert-controller/internal/entra"
	"github.com/markeytos/ezca-cert-controller/internal/keyvault"
)

var _ = Describe("CertIdentity Controller", func() {
	const namespace = "default"
	now := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	ctx := context.Background()

	var (
		reconciler  *CertIdentityReconciler
		ezcaClient  *fakeEZCA
		entraClient *fakeEntra
		kvClient    *fakeKeyVault
		clockNow    time.Time
	)

	newReconciler := func() *CertIdentityReconciler {
		return &CertIdentityReconciler{
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
		}
	}

	createSecretIn := func(ns, name string, certPEM, keyPEM []byte) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{tlsCertKey: certPEM, tlsKeyKey: keyPEM},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	}

	createCertIdentity := func(ns, name, secretName string, withApp bool) {
		ezcaURL := testEZCAURL
		ci := &ezcav1.CertIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: ezcav1.CertIdentitySpec{
				CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{
					EZCAURL:          &ezcaURL,
					CertSecretName:   secretName,
					Cloud:            ezcav1.CloudPublic,
					RenewalThreshold: 20,
				},
			},
		}
		if withApp {
			tnt, app, obj := testUUID0, testUUID1, testObjectID
			ci.Spec.TenantID = &tnt
			ci.Spec.AppID = &app
			ci.Spec.AppObjectID = &obj
		}
		Expect(k8sClient.Create(ctx, ci)).To(Succeed())
	}

	reconcileCI := func(ns, name string) ctrl.Result {
		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}})
		Expect(err).NotTo(HaveOccurred())
		return res
	}

	getCI := func(ns, name string) *ezcav1.CertIdentity {
		var ci ezcav1.CertIdentity
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &ci)).To(Succeed())
		return &ci
	}

	BeforeEach(func() {
		clockNow = now
		ezcaClient = &fakeEZCA{}
		entraClient = &fakeEntra{}
		kvClient = &fakeKeyVault{}
		reconciler = newReconciler()
	})

	It("does not renew a healthy certificate", func() {
		certPEM, keyPEM, _ := genCert("ci-healthy.ezca.io", now.Add(-10*24*time.Hour), now.Add(90*24*time.Hour))
		createSecretIn(namespace, "ci-healthy-sec", certPEM, keyPEM)
		createCertIdentity(namespace, "ci-healthy", "ci-healthy-sec", false)

		res := reconcileCI(namespace, "ci-healthy")
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))
		Expect(ezcaClient.called).To(BeFalse())

		ci := getCI(namespace, "ci-healthy")
		Expect(meta.IsStatusConditionTrue(ci.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		Expect(ci.Status.NotAfter).NotTo(BeNil())
	})

	It("reports Degraded when the Secret is missing", func() {
		createCertIdentity(namespace, "ci-nosec", "ci-absent-sec", false)

		res := reconcileCI(namespace, "ci-nosec")
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))
		Expect(ezcaClient.called).To(BeFalse())

		ci := getCI(namespace, "ci-nosec")
		Expect(meta.IsStatusConditionTrue(ci.Status.Conditions, typeDegradedCertIdentity)).To(BeTrue())
	})

	It("renews a certificate past the threshold", func() {
		certPEM, keyPEM, _ := genCert("ci-renew.ezca.io", now.Add(-90*24*time.Hour), now.Add(10*24*time.Hour))
		createSecretIn(namespace, "ci-renew-sec", certPEM, keyPEM)
		_, _, renewed := genCert("ci-renew.ezca.io", now, now.Add(365*24*time.Hour))
		ezcaClient.newChain = []*x509.Certificate{renewed}
		createCertIdentity(namespace, "ci-renew", "ci-renew-sec", false)

		reconcileCI(namespace, "ci-renew")

		Expect(ezcaClient.called).To(BeTrue())
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "ci-renew-sec"}, &secret)).To(Succeed())
		chain, _, err := parseSecret(&secret)
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].NotAfter).To(BeTemporally("==", renewed.NotAfter))
	})

	It("resolves the Secret in the CertIdentity's own namespace", func() {
		const ns = "ci-team-a"
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		certPEM, keyPEM, _ := genCert("ci-ns.ezca.io", now.Add(-10*24*time.Hour), now.Add(90*24*time.Hour))
		createSecretIn(ns, "ci-ns-sec", certPEM, keyPEM)
		createCertIdentity(ns, "ci-ns", "ci-ns-sec", false)

		reconcileCI(ns, "ci-ns")

		ci := getCI(ns, "ci-ns")
		Expect(meta.IsStatusConditionTrue(ci.Status.Conditions, typeAvailableCertIdentity)).To(BeTrue())
		Expect(ci.Status.Thumbprint).NotTo(BeEmpty())
	})

	It("maps a Secret change only to CertIdentities in the same namespace", func() {
		createCertIdentity(namespace, "ci-map", "shared-sec", false)
		want := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: "ci-map"}}

		same := reconciler.secretToRequests(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "shared-sec"}})
		Expect(same).To(ContainElement(want))

		other := reconciler.secretToRequests(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ci-other-ns", Name: "shared-sec"}})
		Expect(other).NotTo(ContainElement(want))
	})
})

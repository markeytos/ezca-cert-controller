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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ezcav1 "github.com/markeytos/ezca-cert-controller/api/v1"
	"github.com/markeytos/ezca-cert-controller/internal/telemetry"
)

const ezcaGroupFinalizer = "ezca.keytos.io/finalizer"

// ClusterCertIdentityReconciler reconciles a ClusterCertIdentity object
type ClusterCertIdentityReconciler struct {
	ReconcilerBase

	// DefaultNamespace is the namespace used for the certificate Secret when the
	// spec does not set one (the namespace the controller runs in).
	DefaultNamespace string
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
		if controllerutil.RemoveFinalizer(&cci, ezcaGroupFinalizer) {
			if err := r.Update(ctx, &cci); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if controllerutil.AddFinalizer(&cci, ezcaGroupFinalizer) {
		if err := r.Update(ctx, &cci); err != nil {
			return ctrl.Result{}, err
		}
	}

	tel := telemetry.New(cci.Spec.AppInsightsConnString)
	defer tel.Flush(10 * time.Second)

	originalStatus := cci.Status.DeepCopy()
	result, reconcileErr := r.reconcile(ctx, &cci, tel)

	// Only write status when it actually changed, so a steady-state reconcile
	// does not trigger itself through the ClusterCertIdentity watch.
	if !equality.Semantic.DeepEqual(originalStatus, &cci.Status) {
		if err := r.Status().Update(ctx, &cci); err != nil {
			log.Error(err, "Failed to update ClusterCertIdentity status")
			if reconcileErr == nil {
				reconcileErr = err
			}
		}
	}
	// Never return both a non-zero result and a non-nil error: controller-runtime
	// ignores the result when the error is non-nil (requeuing with backoff) and
	// warns when both are set.
	if reconcileErr != nil {
		return ctrl.Result{}, reconcileErr
	}
	return result, nil
}

// reconcile loads the certificate Secret, runs the certificate state machine,
// then optionally mirrors the active certificate into Azure Key Vault.
func (r *ClusterCertIdentityReconciler) reconcile(ctx context.Context, cci *ezcav1.ClusterCertIdentity, tel *telemetry.Telemetry) (ctrl.Result, error) {
	secretNS := cci.Spec.CertSecretNamespace
	if secretNS == "" {
		secretNS = r.DefaultNamespace
	}
	if secretNS == "" {
		setDegraded(cci, "NamespaceUnresolved", "Could not resolve the certificate Secret namespace; set spec.certSecretNamespace or POD_NAMESPACE")
		return ctrl.Result{}, nil
	}

	var secret corev1.Secret
	secretName := types.NamespacedName{Namespace: secretNS, Name: cci.Spec.CertSecretName}
	if err := r.Get(ctx, secretName, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			setDegraded(cci, "CertificateNotBootstrapped",
				fmt.Sprintf("Certificate Secret %s not found; an administrator must bootstrap it", secretName))
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
		return ctrl.Result{}, err
	}

	chain, key, err := parseSecret(&secret)
	if err != nil {
		setDegraded(cci, "InvalidCertificate", fmt.Sprintf("Certificate Secret %s is invalid: %v", secretName, err))
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	now := r.now()
	setObservedCert(cci, chain[0])

	result, coreErr := reconcileCertState(ctx, r, cci, &secret, chain, key, now, tel)

	if cci.Spec.KeyVault != nil {
		syncKeyVaultBestEffort(ctx, r, cci, &secret, now, tel, &result, coreErr)
	}
	return result, coreErr
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

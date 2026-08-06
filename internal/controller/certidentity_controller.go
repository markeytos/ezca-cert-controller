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

// CertIdentityReconciler reconciles a CertIdentity object
type CertIdentityReconciler struct {
	ReconcilerBase
}

// +kubebuilder:rbac:groups=ezca.keytos.io,resources=certidentities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ezca.keytos.io,resources=certidentities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ezca.keytos.io,resources=certidentities/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch

func (r *CertIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var ci ezcav1.CertIdentity
	if err := r.Get(ctx, req.NamespacedName, &ci); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("CertIdentity resource not found, must have been deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get CertIdentity")
		return ctrl.Result{}, err
	}

	// Handle deletion: release the finalizer, leaving any managed app
	// certificates in place (they expire on their own).
	if !ci.DeletionTimestamp.IsZero() {
		if controllerutil.RemoveFinalizer(&ci, ezcaGroupFinalizer) {
			if err := r.Update(ctx, &ci); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if controllerutil.AddFinalizer(&ci, ezcaGroupFinalizer) {
		if err := r.Update(ctx, &ci); err != nil {
			return ctrl.Result{}, err
		}
	}

	tel := telemetry.New(ci.Spec.AppInsightsConnString)
	defer tel.Flush(10 * time.Second)

	result, reconcileErr := r.reconcile(ctx, &ci, tel)

	if err := r.Status().Update(ctx, &ci); err != nil {
		log.Error(err, "Failed to update CertIdentity status")
		if reconcileErr == nil {
			reconcileErr = err
		}
	}
	return result, reconcileErr
}

// reconcile loads the certificate Secret, runs the certificate state machine,
// then optionally mirrors the active certificate into Azure Key Vault.
func (r *CertIdentityReconciler) reconcile(ctx context.Context, ci *ezcav1.CertIdentity, tel *telemetry.Telemetry) (ctrl.Result, error) {
	var secret corev1.Secret
	secretName := types.NamespacedName{Namespace: ci.Namespace, Name: ci.Spec.CertSecretName}
	if err := r.Get(ctx, secretName, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			setDegraded(ci, "CertificateNotBootstrapped",
				fmt.Sprintf("Certificate Secret %s not found; an administrator must bootstrap it", secretName))
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
		return ctrl.Result{}, err
	}

	chain, key, err := parseSecret(&secret)
	if err != nil {
		setDegraded(ci, "InvalidCertificate", fmt.Sprintf("Certificate Secret %s is invalid: %v", secretName, err))
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	now := r.now()
	setObservedCert(ci, chain[0])

	result, coreErr := reconcileCertState(ctx, r, ci, &secret, chain, key, now, tel)

	if ci.Spec.KeyVault != nil {
		syncKeyVaultBestEffort(ctx, r, ci, &secret, now, tel, &result, coreErr)
	}
	return result, coreErr
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ezcav1.CertIdentity{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.secretToRequests)).
		Named("certidentity").
		Complete(r)
}

// secretToRequests maps a changed Secret to the CertIdentities in the same
// namespace that reference it, so external edits to the bootstrapped
// certificate trigger a reconcile. A CertIdentity's Secret always lives in the
// CertIdentity's own namespace.
func (r *CertIdentityReconciler) secretToRequests(ctx context.Context, obj client.Object) []reconcile.Request {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	var list ezcav1.CertIdentityList
	if err := r.List(ctx, &list, client.InNamespace(secret.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		ci := &list.Items[i]
		if ci.Spec.CertSecretName == secret.Name {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ci.Namespace, Name: ci.Name}})
		}
	}
	return reqs
}

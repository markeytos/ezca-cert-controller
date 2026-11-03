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
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	ezcav1 "github.com/markeytos/ezca-cert-controller/api/v1"
	"github.com/markeytos/ezca-cert-controller/internal/telemetry"
)

const (
	// secretReplicaLabel marks a Secret the controller wrote as a copy of a
	// ClusterCertIdentity's certificate Secret (spec.secretReplicas).
	secretReplicaLabel      = "ezca.keytos.io/secret-replica"
	secretReplicaLabelValue = "true"
	// secretReplicaOfAnnotation names the ClusterCertIdentity a copy belongs
	// to, deciding which identity keeps a copy two of them claim. It is an
	// annotation rather than the label's value because a ClusterCertIdentity
	// name can exceed the 63-character label value limit. Being plain
	// metadata, it never authorizes a delete on its own: the copy must also
	// still have the UID recorded in status.secretReplicas.
	secretReplicaOfAnnotation = "ezca.keytos.io/replica-of"

	// typeSecretReplicasSynced reports whether every copy listed in
	// spec.secretReplicas holds the active certificate. It is kept apart from
	// Available and Degraded, which describe the certificate itself.
	typeSecretReplicasSynced = "SecretReplicasSynced"

	// replicaRaceRequeue is how soon a replica write that lost a race with the
	// informer cache is retried.
	replicaRaceRequeue = 5 * time.Second
	// replicaFailureRequeue is how soon a failed replica sync is retried. It
	// is longer than the Key Vault retry because a pass re-runs the whole
	// reconcile, Azure calls included, for what is usually a configuration
	// problem (a missing namespace or a Secret in the way). Changes to a
	// listed copy are watched and retried straight away.
	replicaFailureRequeue = 5 * time.Minute
)

// errCertificateSecretUnusable is reported for the copies while the
// certificate Secret cannot be read or parsed, so they cannot be synced.
var errCertificateSecretUnusable = errors.New("the certificate Secret is missing or invalid; the copies keep their last certificate")

// replicaSync collects the outcome of one pass over an identity's replicas.
type replicaSync struct {
	errs []error
	// raced is set when a write lost a race with the informer cache (it saw
	// a stale object, so the API server answered AlreadyExists or Conflict).
	// That is retried soon rather than reported as a failure.
	raced bool
}

func (s *replicaSync) add(err error) {
	if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
		s.raced = true
		return
	}
	s.errs = append(s.errs, err)
}

// isSecretReplica reports whether secret is a copy a ClusterCertIdentity keeps
// (spec.secretReplicas). The identity overwrites a copy whenever it changes,
// so no identity may use one as its own certificate Secret.
func isSecretReplica(secret *corev1.Secret) bool {
	return secret.Labels[secretReplicaLabel] == secretReplicaLabelValue
}

// refuseReplicaSecret reports that obj's certificate Secret is a replica. The
// Secret watch reconciles obj again once the Secret changes.
func refuseReplicaSecret(obj certIdentity, secret *corev1.Secret) {
	setDegraded(obj, "CertificateSecretIsReplica", fmt.Sprintf(
		"Certificate Secret %s/%s is a copy kept by ClusterCertIdentity %q (spec.secretReplicas); it is renewed through that identity, so it cannot be used as a certificate Secret",
		secret.Namespace, secret.Name, secret.Annotations[secretReplicaOfAnnotation]))
}

// pruneSecretReplicas deletes the copies the controller recorded writing that
// are no longer listed in spec.secretReplicas. A recorded copy is deleted only
// while it still has the recorded UID and is still marked as this identity's
// copy; otherwise it is no longer the controller's, and is forgotten instead.
func (r *ClusterCertIdentityReconciler) pruneSecretReplicas(ctx context.Context, cci *ezcav1.ClusterCertIdentity, rs *replicaSync) {
	cci.Status.SecretReplicas = slices.DeleteFunc(cci.Status.SecretReplicas, func(rec ezcav1.SecretReplicaStatus) bool {
		if replicaListed(cci, rec.Namespace, rec.Name) {
			return false
		}
		forget, err := r.deleteSecretReplica(ctx, cci, rec)
		if err != nil {
			rs.add(fmt.Errorf("failed to delete Secret replica %s/%s: %w", rec.Namespace, rec.Name, err))
		}
		return forget
	})
}

// deleteSecretReplica deletes one recorded copy, reporting whether its record
// can be dropped.
func (r *ClusterCertIdentityReconciler) deleteSecretReplica(ctx context.Context, cci *ezcav1.ClusterCertIdentity, rec ezcav1.SecretReplicaStatus) (bool, error) {
	log := logf.FromContext(ctx)
	key := types.NamespacedName{Namespace: rec.Namespace, Name: rec.Name}
	uid := rec.UID
	preconditions := client.Preconditions{UID: &uid}

	var current corev1.Secret
	err := r.Get(ctx, key, &current)
	switch {
	case apierrors.IsNotFound(err):
		// The cache may not have seen a copy created moments ago; let the API
		// server decide by UID.
	case err != nil:
		return false, err
	case current.UID != rec.UID || !isSecretReplica(&current) || current.Annotations[secretReplicaOfAnnotation] != cci.Name:
		log.Info("Not deleting Secret replica that is no longer this identity's copy", "namespace", key.Namespace, "name", key.Name)
		return true, nil
	default:
		// Delete only the version that was checked, so a copy unmarked in
		// the meantime survives.
		rv := current.ResourceVersion
		preconditions.ResourceVersion = &rv
	}

	stale := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}
	err = r.Delete(ctx, stale, preconditions)
	switch {
	case err == nil:
		log.Info("Deleted Secret replica", "namespace", key.Namespace, "name", key.Name)
		return true, nil
	case apierrors.IsNotFound(err):
		return true, nil
	case apierrors.IsConflict(err) && preconditions.ResourceVersion == nil:
		// The UID no longer matches: something else took the name.
		return true, nil
	default:
		return false, err
	}
}

// syncSecretReplicas writes the active certificate of the source Secret into
// every copy listed in spec.secretReplicas.
func (r *ClusterCertIdentityReconciler) syncSecretReplicas(ctx context.Context, cci *ezcav1.ClusterCertIdentity, source types.NamespacedName, tel *telemetry.Telemetry, rs *replicaSync) {
	if len(cci.Spec.SecretReplicas) == 0 {
		return
	}
	// Read the Secret as stored rather than the copy the state machine wrote
	// through, so a write that failed part-way is never replicated. A cached
	// read can trail the controller's own write; the write's watch event then
	// brings the copies up to date on the next reconcile.
	var src corev1.Secret
	if err := r.Get(ctx, source, &src); err != nil {
		rs.add(fmt.Errorf("failed to read certificate Secret %s: %w", source, err))
		return
	}
	if _, _, err := parseSecret(&src); err != nil {
		rs.add(fmt.Errorf("%w: %v", errCertificateSecretUnusable, err))
		return
	}
	data := map[string][]byte{tlsCertKey: src.Data[tlsCertKey], tlsKeyKey: src.Data[tlsKeyKey]}
	for _, rep := range cci.Spec.SecretReplicas {
		key := types.NamespacedName{Namespace: rep.Namespace, Name: rep.Name}
		if key == source {
			rs.add(fmt.Errorf("secret replica %s is the certificate Secret itself", key))
			continue
		}
		if err := r.writeSecretReplica(ctx, cci, key, data, tel); err != nil {
			rs.add(fmt.Errorf("secret replica %s: %w", key, err))
		}
	}
}

// writeSecretReplica creates or updates one copy with data and records its
// UID. An existing Secret is overwritten only when checkWritable allows it.
func (r *ClusterCertIdentityReconciler) writeSecretReplica(ctx context.Context, cci *ezcav1.ClusterCertIdentity, key types.NamespacedName, data map[string][]byte, tel *telemetry.Telemetry) error {
	log := logf.FromContext(ctx)

	var existing corev1.Secret
	err := r.Get(ctx, key, &existing)
	if apierrors.IsNotFound(err) {
		replica := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        key.Name,
				Namespace:   key.Namespace,
				Labels:      map[string]string{secretReplicaLabel: secretReplicaLabelValue},
				Annotations: map[string]string{secretReplicaOfAnnotation: cci.Name},
			},
			Type: corev1.SecretTypeTLS,
			Data: data,
		}
		if err := r.Create(ctx, replica); err != nil {
			return err
		}
		recordSecretReplica(cci, key, replica.UID)
		log.Info("Created Secret replica", "namespace", key.Namespace, "name", key.Name)
		tel.TrackEvent("SecretReplicaUpdated", identityProps(cci))
		return nil
	}
	if err != nil {
		return err
	}

	if existing.Type != corev1.SecretTypeTLS {
		return fmt.Errorf("already exists with type %s; a copy must be %s, so it is left untouched", existing.Type, corev1.SecretTypeTLS)
	}
	if err := r.checkWritable(ctx, cci, &existing, replicaRecorded(cci, key, existing.UID)); err != nil {
		return err
	}
	if isSecretReplica(&existing) &&
		existing.Annotations[secretReplicaOfAnnotation] == cci.Name &&
		maps.EqualFunc(existing.Data, data, bytes.Equal) {
		recordSecretReplica(cci, key, existing.UID)
		return nil
	}
	if existing.Labels == nil {
		existing.Labels = map[string]string{}
	}
	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	existing.Labels[secretReplicaLabel] = secretReplicaLabelValue
	existing.Annotations[secretReplicaOfAnnotation] = cci.Name
	existing.Data = data
	if err := r.Update(ctx, &existing); err != nil {
		return err
	}
	recordSecretReplica(cci, key, existing.UID)
	log.Info("Updated Secret replica", "namespace", key.Namespace, "name", key.Name)
	tel.TrackEvent("SecretReplicaUpdated", identityProps(cci))
	return nil
}

// checkWritable returns an error unless cci may write its copy over an
// existing Secret. A Secret it has no record of writing must be marked as a
// copy (status is lost when an identity is recreated). Whether recorded or
// not, a copy marked for another ClusterCertIdentity is written only once that
// identity no longer lists or records it: a renamed identity leaves its copies
// behind, and a copy whose record was never written is claimed by no one. A
// copy two identities both claim is otherwise left to the one it names, so the
// two never overwrite it in turn.
func (r *ClusterCertIdentityReconciler) checkWritable(ctx context.Context, cci *ezcav1.ClusterCertIdentity, existing *corev1.Secret, recorded bool) error {
	owner := existing.Annotations[secretReplicaOfAnnotation]
	if !recorded && (!isSecretReplica(existing) || owner == "") {
		return errors.New("already exists and was not written by the controller as a copy; it is left untouched")
	}
	if owner == "" || owner == cci.Name {
		return nil
	}
	var other ezcav1.ClusterCertIdentity
	err := r.Get(ctx, types.NamespacedName{Name: owner}, &other)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if err == nil && replicaTracked(&other, client.ObjectKeyFromObject(existing)) {
		return fmt.Errorf("already exists as a copy for ClusterCertIdentity %q", owner)
	}
	logf.FromContext(ctx).Info("Taking over Secret replica no longer claimed by its ClusterCertIdentity",
		"namespace", existing.Namespace, "name", existing.Name, "previousOwner", owner)
	return nil
}

// reportSecretReplicas sets the SecretReplicasSynced condition from this
// pass's replica sync and retries a failure within replicaFailureRequeue. A pass that only
// lost races with the cache is retried soon and leaves the condition alone.
// The condition is dropped once no copies are listed or recorded.
func reportSecretReplicas(ctx context.Context, cci *ezcav1.ClusterCertIdentity, rs *replicaSync, tel *telemetry.Telemetry, result *ctrl.Result) {
	status := &cci.Status
	if err := errors.Join(rs.errs...); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to sync certificate Secret replicas")
		tel.TrackError(err, "Failed to sync certificate Secret replicas", identityProps(cci))
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type:    typeSecretReplicasSynced,
			Status:  metav1.ConditionFalse,
			Reason:  "SecretReplicationFailed",
			Message: fmt.Sprintf("Failed to sync certificate Secret replicas: %s", conditionError(err)),
		})
		requeueAtMost(result, replicaFailureRequeue)
		return
	}
	if rs.raced {
		requeueAtMost(result, replicaRaceRequeue)
		return
	}
	if len(cci.Spec.SecretReplicas) == 0 && len(status.SecretReplicas) == 0 {
		meta.RemoveStatusCondition(&status.Conditions, typeSecretReplicasSynced)
		return
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:    typeSecretReplicasSynced,
		Status:  metav1.ConditionTrue,
		Reason:  "Synced",
		Message: "Every Secret replica holds the active certificate",
	})
}

// blockSecretReplicas records, for a pass that stopped before the certificate
// Secret could be used, that the listed copies could not be synced.
func blockSecretReplicas(cci *ezcav1.ClusterCertIdentity, rs *replicaSync) {
	if len(cci.Spec.SecretReplicas) > 0 {
		rs.add(errCertificateSecretUnusable)
	}
}

func replicaListed(cci *ezcav1.ClusterCertIdentity, namespace, name string) bool {
	return slices.ContainsFunc(cci.Spec.SecretReplicas, func(rep ezcav1.SecretReplica) bool {
		return rep.Namespace == namespace && rep.Name == name
	})
}

// replicaTracked reports whether cci lists or has recorded a copy at key.
func replicaTracked(cci *ezcav1.ClusterCertIdentity, key types.NamespacedName) bool {
	return replicaListed(cci, key.Namespace, key.Name) || slices.ContainsFunc(cci.Status.SecretReplicas, func(rec ezcav1.SecretReplicaStatus) bool {
		return rec.Namespace == key.Namespace && rec.Name == key.Name
	})
}

func replicaRecorded(cci *ezcav1.ClusterCertIdentity, key types.NamespacedName, uid types.UID) bool {
	return slices.ContainsFunc(cci.Status.SecretReplicas, func(rec ezcav1.SecretReplicaStatus) bool {
		return rec.Namespace == key.Namespace && rec.Name == key.Name && rec.UID == uid
	})
}

// recordSecretReplica records uid as the copy at key, replacing any earlier
// record for that key.
func recordSecretReplica(cci *ezcav1.ClusterCertIdentity, key types.NamespacedName, uid types.UID) {
	if replicaRecorded(cci, key, uid) {
		return
	}
	cci.Status.SecretReplicas = slices.DeleteFunc(cci.Status.SecretReplicas, func(rec ezcav1.SecretReplicaStatus) bool {
		return rec.Namespace == key.Namespace && rec.Name == key.Name
	})
	cci.Status.SecretReplicas = append(cci.Status.SecretReplicas, ezcav1.SecretReplicaStatus{
		Namespace: key.Namespace, Name: key.Name, UID: uid,
	})
}

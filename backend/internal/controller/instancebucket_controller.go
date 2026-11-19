package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/openeverest/plugin-user-management/backend/api/v1alpha1"
	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

// BucketFinalizer releases or drops a bucket before its InstanceBucket goes away.
const BucketFinalizer = "plugin-user-management.plugins.openeverest.io/release-bucket"

// BucketReconciler reconciles all InstanceBuckets of an instance at once.
type BucketReconciler struct {
	Client client.Client
	Reader client.Reader
	// Engines by provider name. Only BucketEngine implementations manage buckets.
	Engines map[string]engine.Engine
	// MaxConcurrentReconciles is how many instances are reconciled at once.
	MaxConcurrentReconciles int
}

// IndexBucketInstance registers the InstanceIndex for InstanceBuckets.
func IndexBucketInstance(ctx context.Context, mgr ctrl.Manager) error {
	return mgr.GetFieldIndexer().IndexField(ctx, &v1alpha1.InstanceBucket{}, InstanceIndex, func(obj client.Object) []string {
		bucket, ok := obj.(*v1alpha1.InstanceBucket)
		if !ok {
			return nil
		}
		return []string{bucket.Spec.InstanceRef.Name}
	})
}

func (r *BucketReconciler) SetupWithManager(mgr ctrl.Manager) error {
	byInstance := func(name string, obj client.Object) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: obj.GetNamespace(), Name: name}}}
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("instancebucket").
		WithOptions(ctrlcontroller.Options{MaxConcurrentReconciles: r.MaxConcurrentReconciles}).
		Watches(&v1alpha1.InstanceBucket{}, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, obj client.Object) []reconcile.Request {
				bucket, ok := obj.(*v1alpha1.InstanceBucket)
				if !ok {
					return nil
				}
				return byInstance(bucket.Spec.InstanceRef.Name, bucket)
			})).
		Watches(&v1alpha1.InstanceUser{}, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, obj client.Object) []reconcile.Request {
				user, ok := obj.(*v1alpha1.InstanceUser)
				if !ok {
					return nil
				}
				return byInstance(user.Spec.InstanceRef.Name, user)
			})).
		Complete(r)
}

type bucketState struct {
	bucket       *v1alpha1.InstanceBucket
	owner        string
	phase        string
	message      string
	declared     bool
	available    bool
	ownerProblem string
	ownerInvalid bool
}

func (s *bucketState) fail(message string)    { s.phase, s.message = v1alpha1.PhaseFailed, message }
func (s *bucketState) pending(message string) { s.phase, s.message = v1alpha1.PhasePending, message }

func (r *BucketReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var list v1alpha1.InstanceBucketList
	if err := r.Client.List(ctx, &list, client.InNamespace(req.Namespace), client.MatchingFields{InstanceIndex: req.Name}); err != nil {
		return ctrl.Result{}, err
	}
	if len(list.Items) == 0 {
		return ctrl.Result{}, nil
	}
	sort.Slice(list.Items, func(i, j int) bool {
		a, b := list.Items[i], list.Items[j]
		if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
			return a.CreationTimestamp.Before(&b.CreationTimestamp)
		}
		return a.Name < b.Name
	})
	var live, deleting []*v1alpha1.InstanceBucket
	for i := range list.Items {
		if list.Items[i].DeletionTimestamp.IsZero() {
			live = append(live, &list.Items[i])
		} else {
			deleting = append(deleting, &list.Items[i])
		}
	}

	instance := &unstructured.Unstructured{}
	instance.SetGroupVersionKind(InstanceGVK)
	if err := r.Client.Get(ctx, req.NamespacedName, instance); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, r.abandon(ctx, live, deleting, fmt.Sprintf("instance %q not found", req.Name))
	}
	if !instance.GetDeletionTimestamp().IsZero() {
		return ctrl.Result{}, r.abandon(ctx, live, deleting, fmt.Sprintf("instance %q is being deleted", req.Name))
	}
	provider, _, _ := unstructured.NestedString(instance.Object, "spec", "providerRef", "name")
	eng, ok := r.Engines[provider].(engine.BucketEngine)
	if !ok {
		return ctrl.Result{}, r.abandon(ctx, live, deleting, fmt.Sprintf("buckets are not supported for provider %q", provider))
	}
	target := engine.Target{Namespace: req.Namespace, Instance: req.Name}

	states := make([]*bucketState, 0, len(live))
	names := map[string]bool{}
	for _, bucket := range live {
		if err := ensureInstanceMetadata(ctx, r.Client, bucket, instance, BucketFinalizer); err != nil {
			return ctrl.Result{}, err
		}
		state := &bucketState{
			bucket: bucket, declared: bucket.Status.Declared, available: bucket.Status.Available,
		}
		states = append(states, state)
		if err := eng.ValidateBucket(bucket.Spec.Name); err != nil {
			state.fail(err.Error())
			continue
		}
		if names[bucket.Spec.Name] {
			state.fail(fmt.Sprintf("another InstanceBucket already declares bucket %q on this instance", bucket.Spec.Name))
			continue
		}
		names[bucket.Spec.Name] = true
		owner, err := r.owner(ctx, bucket)
		var pending errOwnerPending
		var invalid errOwnerInvalid
		switch {
		case errors.As(err, &invalid):
			state.ownerProblem, state.ownerInvalid = invalid.Error(), true
		case errors.As(err, &pending):
			state.ownerProblem = pending.Error()
		case err != nil:
			return ctrl.Result{}, err
		}
		if owner != nil {
			state.owner = owner.Spec.Username
		}
	}

	result, err := r.syncBuckets(ctx, eng, target, states, deleting)
	if err != nil {
		return ctrl.Result{}, err
	}
	for _, state := range states {
		if err := r.writeStatus(ctx, state); err != nil {
			return ctrl.Result{}, err
		}
		if state.phase == v1alpha1.PhasePending {
			result.RequeueAfter = pendingRequeue
		}
	}
	return withResync(result, eng, len(states) > 0), nil
}

func (r *BucketReconciler) owner(ctx context.Context, bucket *v1alpha1.InstanceBucket) (*v1alpha1.InstanceUser, error) {
	if bucket.Spec.Owner == nil {
		return nil, nil
	}
	name := bucket.Spec.Owner.InstanceUserRef.Name
	user := &v1alpha1.InstanceUser{}
	err := r.Client.Get(ctx, types.NamespacedName{Namespace: bucket.Namespace, Name: name}, user)
	if apierrors.IsNotFound(err) {
		return nil, errOwnerPending(fmt.Sprintf("owner InstanceUser %q not found", name))
	}
	if err != nil {
		return nil, err
	}
	if user.Spec.InstanceRef.Name != bucket.Spec.InstanceRef.Name {
		return nil, errOwnerInvalid(fmt.Sprintf("owner InstanceUser %q belongs to instance %q", name, user.Spec.InstanceRef.Name))
	}
	if !user.DeletionTimestamp.IsZero() {
		return nil, errOwnerPending(fmt.Sprintf("owner InstanceUser %q is being deleted", name))
	}
	if !user.Status.Declared {
		return nil, errOwnerPending(fmt.Sprintf("waiting for owner InstanceUser %q to be created", name))
	}
	return user, nil
}

func (r *BucketReconciler) syncBuckets(
	ctx context.Context,
	eng engine.BucketEngine,
	target engine.Target,
	states []*bucketState,
	deleting []*v1alpha1.InstanceBucket,
) (ctrl.Result, error) {
	buckets, err := eng.ListBuckets(ctx, target)
	if err != nil {
		if !errors.Is(err, engine.ErrNotReady) {
			return ctrl.Result{}, err
		}
		for _, state := range states {
			if state.phase == "" {
				state.pending(err.Error())
			}
		}
		for _, bucket := range deleting {
			declared, err := r.declared(ctx, bucket)
			if err != nil {
				return ctrl.Result{}, err
			}
			if !declared {
				if err := removeFinalizer(ctx, r.Client, bucket, BucketFinalizer); err != nil {
					return ctrl.Result{}, err
				}
			}
		}
		return ctrl.Result{RequeueAfter: pendingRequeue}, nil
	}
	existing := map[string]engine.Bucket{}
	for _, bucket := range buckets {
		existing[bucket.Name] = bucket
	}
	claimed := map[string]bool{}
	for _, state := range states {
		if state.phase != "" {
			continue
		}
		name := state.bucket.Spec.Name
		if found, ok := existing[name]; ok && !state.declared {
			wasClaimed, err := r.declared(ctx, state.bucket)
			if err != nil {
				return ctrl.Result{}, err
			}
			if !wasClaimed {
				if found.System {
					state.fail(fmt.Sprintf("bucket %q is reserved for the operator", name))
				} else {
					state.fail(fmt.Sprintf("bucket %q already exists and isn't managed by this InstanceBucket", name))
				}
				continue
			}
			state.declared = true
		}
		if state.ownerProblem != "" {
			if state.ownerInvalid {
				state.fail(state.ownerProblem)
			} else {
				state.pending(state.ownerProblem)
			}
			continue
		}
		if !state.declared {
			state.declared = true
			if err := r.patchStatus(ctx, state.bucket, func(status *v1alpha1.InstanceBucketStatus) {
				status.Declared = true
			}); err != nil {
				return ctrl.Result{}, err
			}
		}
		claimed[name] = true
		err := eng.SyncBucket(ctx, target, engine.DesiredBucket{Name: name, Owner: state.owner})
		switch {
		case errors.Is(err, engine.ErrInvalid):
			state.fail(err.Error())
		case errors.Is(err, engine.ErrInProgress), errors.Is(err, engine.ErrNotReady):
			state.pending(err.Error())
		case err != nil:
			return ctrl.Result{}, fmt.Errorf("sync bucket %q: %w", name, err)
		default:
			state.available = true
			if found, ok := existing[name]; ok && found.Owner == state.owner {
				state.phase = v1alpha1.PhaseReady
			} else {
				state.pending("waiting for the bucket to be created")
			}
		}
	}

	var result ctrl.Result
	for _, bucket := range deleting {
		declared, err := r.declared(ctx, bucket)
		if err != nil {
			return ctrl.Result{}, err
		}
		if declared && !claimed[bucket.Spec.Name] {
			drop := bucket.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete
			err := eng.ReleaseBucket(ctx, target, bucket.Spec.Name, drop)
			if errors.Is(err, engine.ErrInProgress) {
				state := &bucketState{
					bucket: bucket, declared: true, owner: bucket.Status.Owner,
					phase: v1alpha1.PhaseDeleting, message: err.Error(),
				}
				if err := r.writeStatus(ctx, state); err != nil {
					return ctrl.Result{}, err
				}
				result.RequeueAfter = pendingRequeue
				continue
			}
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("release bucket %q: %w", bucket.Spec.Name, err)
			}
			log.FromContext(ctx).Info("released bucket", "bucket", bucket.Spec.Name, "dropped", drop, "instanceBucket", bucket.Name)
		}
		if err := removeFinalizer(ctx, r.Client, bucket, BucketFinalizer); err != nil {
			return ctrl.Result{}, err
		}
	}
	return result, nil
}

func (r *BucketReconciler) declared(ctx context.Context, bucket *v1alpha1.InstanceBucket) (bool, error) {
	if bucket.Status.Declared {
		return true, nil
	}
	reader := r.Reader
	if reader == nil {
		reader = r.Client
	}
	live := &v1alpha1.InstanceBucket{}
	if err := reader.Get(ctx, client.ObjectKeyFromObject(bucket), live); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if live.UID != bucket.UID {
		return false, nil
	}
	bucket.Status.Declared = live.Status.Declared
	return live.Status.Declared, nil
}

func (r *BucketReconciler) abandon(
	ctx context.Context,
	live, deleting []*v1alpha1.InstanceBucket,
	message string,
) error {
	for _, bucket := range deleting {
		if err := removeFinalizer(ctx, r.Client, bucket, BucketFinalizer); err != nil {
			return err
		}
	}
	for _, bucket := range live {
		state := &bucketState{
			bucket: bucket, declared: bucket.Status.Declared, owner: bucket.Status.Owner,
		}
		state.fail(message)
		if err := r.writeStatus(ctx, state); err != nil {
			return err
		}
	}
	return nil
}

func (r *BucketReconciler) patchStatus(
	ctx context.Context,
	bucket *v1alpha1.InstanceBucket,
	mutate func(*v1alpha1.InstanceBucketStatus),
) error {
	orig := bucket.DeepCopy()
	mutate(&bucket.Status)
	return client.IgnoreNotFound(r.Client.Status().Patch(ctx, bucket, client.MergeFrom(orig)))
}

func (r *BucketReconciler) writeStatus(ctx context.Context, state *bucketState) error {
	bucket := state.bucket
	return r.patchStatus(ctx, bucket, func(status *v1alpha1.InstanceBucketStatus) {
		status.Phase = state.phase
		status.Message = state.message
		status.Declared = state.declared
		status.Available = status.Available || state.available
		status.Owner = state.owner
		status.ObservedGeneration = bucket.Generation
		condition := metav1.Condition{
			Type:               v1alpha1.ConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             state.phase,
			Message:            state.message,
			ObservedGeneration: bucket.Generation,
		}
		if state.phase == v1alpha1.PhaseReady {
			condition.Status = metav1.ConditionTrue
		}
		meta.SetStatusCondition(&status.Conditions, condition)
	})
}

package controller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/openeverest/plugin-user-management/backend/api/v1alpha1"
	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

type bucketRelease struct {
	name string
	drop bool
}

type fakeBucketEngine struct {
	fakeEngine
	buckets       []engine.Bucket
	listErr       error
	syncErr       error
	releaseErr    error
	syncedBuckets []engine.DesiredBucket
	released      []bucketRelease
}

func (f *fakeBucketEngine) ValidateBucket(name string) error {
	if name == "Invalid" {
		return errors.Join(engine.ErrInvalid, errors.New("invalid bucket name"))
	}
	return nil
}

func (f *fakeBucketEngine) ListBuckets(context.Context, engine.Target) ([]engine.Bucket, error) {
	return f.buckets, f.listErr
}

func (f *fakeBucketEngine) SyncBucket(_ context.Context, _ engine.Target, bucket engine.DesiredBucket) error {
	f.syncedBuckets = append(f.syncedBuckets, bucket)
	return f.syncErr
}

func (f *fakeBucketEngine) ReleaseBucket(
	_ context.Context,
	_ engine.Target,
	name string,
	drop bool,
) error {
	f.released = append(f.released, bucketRelease{name, drop})
	return f.releaseErr
}

func instanceBucket(name, bucket, owner string) *v1alpha1.InstanceBucket {
	created = created.Add(time.Minute)
	obj := &v1alpha1.InstanceBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, CreationTimestamp: metav1.NewTime(created),
		},
		Spec: v1alpha1.InstanceBucketSpec{
			InstanceRef: v1alpha1.InstanceReference{Name: "mongo"},
			Name:        bucket,
		},
	}
	if owner != "" {
		obj.Spec.Owner = &v1alpha1.BucketOwner{
			InstanceUserRef: v1alpha1.InstanceUserReference{Name: owner},
		}
	}
	return obj
}

type bucketHarness struct {
	t      *testing.T
	client client.Client
	engine *fakeBucketEngine
	r      *BucketReconciler
}

func newBucketHarness(t *testing.T, objs ...client.Object) *bucketHarness {
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.InstanceUser{}, &v1alpha1.InstanceBucket{}).
		WithIndex(&v1alpha1.InstanceBucket{}, InstanceIndex, func(obj client.Object) []string {
			return []string{obj.(*v1alpha1.InstanceBucket).Spec.InstanceRef.Name}
		}).
		Build()
	eng := &fakeBucketEngine{}
	return &bucketHarness{
		t: t, client: c, engine: eng,
		r: &BucketReconciler{
			Client:  c,
			Engines: map[string]engine.Engine{"provider-seaweedfs": eng},
		},
	}
}

func (h *bucketHarness) reconcile() ctrl.Result {
	h.t.Helper()
	result, err := h.r.Reconcile(
		context.Background(),
		ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: "mongo"}},
	)
	if err != nil {
		h.t.Fatalf("reconcile: %v", err)
	}
	return result
}

func (h *bucketHarness) get(name string) *v1alpha1.InstanceBucket {
	h.t.Helper()
	bucket := &v1alpha1.InstanceBucket{}
	if err := h.client.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, bucket); err != nil {
		h.t.Fatalf("get %s: %v", name, err)
	}
	return bucket
}

func (h *bucketHarness) expectPhase(name, phase, message string) *v1alpha1.InstanceBucket {
	h.t.Helper()
	bucket := h.get(name)
	if bucket.Status.Phase != phase || !strings.Contains(bucket.Status.Message, message) {
		h.t.Fatalf("%s: phase = %q, message = %q; want %q containing %q", name, bucket.Status.Phase, bucket.Status.Message, phase, message)
	}
	return bucket
}

func TestBucketLifecycle(t *testing.T) {
	h := newBucketHarness(t,
		instance("provider-seaweedfs"),
		owner("uploader-owner", "uploader", "mongo", v1alpha1.PhaseReady),
		instanceBucket("uploads", "uploads", "uploader-owner"),
	)
	if result := h.reconcile(); result.RequeueAfter == 0 {
		t.Error("pending bucket must be requeued")
	}
	bucket := h.expectPhase("uploads", v1alpha1.PhasePending, "waiting for the bucket to be created")
	if !bucket.Status.Declared || bucket.Status.Owner != "uploader" {
		t.Fatalf("status = %+v", bucket.Status)
	}
	if want := []engine.DesiredBucket{{Name: "uploads", Owner: "uploader"}}; !reflect.DeepEqual(h.engine.syncedBuckets, want) {
		t.Fatalf("synced = %+v, want %+v", h.engine.syncedBuckets, want)
	}
	h.engine.buckets = []engine.Bucket{{Name: "uploads", Owner: "uploader"}}
	h.reconcile()
	h.expectPhase("uploads", v1alpha1.PhaseReady, "")
}

func TestBucketWaitsForOwnerAndNoTakeover(t *testing.T) {
	h := newBucketHarness(t,
		instance("provider-seaweedfs"),
		owner("pending-owner", "pending", "mongo", v1alpha1.PhasePending),
		owner("elsewhere", "other", "other", v1alpha1.PhaseReady),
		instanceBucket("missing", "a", "nobody"),
		instanceBucket("pending", "b", "pending-owner"),
		instanceBucket("foreign-owner", "c", "elsewhere"),
		instanceBucket("existing", "existing", ""),
		instanceBucket("first", "dup", ""),
		instanceBucket("second", "dup", ""),
	)
	h.engine.buckets = []engine.Bucket{{Name: "existing"}}
	h.reconcile()
	h.expectPhase("missing", v1alpha1.PhasePending, `owner InstanceUser "nobody" not found`)
	h.expectPhase("pending", v1alpha1.PhasePending, `waiting for owner InstanceUser "pending-owner" to be created`)
	h.expectPhase("foreign-owner", v1alpha1.PhaseFailed, `belongs to instance "other"`)
	h.expectPhase("existing", v1alpha1.PhaseFailed, `bucket "existing" already exists`)
	h.expectPhase("first", v1alpha1.PhasePending, "")
	h.expectPhase("second", v1alpha1.PhaseFailed, `another InstanceBucket already declares bucket "dup"`)
}

func TestBucketDeletePolicy(t *testing.T) {
	bucket := instanceBucket("uploads", "uploads", "")
	now := metav1.Now()
	bucket.DeletionTimestamp = &now
	bucket.Finalizers = []string{BucketFinalizer}
	bucket.Spec.DeletionPolicy = v1alpha1.DeletionPolicyDelete
	bucket.Status.Declared = true
	h := newBucketHarness(t, instance("provider-seaweedfs"), bucket)
	h.reconcile()
	if want := []bucketRelease{{"uploads", true}}; !reflect.DeepEqual(h.engine.released, want) {
		t.Fatalf("released = %+v, want %+v", h.engine.released, want)
	}
}

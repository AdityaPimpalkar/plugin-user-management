package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openeverest/plugin-user-management/backend/api/v1alpha1"
	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

func declaredBucket(id, name, instance string) *v1alpha1.InstanceBucket {
	return &v1alpha1.InstanceBucket{
		ObjectMeta: metav1.ObjectMeta{Name: id, Namespace: "ns"},
		Spec: v1alpha1.InstanceBucketSpec{
			InstanceRef: v1alpha1.InstanceReference{Name: instance},
			Name:        name,
		},
		Status: v1alpha1.InstanceBucketStatus{Phase: v1alpha1.PhaseReady, Available: true},
	}
}

func (e *testEnv) instanceBuckets() []v1alpha1.InstanceBucket {
	var list v1alpha1.InstanceBucketList
	if err := e.kube.List(context.Background(), &list); err != nil {
		e.t.Fatal(err)
	}
	return list.Items
}

func TestCreateAndUpdateBucket(t *testing.T) {
	owner := declared("mongo-owner-1", "alice", "mongo")
	other := declared("mongo-other-1", "bob", "mongo")
	env := newTestEnv(t, s3Provider, http.StatusOK, http.StatusOK, owner, other)
	rec := env.do(
		http.MethodPost,
		"/api/buckets"+testQuery,
		`{"name":"uploads.bucket","ownerId":"mongo-owner-1"}`,
	)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var view bucketView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	buckets := env.instanceBuckets()
	if len(buckets) != 1 || view.Name != "uploads.bucket" || view.OwnerID != owner.Name {
		t.Fatalf("response = %+v, buckets = %+v", view, buckets)
	}
	rec = env.do(
		http.MethodPut,
		"/api/buckets/"+buckets[0].Name+testQuery,
		`{"ownerId":"mongo-other-1"}`,
	)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("update status = %d: %s", rec.Code, rec.Body)
	}
	updated := env.instanceBuckets()[0]
	if updated.Spec.Owner == nil || updated.Spec.Owner.InstanceUserRef.Name != other.Name {
		t.Fatalf("owner = %+v", updated.Spec.Owner)
	}
}

func TestListBucketsMergesDeclaredAndNative(t *testing.T) {
	owner := declared("mongo-owner-1", "alice", "mongo")
	managed := declaredBucket("mongo-uploads-1", "uploads", "mongo")
	managed.Spec.Owner = &v1alpha1.BucketOwner{
		InstanceUserRef: v1alpha1.InstanceUserReference{Name: owner.Name},
	}
	other := declaredBucket("other-x-1", "other", "other")
	env := newTestEnv(t, s3Provider, http.StatusOK, http.StatusOK, owner, managed, other)
	env.bucketEngine.buckets = []engine.Bucket{
		{Name: "uploads", Owner: "alice"},
		{Name: "existing", Owner: ""},
	}
	rec := env.do(http.MethodGet, "/api/buckets"+testQuery, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var response bucketsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Supported || !response.CanManage || len(response.Buckets) != 2 {
		t.Fatalf("response = %+v", response)
	}
	if response.Buckets[0].Name != "uploads" || !response.Buckets[0].Managed {
		t.Fatalf("managed bucket = %+v", response.Buckets[0])
	}
	if response.Buckets[1].Name != "existing" || response.Buckets[1].Managed {
		t.Fatalf("existing bucket = %+v", response.Buckets[1])
	}
}

func TestBucketDeletePolicyAndValidation(t *testing.T) {
	bucket := declaredBucket("mongo-uploads-1", "uploads", "mongo")
	env := newTestEnv(t, s3Provider, http.StatusOK, http.StatusOK, bucket)
	if rec := env.do(
		http.MethodPost,
		"/api/buckets"+testQuery,
		`{"name":"../bad"}`,
	); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid bucket status = %d: %s", rec.Code, rec.Body)
	}
	if rec := env.do(
		http.MethodDelete,
		"/api/buckets/"+bucket.Name+"?namespace=ns&instance=mongo&drop=true",
		"",
	); rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d: %s", rec.Code, rec.Body)
	}
	if len(env.instanceBuckets()) != 0 {
		t.Fatalf("InstanceBuckets = %+v", env.instanceBuckets())
	}
}

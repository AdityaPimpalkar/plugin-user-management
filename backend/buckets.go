package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openeverest/plugin-user-management/backend/api/v1alpha1"
	"github.com/openeverest/plugin-user-management/backend/internal/controller"
	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

var bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

type bucketView struct {
	ID             string `json:"id,omitempty"`
	Name           string `json:"name"`
	Owner          string `json:"owner,omitempty"`
	OwnerID        string `json:"ownerId,omitempty"`
	DeletionPolicy string `json:"deletionPolicy,omitempty"`
	Managed        bool   `json:"managed"`
	Phase          string `json:"phase,omitempty"`
	Message        string `json:"message,omitempty"`
}

type bucketsResponse struct {
	Buckets     []bucketView `json:"buckets"`
	Supported   bool         `json:"supported"`
	CanManage   bool         `json:"canManage"`
	BucketError string       `json:"bucketError,omitempty"`
}

type bucketSettings struct {
	OwnerID string `json:"ownerId,omitempty"`
}

type createBucketRequest struct {
	Name    string `json:"name"`
	OwnerID string `json:"ownerId,omitempty"`
}

func bucketEngine(a access) (engine.BucketEngine, error) {
	if eng, ok := a.engine.(engine.BucketEngine); ok {
		return eng, nil
	}
	return nil, &statusError{status: http.StatusNotFound, message: "buckets are not supported for this provider"}
}

func validBucketName(name string) bool {
	return bucketNamePattern.MatchString(name) &&
		!strings.Contains(name, "..") &&
		!ipv4BucketName(name)
}

func ipv4BucketName(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func (s *server) instanceBuckets(ctx context.Context, target engine.Target) ([]v1alpha1.InstanceBucket, error) {
	var list v1alpha1.InstanceBucketList
	err := s.kube.List(ctx, &list, client.InNamespace(target.Namespace), client.MatchingFields{controller.InstanceIndex: target.Instance})
	return list.Items, err
}

func (s *server) instanceBucket(ctx context.Context, target engine.Target, id string) (*v1alpha1.InstanceBucket, error) {
	bucket := &v1alpha1.InstanceBucket{}
	if err := s.kube.Get(ctx, types.NamespacedName{Namespace: target.Namespace, Name: id}, bucket); err != nil {
		return nil, err
	}
	if bucket.Spec.InstanceRef.Name != target.Instance {
		return nil, &statusError{status: http.StatusNotFound, message: "bucket not found"}
	}
	return bucket, nil
}

func (s *server) optionalOwnerUser(
	ctx context.Context,
	target engine.Target,
	id string,
) (*v1alpha1.InstanceUser, error) {
	if id == "" {
		return nil, nil
	}
	user, err := s.instanceUser(ctx, target, id)
	if apierrors.IsNotFound(err) || err != nil && errors.As(err, new(*statusError)) {
		return nil, badRequest("the owner must be a user of this instance managed by OpenEverest")
	}
	return user, err
}

func managedBucketView(bucket *v1alpha1.InstanceBucket, owners map[string]string) bucketView {
	view := bucketView{
		ID:             bucket.Name,
		Name:           bucket.Spec.Name,
		Owner:          bucket.Status.Owner,
		DeletionPolicy: bucket.Spec.DeletionPolicy,
		Managed:        true,
		Phase:          bucket.Status.Phase,
		Message:        bucket.Status.Message,
	}
	if owner := bucket.Spec.Owner; owner != nil {
		view.OwnerID = owner.InstanceUserRef.Name
		if username, ok := owners[view.OwnerID]; ok {
			view.Owner = username
		}
	}
	if view.DeletionPolicy == "" {
		view.DeletionPolicy = v1alpha1.DeletionPolicyRetain
	}
	if view.Phase == "" {
		view.Phase = v1alpha1.PhasePending
	}
	if !bucket.DeletionTimestamp.IsZero() {
		view.Phase = v1alpha1.PhaseDeleting
		if bucket.Status.Phase != v1alpha1.PhaseDeleting {
			view.Message = ""
		}
	}
	return view
}

// GET /api/buckets?k8sCluster=&namespace=&instance=
func (s *server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	a, err := s.authorize(r, false)
	if err != nil {
		writeError(w, err)
		return
	}
	response := bucketsResponse{Buckets: []bucketView{}, CanManage: a.canManage}
	eng, err := bucketEngine(a)
	if err != nil {
		writeJSON(w, http.StatusOK, response)
		return
	}
	response.Supported = true
	ctx := r.Context()
	declared, err := s.instanceBuckets(ctx, a.target)
	if err != nil {
		writeError(w, err)
		return
	}
	users, err := s.instanceUsers(ctx, a.target)
	if err != nil {
		writeError(w, err)
		return
	}
	owners := map[string]string{}
	for _, user := range users {
		owners[user.Name] = user.Spec.Username
	}
	managed := map[string]bool{}
	for i := range declared {
		response.Buckets = append(response.Buckets, managedBucketView(&declared[i], owners))
		managed[declared[i].Spec.Name] = true
	}
	buckets, err := eng.ListBuckets(ctx, a.target)
	switch {
	case errors.Is(err, engine.ErrNotReady):
		response.BucketError = err.Error()
	case err != nil:
		log.Printf("list buckets of %s/%s: %v", a.target.Namespace, a.target.Instance, err)
		response.BucketError = "the object store can't be reached"
	}
	for _, bucket := range buckets {
		if !managed[bucket.Name] {
			response.Buckets = append(response.Buckets, bucketView{
				Name: bucket.Name, Owner: bucket.Owner,
			})
		}
	}
	sort.SliceStable(response.Buckets, func(i, j int) bool {
		if response.Buckets[i].Managed != response.Buckets[j].Managed {
			return response.Buckets[i].Managed
		}
		return response.Buckets[i].Name < response.Buckets[j].Name
	})
	writeJSON(w, http.StatusOK, response)
}

// POST /api/buckets?k8sCluster=&namespace=&instance=
func (s *server) handleCreateBucket(w http.ResponseWriter, r *http.Request) {
	var req createBucketRequest
	if err := decodeBody(r, w, &req); err != nil {
		writeError(w, err)
		return
	}
	if !validBucketName(req.Name) {
		writeError(w, badRequest("bucket names are 3-63 lowercase letters, digits, dots or hyphens, must not contain '..' or be an IPv4 address"))
		return
	}
	a, err := s.authorize(r, true)
	if err != nil {
		writeError(w, err)
		return
	}
	eng, err := bucketEngine(a)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := eng.ValidateBucket(req.Name); err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	owner, err := s.optionalOwnerUser(ctx, a.target, req.OwnerID)
	if err != nil {
		writeError(w, err)
		return
	}
	declared, err := s.instanceBuckets(ctx, a.target)
	if err != nil {
		writeError(w, err)
		return
	}
	for _, bucket := range declared {
		if bucket.Spec.Name == req.Name {
			writeError(w, conflict("bucket already exists"))
			return
		}
	}
	if buckets, err := eng.ListBuckets(ctx, a.target); err == nil {
		for _, bucket := range buckets {
			if bucket.Name == req.Name {
				writeError(w, conflict("bucket already exists in the instance"))
				return
			}
		}
	}

	bucket := &v1alpha1.InstanceBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name: userResourceName(a.target.Instance, req.Name), Namespace: a.target.Namespace,
			Labels: map[string]string{controller.InstanceLabel: a.target.Instance},
		},
		Spec: v1alpha1.InstanceBucketSpec{
			InstanceRef:    v1alpha1.InstanceReference{Name: a.target.Instance},
			Name:           req.Name,
			DeletionPolicy: v1alpha1.DeletionPolicyRetain,
		},
	}
	owners := map[string]string{}
	if owner != nil {
		bucket.Spec.Owner = &v1alpha1.BucketOwner{
			InstanceUserRef: v1alpha1.InstanceUserReference{Name: owner.Name},
		}
		owners[owner.Name] = owner.Spec.Username
	}
	if err := s.kube.Create(ctx, bucket); err != nil {
		writeError(w, err)
		return
	}
	log.Printf("declared bucket %q on %s/%s as InstanceBucket %s", req.Name, a.target.Namespace, a.target.Instance, bucket.Name)
	writeJSON(w, http.StatusCreated, managedBucketView(bucket, owners))
}

// PUT /api/buckets/{id}?k8sCluster=&namespace=&instance=
func (s *server) handleUpdateBucket(w http.ResponseWriter, r *http.Request) {
	var req bucketSettings
	if err := decodeBody(r, w, &req); err != nil {
		writeError(w, err)
		return
	}
	a, err := s.authorize(r, true)
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := bucketEngine(a); err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	bucket, err := s.instanceBucket(ctx, a.target, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	owner, err := s.optionalOwnerUser(ctx, a.target, req.OwnerID)
	if err != nil {
		writeError(w, err)
		return
	}
	orig := bucket.DeepCopy()
	if owner == nil {
		bucket.Spec.Owner = nil
	} else {
		bucket.Spec.Owner = &v1alpha1.BucketOwner{
			InstanceUserRef: v1alpha1.InstanceUserReference{Name: owner.Name},
		}
	}
	if err := s.kube.Patch(ctx, bucket, client.MergeFrom(orig)); err != nil {
		writeError(w, err)
		return
	}
	log.Printf("updated InstanceBucket %s/%s", bucket.Namespace, bucket.Name)
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /api/buckets/{id}?k8sCluster=&namespace=&instance=&drop=true
func (s *server) handleDeleteBucket(w http.ResponseWriter, r *http.Request) {
	a, err := s.authorize(r, true)
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := bucketEngine(a); err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	bucket, err := s.instanceBucket(ctx, a.target, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	policy := v1alpha1.DeletionPolicyRetain
	if r.URL.Query().Get("drop") == "true" {
		policy = v1alpha1.DeletionPolicyDelete
	}
	if bucket.Spec.DeletionPolicy != policy {
		orig := bucket.DeepCopy()
		bucket.Spec.DeletionPolicy = policy
		if err := s.kube.Patch(ctx, bucket, client.MergeFrom(orig)); err != nil {
			writeError(w, err)
			return
		}
	}
	if err := s.kube.Delete(ctx, bucket); err != nil && !apierrors.IsNotFound(err) {
		writeError(w, err)
		return
	}
	log.Printf("deleted InstanceBucket %s/%s (%s)", bucket.Namespace, bucket.Name, policy)
	w.WriteHeader(http.StatusNoContent)
}

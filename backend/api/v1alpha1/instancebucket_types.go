package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// BucketOwner is the managed user that owns a bucket.
type BucketOwner struct {
	// InstanceUserRef names an InstanceUser of the same instance.
	InstanceUserRef InstanceUserReference `json:"instanceUserRef"`
}

// InstanceBucketSpec declares an object-storage bucket of an instance.
// +kubebuilder:validation:XValidation:rule="self.instanceRef == oldSelf.instanceRef",message="instanceRef is immutable"
// +kubebuilder:validation:XValidation:rule="self.name == oldSelf.name",message="name is immutable"
type InstanceBucketSpec struct {
	// InstanceRef is the Instance the bucket belongs to.
	InstanceRef InstanceReference `json:"instanceRef"`
	// Name is the S3 bucket name: 3-63 lowercase letters, digits, dots or
	// hyphens, starting and ending with a letter or digit.
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`
	// +kubebuilder:validation:XValidation:rule="!self.contains('..')",message="bucket name must not contain consecutive dots"
	// +kubebuilder:validation:XValidation:rule="!self.matches('^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$')",message="bucket name must not be an IPv4 address"
	Name string `json:"name"`
	// Owner optionally assigns the bucket to a managed S3 identity.
	// +optional
	Owner *BucketOwner `json:"owner,omitempty"`
	// DeletionPolicy tells what deleting the InstanceBucket does: Retain
	// removes management and keeps the bucket and its data, Delete drops it.
	// +kubebuilder:validation:Enum=Retain;Delete
	// +kubebuilder:default=Retain
	// +optional
	DeletionPolicy string `json:"deletionPolicy,omitempty"`
}

// InstanceBucketStatus is the observed state of an InstanceBucket.
type InstanceBucketStatus struct {
	// +optional
	Phase string `json:"phase,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// Owner is the visible username of the owner last declared.
	// +optional
	Owner string `json:"owner,omitempty"`
	// Declared is set once the plugin claimed the bucket name. A pre-existing
	// bucket is a conflict, so an InstanceBucket cannot take it over.
	// +optional
	Declared bool `json:"declared,omitempty"`
	// Available is set once the bucket has been successfully applied and stays
	// true through transient later errors.
	// +optional
	Available bool `json:"available,omitempty"`
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// InstanceBucket is an object-storage bucket of an OpenEverest instance.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ibucket;ibuckets
// +kubebuilder:printcolumn:name="Instance",type=string,JSONPath=`.spec.instanceRef.name`
// +kubebuilder:printcolumn:name="Bucket",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Owner",type=string,JSONPath=`.status.owner`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type InstanceBucket struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   InstanceBucketSpec   `json:"spec"`
	Status InstanceBucketStatus `json:"status,omitempty"`
}

// InstanceBucketList is a list of InstanceBuckets.
// +kubebuilder:object:root=true
type InstanceBucketList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []InstanceBucket `json:"items"`
}

func init() {
	SchemeBuilder.Register(&InstanceBucket{}, &InstanceBucketList{})
}

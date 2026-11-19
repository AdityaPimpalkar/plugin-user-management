package mariadb

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

var mariadbResource = schema.GroupVersionResource{Group: "k8s.mariadb.com", Version: "v1alpha1", Resource: "mariadbs"}

const (
	defaultPort       = 3306
	rootSecretSuffix  = "-root"
	rootPasswordKey   = "root-password"
	defaultDatabase   = "everest"
	defaultUser       = "everest"
	caBundleSuffix    = "-ca-bundle"
	caCertKey         = "ca.crt"
	primaryServiceSep = "-primary"
)

type cluster struct {
	name         string
	namespace    string
	uid          string
	host         string
	port         int
	rootPassword string
	tlsEnabled   bool
	caPEM        []byte
	database     string
	systemUsers  map[string]bool
}

type clusterResolver struct {
	kube kubernetes.Interface
	dyn  dynamic.Interface
}

func (r *clusterResolver) resolve(ctx context.Context, target engine.Target) (cluster, error) {
	obj, err := r.dyn.Resource(mariadbResource).Namespace(target.Namespace).Get(ctx, target.Instance, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return cluster{}, fmt.Errorf("%w: MariaDB cluster not found", engine.ErrNotReady)
	}
	if err != nil {
		return cluster{}, fmt.Errorf("get MariaDB: %w", err)
	}
	ready, message := readyCondition(obj)
	if !ready {
		return cluster{}, fmt.Errorf("%w: MariaDB cluster is not ready: %s", engine.ErrNotReady, message)
	}

	c := cluster{
		name:        obj.GetName(),
		namespace:   obj.GetNamespace(),
		uid:         string(obj.GetUID()),
		host:        serviceFQDN(obj.GetName(), obj.GetNamespace()),
		port:        defaultPort,
		database:    nestedStringOr(obj, "spec", "database", defaultDatabase),
		systemUsers: map[string]bool{"root": true, "mariadb.sys": true},
	}
	initialUser := nestedStringOr(obj, "spec", "username", defaultUser)
	c.systemUsers[initialUser] = true
	galera, _, _ := unstructured.NestedBool(obj.Object, "spec", "galera", "enabled")
	replication, _, _ := unstructured.NestedBool(obj.Object, "spec", "replication", "enabled")
	if galera || replication {
		c.host = serviceFQDN(obj.GetName()+primaryServiceSep, obj.GetNamespace())
	}

	secretName := "everest-secrets-" + target.Instance + rootSecretSuffix
	secret, err := r.kube.CoreV1().Secrets(target.Namespace).Get(ctx, secretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return cluster{}, fmt.Errorf("%w: root password Secret %q not found", engine.ErrNotReady, secretName)
	}
	if err != nil {
		return cluster{}, fmt.Errorf("get root password Secret %q: %w", secretName, err)
	}
	c.rootPassword = string(secret.Data[rootPasswordKey])
	if c.rootPassword == "" {
		return cluster{}, fmt.Errorf("%w: root password Secret %q has no %q key", engine.ErrNotReady, secretName, rootPasswordKey)
	}

	c.tlsEnabled, _, _ = unstructured.NestedBool(obj.Object, "spec", "tls", "enabled")
	if c.tlsEnabled {
		caName := target.Instance + caBundleSuffix
		caSecret, err := r.kube.CoreV1().Secrets(target.Namespace).Get(ctx, caName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return cluster{}, fmt.Errorf("%w: TLS CA Secret %q not found", engine.ErrNotReady, caName)
		}
		if err != nil {
			return cluster{}, fmt.Errorf("get TLS CA Secret %q: %w", caName, err)
		}
		c.caPEM = caSecret.Data[caCertKey]
		if len(c.caPEM) == 0 {
			return cluster{}, fmt.Errorf("%w: TLS CA Secret %q has no %q key", engine.ErrNotReady, caName, caCertKey)
		}
	}
	return c, nil
}

func nestedStringOr(obj *unstructured.Unstructured, section, field, fallback string) string {
	value, _, _ := unstructured.NestedString(obj.Object, section, field)
	if value == "" {
		return fallback
	}
	return value
}

func readyCondition(obj *unstructured.Unstructured) (bool, string) {
	conditions, found, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if !found {
		return false, "status is not available yet"
	}
	for _, item := range conditions {
		condition, ok := item.(map[string]any)
		if !ok || condition["type"] != "Ready" {
			continue
		}
		if condition["status"] == "True" {
			return true, ""
		}
		if message, _ := condition["message"].(string); message != "" {
			return false, message
		}
		return false, "not ready"
	}
	return false, "Ready condition is not available yet"
}

func serviceFQDN(service, namespace string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", service, namespace)
}

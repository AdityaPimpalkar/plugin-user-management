package pxc

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

var pxcResource = schema.GroupVersionResource{Group: "pxc.percona.com", Version: "v1", Resource: "perconaxtradbclusters"}

const (
	defaultPort     = 3306
	rootPasswordKey = "root"
	caCertKey       = "ca.crt"
	stateReady      = "ready"
)

type cluster struct {
	name      string
	namespace string
	state     string
	message   string
	// host is the proxy's Service: HAProxy sends writes to one node, and
	// ProxySQL picks up new users from the nodes on its next user sync.
	host         string
	port         int
	secretsName  string
	sslSecret    string
	tls          bool
	rootPassword string
	caPEM        []byte
}

func (c cluster) ready() bool {
	return c.state == stateReady
}

// serverName is a name on the operator's certificates, which have
// <cluster>-pxc and <cluster>-proxysql names but not the HAProxy Service's.
// HAProxy passes the PXC nodes' TLS through.
func (c cluster) serverName() string {
	return c.name + "-pxc"
}

func (e *Engine) resolve(ctx context.Context, target engine.Target) (cluster, error) {
	obj, err := e.dyn.Resource(pxcResource).Namespace(target.Namespace).Get(ctx, target.Instance, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return cluster{}, fmt.Errorf("%w: PerconaXtraDBCluster %q not found", engine.ErrNotReady, target.Instance)
	}
	if err != nil {
		return cluster{}, fmt.Errorf("get PerconaXtraDBCluster: %w", err)
	}
	return clusterFrom(obj), nil
}

func clusterFrom(obj *unstructured.Unstructured) cluster {
	name := obj.GetName()
	c := cluster{
		name:        name,
		namespace:   obj.GetNamespace(),
		port:        defaultPort,
		secretsName: nestedString(obj, "everest-secrets-"+name, "spec", "secretsName"),
		tls:         true,
	}
	c.state, _, _ = unstructured.NestedString(obj.Object, "status", "state")
	messages, _, _ := unstructured.NestedStringSlice(obj.Object, "status", "messages")
	c.message = strings.Join(messages, "; ")

	service := name + "-pxc"
	if enabled, _, _ := unstructured.NestedBool(obj.Object, "spec", "haproxy", "enabled"); enabled {
		service = name + "-haproxy"
	} else if enabled, _, _ := unstructured.NestedBool(obj.Object, "spec", "proxysql", "enabled"); enabled {
		service = name + "-proxysql"
	}
	c.host = fmt.Sprintf("%s.%s.svc.cluster.local", service, c.namespace)

	// The operator only turns TLS off when both are set.
	unsafeTLS, _, _ := unstructured.NestedBool(obj.Object, "spec", "unsafeFlags", "tls")
	enabled, found, _ := unstructured.NestedBool(obj.Object, "spec", "tls", "enabled")
	if unsafeTLS && found && !enabled {
		c.tls = false
	}
	c.sslSecret = nestedString(obj, "", "spec", "pxc", "sslSecretName")
	if c.sslSecret == "" {
		c.sslSecret = nestedString(obj, name+"-ssl", "spec", "sslSecretName")
	}
	return c
}

func nestedString(obj *unstructured.Unstructured, fallback string, fields ...string) string {
	if value, _, _ := unstructured.NestedString(obj.Object, fields...); value != "" {
		return value
	}
	return fallback
}

// credentials reads root's password and, with TLS, the CA of the cluster.
func (e *Engine) credentials(ctx context.Context, c *cluster) error {
	secret, err := e.kube.CoreV1().Secrets(c.namespace).Get(ctx, c.secretsName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("%w: users Secret %q not found", engine.ErrNotReady, c.secretsName)
	}
	if err != nil {
		return fmt.Errorf("get users Secret %q: %w", c.secretsName, err)
	}
	c.rootPassword = string(secret.Data[rootPasswordKey])
	if c.rootPassword == "" {
		return fmt.Errorf("%w: users Secret %q has no %q key", engine.ErrNotReady, c.secretsName, rootPasswordKey)
	}
	if !c.tls {
		return nil
	}
	ca, err := e.kube.CoreV1().Secrets(c.namespace).Get(ctx, c.sslSecret, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("%w: TLS Secret %q not found", engine.ErrNotReady, c.sslSecret)
	}
	if err != nil {
		return fmt.Errorf("get TLS Secret %q: %w", c.sslSecret, err)
	}
	c.caPEM = ca.Data[caCertKey]
	if len(c.caPEM) == 0 {
		return fmt.Errorf("%w: TLS Secret %q has no %q key", engine.ErrNotReady, c.sslSecret, caCertKey)
	}
	return nil
}

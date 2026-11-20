package clickhouse

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

var clickHouseInstallationResource = schema.GroupVersionResource{
	Group: "clickhouse.altinity.com", Version: "v1", Resource: "clickhouseinstallations",
}

const (
	clickHousePort       = 9000
	clickHouseSecurePort = 9440
	clickHouseCluster    = "clickhouse"
	defaultDatabase      = "default"
)

type cluster struct {
	name        string
	namespace   string
	host        string
	port        int
	adminUser   string
	adminPass   string
	tls         bool
	caPEM       []byte
	distributed bool
	systemUsers map[string]bool
}

type clusterResolver struct {
	kube kubernetes.Interface
	dyn  dynamic.Interface
}

func (r *clusterResolver) resolve(ctx context.Context, target engine.Target) (cluster, error) {
	obj, err := r.dyn.Resource(clickHouseInstallationResource).Namespace(target.Namespace).
		Get(ctx, target.Instance, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return cluster{}, fmt.Errorf("%w: ClickHouse installation not found", engine.ErrNotReady)
	}
	if err != nil {
		return cluster{}, fmt.Errorf("get ClickHouse installation: %w", err)
	}
	state, _, _ := unstructured.NestedString(obj.Object, "status", "status")
	if state != "Completed" {
		if state == "" {
			state = "Initializing"
		}
		return cluster{}, fmt.Errorf("%w: ClickHouse installation is %q", engine.ErrNotReady, state)
	}

	c := cluster{
		name:        target.Instance,
		namespace:   target.Namespace,
		host:        fmt.Sprintf("clickhouse-%s.%s.svc.cluster.local", target.Instance, target.Namespace),
		port:        clickHousePort,
		distributed: hasKeeper(obj),
		systemUsers: map[string]bool{"default": true, "interserver": true, "clickhouse_operator": true},
	}

	credentialsName := target.Instance + "-credentials"
	credentials, err := r.kube.CoreV1().Secrets(target.Namespace).Get(ctx, credentialsName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return cluster{}, fmt.Errorf("%w: credentials Secret %q not found", engine.ErrNotReady, credentialsName)
	}
	if err != nil {
		return cluster{}, fmt.Errorf("get credentials Secret %q: %w", credentialsName, err)
	}
	c.adminUser = string(credentials.Data["username"])
	if c.adminUser == "" {
		c.adminUser = "admin"
	}
	c.adminPass = string(credentials.Data["password"])
	if c.adminPass == "" {
		return cluster{}, fmt.Errorf("%w: credentials Secret %q has no password", engine.ErrNotReady, credentialsName)
	}
	c.systemUsers[c.adminUser] = true

	c.tls = clusterTLS(obj)
	if c.tls {
		c.port = clickHouseSecurePort
		caName := target.Instance + "-server-tls"
		ca, err := r.kube.CoreV1().Secrets(target.Namespace).Get(ctx, caName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return cluster{}, fmt.Errorf("%w: TLS Secret %q not found", engine.ErrNotReady, caName)
		}
		if err != nil {
			return cluster{}, fmt.Errorf("get TLS Secret %q: %w", caName, err)
		}
		c.caPEM = ca.Data["ca.crt"]
		if len(c.caPEM) == 0 {
			return cluster{}, fmt.Errorf("%w: TLS Secret %q has no ca.crt", engine.ErrNotReady, caName)
		}
	}
	return c, nil
}

func hasKeeper(obj *unstructured.Unstructured) bool {
	keeper, found, _ := unstructured.NestedFieldNoCopy(obj.Object, "spec", "configuration", "zookeeper")
	return found && keeper != nil
}

func clusterTLS(obj *unstructured.Unstructured) bool {
	clusters, _, _ := unstructured.NestedSlice(obj.Object, "spec", "configuration", "clusters")
	if len(clusters) == 0 {
		return false
	}
	cluster, ok := clusters[0].(map[string]any)
	if !ok {
		return false
	}
	switch secure := cluster["secure"].(type) {
	case bool:
		return secure
	case string:
		return secure == "1" || secure == "true"
	}
	return false
}

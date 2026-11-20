package clickhouse

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

func TestResolveReplicatedTLSCluster(t *testing.T) {
	installation := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "clickhouse.altinity.com/v1",
		"kind":       "ClickHouseInstallation",
		"metadata": map[string]any{
			"name": "events", "namespace": "team-a",
		},
		"spec": map[string]any{
			"configuration": map[string]any{
				"clusters":  []any{map[string]any{"secure": true}},
				"zookeeper": map[string]any{"nodes": []any{}},
			},
		},
		"status": map[string]any{"status": "Completed"},
	}}
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), installation)
	kube := kubernetesfake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "events-credentials", Namespace: "team-a"},
			Data: map[string][]byte{
				"username": []byte("dba"),
				"password": []byte("secret"),
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "events-server-tls", Namespace: "team-a"},
			Data:       map[string][]byte{"ca.crt": []byte("ca")},
		},
	)
	resolver := &clusterResolver{kube: kube, dyn: dyn}
	cluster, err := resolver.resolve(context.Background(), engine.Target{Namespace: "team-a", Instance: "events"})
	require.NoError(t, err)
	assert.Equal(t, clickHouseSecurePort, cluster.port)
	assert.True(t, cluster.tls)
	assert.True(t, cluster.distributed)
	assert.Equal(t, "dba", cluster.adminUser)
	assert.True(t, cluster.systemUsers["dba"])
	assert.Equal(t, "clickhouse-events.team-a.svc.cluster.local", cluster.host)
}

func TestResolveStandaloneUsesLocalDDL(t *testing.T) {
	installation := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "clickhouse.altinity.com/v1",
		"kind":       "ClickHouseInstallation",
		"metadata": map[string]any{
			"name": "events", "namespace": "team-a",
		},
		"spec": map[string]any{"configuration": map[string]any{
			"clusters": []any{map[string]any{}},
		}},
		"status": map[string]any{"status": "Completed"},
	}}
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), installation)
	kube := kubernetesfake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "events-credentials", Namespace: "team-a"},
		Data:       map[string][]byte{"password": []byte("secret")},
	})
	resolver := &clusterResolver{kube: kube, dyn: dyn}
	cluster, err := resolver.resolve(context.Background(), engine.Target{Namespace: "team-a", Instance: "events"})
	require.NoError(t, err)
	assert.Equal(t, clickHousePort, cluster.port)
	assert.False(t, cluster.tls)
	assert.False(t, cluster.distributed)
	assert.Equal(t, "admin", cluster.adminUser)
}

func TestResolveRequiresCompletedInstallation(t *testing.T) {
	installation := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "clickhouse.altinity.com/v1",
		"kind":       "ClickHouseInstallation",
		"metadata": map[string]any{
			"name": "events", "namespace": "team-a",
		},
		"status": map[string]any{"status": "InProgress"},
	}}
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), installation)
	resolver := &clusterResolver{kube: kubernetesfake.NewSimpleClientset(), dyn: dyn}
	_, err := resolver.resolve(context.Background(), engine.Target{Namespace: "team-a", Instance: "events"})
	assert.ErrorIs(t, err, engine.ErrNotReady)
}

package valkey

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

var (
	clusterResource = schema.GroupVersionResource{Group: "valkey.io", Version: "v1alpha1", Resource: "valkeyclusters"}
	nodeResource    = schema.GroupVersionResource{Group: "valkey.io", Version: "v1alpha1", Resource: "valkeynodes"}
)

const (
	// The operator renders every user of a cluster into this Secret's
	// aclfile, which each node loads with ACL LOAD.
	internalACLSecretPrefix = "internal-"
	internalACLSecretSuffix = "-acl"
	aclFileKey              = "users.acl"
	// aclRevisionUser is the operator's disabled bookkeeping user whose only
	// password hash is the revision of the aclfile; each ValkeyNode reports
	// the revision it loaded in status.appliedACLRevision.
	aclRevisionUser = "_operator_acl_revision"
	clusterLabel    = "valkey.io/cluster"

	conditionDegraded        = "Degraded"
	reasonUsersACLUnresolved = "UsersACLUnresolved"
	reasonACLApplyFailed     = "ACLApplyFailed"

	// The provider publishes the address, the default user and the CA in the
	// Instance's connection Secret.
	connectionSecretSuffix = "-conn"
	defaultPort            = "6379"
	caCertKey              = "ca.crt"
)

// aclState is the ACL the operator rendered for a cluster, and how far its
// nodes got loading it.
type aclState struct {
	revision string
	// entries holds each user's rules, keyed by username, as rendered in
	// the aclfile: "on #<hash> ~* +@read ...".
	entries map[string]string
	// readyNodes are the nodes serving traffic; pendingNodes those of them
	// that haven't loaded revision yet.
	readyNodes, pendingNodes int
	// problem is why the operator can't apply the ACL, from the cluster's
	// Degraded condition.
	problem string
}

// parseACLFile reads the users of an aclfile ("user <name> <rules...>" lines).
func parseACLFile(aclFile string) (entries map[string]string, revision string) {
	entries = map[string]string{}
	for line := range strings.SplitSeq(aclFile, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "user" {
			continue
		}
		entries[fields[1]] = strings.Join(fields[2:], " ")
		if fields[1] == aclRevisionUser {
			for _, f := range fields[2:] {
				if h, ok := strings.CutPrefix(f, "#"); ok {
					revision = h
				}
			}
		}
	}
	return entries, revision
}

func (e *Engine) getCluster(ctx context.Context, target engine.Target) (*unstructured.Unstructured, error) {
	vc, err := e.dyn.Resource(clusterResource).Namespace(target.Namespace).Get(ctx, target.Instance, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("%w: Valkey cluster not found", engine.ErrNotReady)
	}
	if err != nil {
		return nil, fmt.Errorf("get ValkeyCluster: %w", err)
	}
	return vc, nil
}

// readACL reads the ACL the operator rendered for the cluster, and which of
// its nodes loaded it.
func (e *Engine) readACL(ctx context.Context, target engine.Target) (aclState, error) {
	vc, err := e.getCluster(ctx, target)
	if err != nil {
		return aclState{}, err
	}
	var s aclState
	conditions, _, _ := unstructured.NestedSlice(vc.Object, "status", "conditions")
	for _, c := range conditions {
		cond, _ := c.(map[string]any)
		if cond["type"] == conditionDegraded && cond["status"] == string(metav1.ConditionTrue) &&
			(cond["reason"] == reasonUsersACLUnresolved || cond["reason"] == reasonACLApplyFailed) {
			s.problem, _ = cond["message"].(string)
		}
	}

	name := internalACLSecretPrefix + target.Instance + internalACLSecretSuffix
	secret, err := e.kube.CoreV1().Secrets(target.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return aclState{}, fmt.Errorf("%w: the operator hasn't rendered the ACL yet", engine.ErrNotReady)
	}
	if err != nil {
		return aclState{}, fmt.Errorf("get ACL secret %q: %w", name, err)
	}
	s.entries, s.revision = parseACLFile(string(secret.Data[aclFileKey]))
	if s.revision == "" {
		return aclState{}, fmt.Errorf("%w: the operator hasn't rendered the ACL yet", engine.ErrNotReady)
	}

	nodes, err := e.dyn.Resource(nodeResource).Namespace(target.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: clusterLabel + "=" + target.Instance,
	})
	if err != nil {
		return aclState{}, fmt.Errorf("list ValkeyNodes: %w", err)
	}
	for _, n := range nodes.Items {
		// A node that isn't serving loads the current aclfile when it starts.
		if ready, _, _ := unstructured.NestedBool(n.Object, "status", "ready"); !ready {
			continue
		}
		s.readyNodes++
		if applied, _, _ := unstructured.NestedString(n.Object, "status", "appliedACLRevision"); applied != s.revision {
			s.pendingNodes++
		}
	}
	if s.readyNodes == 0 {
		return aclState{}, fmt.Errorf("%w: no Valkey node is ready", engine.ErrNotReady)
	}
	return s, nil
}

// connection is the address and TLS settings clients connect with.
type connection struct {
	host string
	port string
	tls  bool
	ca   string
}

func (e *Engine) readConnection(ctx context.Context, target engine.Target) (connection, error) {
	name := target.Instance + connectionSecretSuffix
	secret, err := e.kube.CoreV1().Secrets(target.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return connection{}, fmt.Errorf("%w: the instance has no connection details yet", engine.ErrNotReady)
	}
	if err != nil {
		return connection{}, fmt.Errorf("get connection secret %q: %w", name, err)
	}
	c := connection{
		host: string(secret.Data["host"]),
		port: string(secret.Data["port"]),
		tls:  string(secret.Data["ssl"]) == "true",
		ca:   string(secret.Data[caCertKey]),
	}
	if c.host == "" {
		return connection{}, fmt.Errorf("%w: the instance has no connection details yet", engine.ErrNotReady)
	}
	if c.port == "" {
		c.port = defaultPort
	}
	return c, nil
}

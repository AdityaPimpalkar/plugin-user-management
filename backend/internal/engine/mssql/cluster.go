package mssql

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

var (
	agResource       = schema.GroupVersionResource{Group: "mssql.solanica.io", Version: "v1alpha1", Resource: "mssqlavailabilitygroups"}
	instanceResource = schema.GroupVersionResource{Group: "mssql.solanica.io", Version: "v1alpha1", Resource: "mssqlinstances"}
)

const (
	defaultPort = 1433
	stateReady  = "Ready"
	saPassword  = "MSSQL_SA_PASSWORD"
	caCertKey   = "ca.crt"
)

// cluster is what the plugin needs from an MSSQLAvailabilityGroup or an
// MSSQLInstance. The provider names either after the Instance.
type cluster struct {
	name      string
	namespace string
	ready     bool
	state     string
	// unsupported explains why the plugin can't manage this deployment.
	unsupported string
	// ag is the Availability Group's name, for Availability Groups.
	ag string
	// host is the Service that always points at the primary.
	host string
	port int64
	// saSecret holds the sa password, in MSSQL_SA_PASSWORD.
	saSecret string
	tls      bool
	// tlsSecret holds the server certificate and, when the operator
	// generated it, its CA (ca.crt).
	tlsSecret string
	// tlsServerName is the name the certificate is checked against, the
	// host when empty.
	tlsServerName string
}

func (c cluster) isAG() bool {
	return c.ag != ""
}

func serviceFQDN(service, namespace string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", service, namespace)
}

func clusterFrom(obj *unstructured.Unstructured, ag bool) cluster {
	name, namespace := obj.GetName(), obj.GetNamespace()
	c := cluster{
		name:      name,
		namespace: namespace,
		host:      serviceFQDN(name, namespace),
		port:      defaultPort,
		tls:       true,
		tlsSecret: name + "-tls-certs",
		// The operator's certificate names the instance's Service, not the
		// -primary one; its CA is the instance's own.
		tlsServerName: serviceFQDN(name, namespace),
	}
	c.saSecret, _, _ = unstructured.NestedString(obj.Object, "spec", "saPasswordSecret")
	if port, found, _ := unstructured.NestedInt64(obj.Object, "spec", "port"); found && port > 0 {
		c.port = port
	}
	if enabled, found, _ := unstructured.NestedBool(obj.Object, "spec", "tls", "enabled"); found {
		c.tls = enabled
	}
	if secret, _, _ := unstructured.NestedString(obj.Object, "spec", "tls", "certificateSecret"); secret != "" {
		// A certificate of the user's own is checked against the host dialed.
		c.tlsSecret, c.tlsServerName = secret, ""
	}
	c.state, _, _ = unstructured.NestedString(obj.Object, "status", "state")
	c.ready = c.state == stateReady

	if ag {
		c.host = serviceFQDN(name+"-primary", namespace)
		c.ag, _, _ = unstructured.NestedString(obj.Object, "spec", "availabilityGroup", "name")
		if c.ag == "" {
			c.ag = name + "-ag"
		}
		if contained, _, _ := unstructured.NestedBool(obj.Object, "spec", "availabilityGroup", "contained"); contained {
			c.unsupported = "user management doesn't support contained Availability Groups"
		}
		return c
	}
	// Replicas of a standalone deployment are independent servers behind one
	// Service: users and databases would only exist on some of them.
	if size, found, _ := unstructured.NestedInt64(obj.Object, "spec", "size"); found && size > 1 {
		c.unsupported = fmt.Sprintf("user management needs one replica, or an Availability Group: this instance runs %d independent SQL Server replicas", size)
	}
	return c
}

// resolve reads the Availability Group, or else the standalone instance.
func (e *Engine) resolve(ctx context.Context, target engine.Target) (cluster, error) {
	obj, err := e.dyn.Resource(agResource).Namespace(target.Namespace).Get(ctx, target.Instance, metav1.GetOptions{})
	if err == nil {
		return clusterFrom(obj, true), nil
	}
	if !apierrors.IsNotFound(err) {
		return cluster{}, fmt.Errorf("get MSSQLAvailabilityGroup: %w", err)
	}
	obj, err = e.dyn.Resource(instanceResource).Namespace(target.Namespace).Get(ctx, target.Instance, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return cluster{}, fmt.Errorf("%w: SQL Server instance not found", engine.ErrNotReady)
	}
	if err != nil {
		return cluster{}, fmt.Errorf("get MSSQLInstance: %w", err)
	}
	return clusterFrom(obj, false), nil
}

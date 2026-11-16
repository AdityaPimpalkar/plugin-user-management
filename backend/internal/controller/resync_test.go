package controller

import (
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
)

type resyncer time.Duration

func (r resyncer) ResyncInterval() time.Duration { return time.Duration(r) }

func TestWithResync(t *testing.T) {
	eng := resyncer(5 * time.Minute)
	for _, tc := range []struct {
		name    string
		in      ctrl.Result
		eng     any
		managed bool
		want    time.Duration
	}{
		{"resyncs", ctrl.Result{}, eng, true, 5 * time.Minute},
		{"keeps a sooner requeue", ctrl.Result{RequeueAfter: pendingRequeue}, eng, true, pendingRequeue},
		{"shortens a later requeue", ctrl.Result{RequeueAfter: time.Hour}, eng, true, 5 * time.Minute},
		{"nothing managed", ctrl.Result{}, eng, false, 0},
		{"engine without resync", ctrl.Result{}, struct{}{}, true, 0},
	} {
		if got := withResync(tc.in, tc.eng, tc.managed).RequeueAfter; got != tc.want {
			t.Errorf("%s: RequeueAfter = %v, want %v", tc.name, got, tc.want)
		}
	}
}

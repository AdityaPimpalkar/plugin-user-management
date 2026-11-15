package controller

import (
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

// withResync requeues the instance after the engine's resync interval when
// nothing comes sooner, so what a failover lost is applied again.
func withResync(result ctrl.Result, eng any, managed bool) ctrl.Result {
	resyncer, ok := eng.(engine.Resyncer)
	if !ok || !managed {
		return result
	}
	if interval := resyncer.ResyncInterval(); result.RequeueAfter == 0 || result.RequeueAfter > interval {
		result.RequeueAfter = interval
	}
	return result
}

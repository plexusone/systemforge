package authz

import (
	"strings"
	"testing"
	"time"
)

func TestReconcileConfig(t *testing.T) {
	var none *ReconcileConfig
	if d, err := none.IntervalDuration(); err != nil || d != DefaultReconcileInterval {
		t.Errorf("default interval = %v, %v", d, err)
	}
	if d, err := none.JitterDuration(); err != nil || d != DefaultReconcileInterval/10 {
		t.Errorf("default jitter = %v, %v", d, err)
	}
	c := &ReconcileConfig{Interval: "1h", Jitter: "30s"}
	if d, err := c.IntervalDuration(); err != nil || d != time.Hour {
		t.Errorf("interval = %v, %v", d, err)
	}
	if d, err := c.JitterDuration(); err != nil || d != 30*time.Second {
		t.Errorf("jitter = %v, %v", d, err)
	}
	if d, err := (&ReconcileConfig{Interval: "0"}).IntervalDuration(); err != nil || d != 0 {
		t.Errorf("startup-only interval = %v, %v", d, err)
	}
	for _, bad := range []*ReconcileConfig{{Interval: "soon"}, {Interval: "-1m"}, {Jitter: "x"}, {Jitter: "-1s"}, {PageSize: -1}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v validated", bad)
		}
	}
	rebac := ModeConfig{Mode: ModeReBAC, Reconcile: &ReconcileConfig{Interval: "soon"}}
	rebac.ApplyDefaults()
	if err := rebac.Validate(); err == nil || !strings.Contains(err.Error(), "reconcile.interval") {
		t.Errorf("rebac with a bad interval = %v", err)
	}
	rbac := ModeConfig{Mode: ModeRBAC, Reconcile: &ReconcileConfig{}}
	if err := rbac.Validate(); err == nil {
		t.Error("reconcile settings with mode rbac validated")
	}
}

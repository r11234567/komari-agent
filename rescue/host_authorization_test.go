package rescue

import (
	"context"
	"strings"
	"testing"

	"github.com/komari-monitor/komari-agent/core/hostops"
)

func TestIdleManagedHelperCannotLeaseOrExecute(t *testing.T) {
	// No client or assignment is necessary: the authorization gate must run
	// before either can be used, including while a pending helper stays alive.
	h := &Helper{hostTrust: &hostops.Trust{}}
	if _, err := h.lease(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("idle helper attempted a lease: %v", err)
	}
	if err := h.execute(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("idle helper attempted an action: %v", err)
	}
}

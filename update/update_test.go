package update

import (
	"strings"
	"testing"
)

func TestDaemonUpdatePointsToAdministratorHostTool(t *testing.T) {
	if err := CheckAndUpdate(); err == nil || !strings.Contains(err.Error(), "komari-host update") {
		t.Fatalf("expected the administrator update route, got %v", err)
	}
}

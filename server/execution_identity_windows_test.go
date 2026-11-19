//go:build windows

package server

import (
	"os/exec"
	"strings"
	"testing"

	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
)

func TestConfigureExecutionIdentityWindowsRequiresOptInAndStripsSecrets(t *testing.T) {
	t.Setenv("AGENT_TOKEN", "secret-agent-token")
	t.Setenv("AGENT_AUTO_DISCOVERY_KEY", "secret-discovery-key")
	t.Setenv("AGENT_CF_ACCESS_CLIENT_SECRET", "secret-cf")
	t.Setenv(windowsServiceExecOptInEnv, "")

	cmd := exec.Command("cmd.exe")
	if err := configureExecutionIdentity(cmd, &execv1.ExecutionSpec{RunAsRoot: false}); err == nil {
		t.Fatal("expected Windows execution without explicit service-exec opt-in to fail closed")
	}

	t.Setenv(windowsServiceExecOptInEnv, "true")
	if err := configureExecutionIdentity(cmd, &execv1.ExecutionSpec{RunAsRoot: true}); err == nil {
		t.Fatal("expected RunAsRoot=true to remain rejected on Windows")
	}
	if err := configureExecutionIdentity(cmd, &execv1.ExecutionSpec{RunAsRoot: false, WorkingDirectory: `C:\Windows\Temp`}); err != nil {
		t.Fatalf("configureExecutionIdentity failed with explicit opt-in: %v", err)
	}
	for _, entry := range cmd.Env {
		upper := strings.ToUpper(entry)
		if strings.HasPrefix(upper, "AGENT_TOKEN=") ||
			strings.HasPrefix(upper, "AGENT_AUTO_DISCOVERY_KEY=") ||
			strings.HasPrefix(upper, "AGENT_CF_ACCESS_CLIENT_SECRET=") {
			t.Fatalf("leaked daemon secret into Windows execution environment: %s", entry)
		}
	}
}

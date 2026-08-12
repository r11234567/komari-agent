package rescue

import (
	"context"
	"strings"
	"testing"

	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
)

func TestExecuteActionRejectsRemoteArguments(t *testing.T) {
	_, err := ExecuteAction(context.Background(), ActionConfig{}, rescuev1.RescueAction_RESCUE_ACTION_DIAGNOSTICS, []string{"whoami"})
	if err == nil || !strings.Contains(err.Error(), "do not accept remote arguments") {
		t.Fatalf("ExecuteAction() error = %v, want remote argument rejection", err)
	}
}

func TestExecuteActionRejectsUnspecifiedAction(t *testing.T) {
	_, err := ExecuteAction(context.Background(), ActionConfig{}, rescuev1.RescueAction_RESCUE_ACTION_UNSPECIFIED, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported rescue action") {
		t.Fatalf("ExecuteAction() error = %v, want unsupported action rejection", err)
	}
}

func TestNormalizeEndpointRejectsNonHTTPTransport(t *testing.T) {
	if _, err := normalizeEndpoint("file:///tmp/socket"); err == nil {
		t.Fatal("normalizeEndpoint() accepted a non-HTTP transport")
	}
}

func TestFinalOutputIsBoundedAndMarksStderr(t *testing.T) {
	result := finalOutput(ActionResult{Stdout: []byte("ok"), Stderr: []byte("warning")}, 7)
	if len(result) > maximumEventOutput || !strings.Contains(string(result), "[stderr]\nwarning") {
		t.Fatalf("finalOutput() = %q", result)
	}
}

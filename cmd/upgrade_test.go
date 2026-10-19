package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/localauth"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"google.golang.org/protobuf/proto"
)

func TestReportPrivilegedOutcome_SuccessAndDPoP(t *testing.T) {
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, "credentials.json")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	reportDeliveredCalled := false
	completeManualUpgradeCalled := false
	var capturedNonce string
	var dpopReportSig, dpopCompleteSig string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/komari.config.v1.PrivilegedDeliveryService/ReportPrivilegedDelivery":
			reportDeliveredCalled = true
			dpopReportSig = r.Header.Get("X-Komari-Signature")
			resp := &configv1.ReportPrivilegedDeliveryResponse{}
			out, _ := proto.Marshal(resp)
			w.Header().Set("Content-Type", "application/proto")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(out)
		case "/komari.config.v1.PrivilegedDeliveryService/CompleteManualUpgrade":
			completeManualUpgradeCalled = true
			dpopCompleteSig = r.Header.Get("X-Komari-Signature")
			resp := &configv1.CompleteManualUpgradeResponse{}
			out, _ := proto.Marshal(resp)
			w.Header().Set("Content-Type", "application/proto")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(out)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store, err := credentials.Open(credPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := credentials.Identity{
		Endpoint:    srv.URL,
		AgentID:     "agent-upgrade-test",
		AccessToken: "upgrade-token-abc",
		PrivateKey:  base64.StdEncoding.EncodeToString(priv),
	}
	if err := store.Save(identity); err != nil {
		t.Fatal(err)
	}

	// Set flags credentials path
	flags.CredentialsFile = credPath
	capturedNonce = "expected-pending-nonce-456"

	authResult := localauth.Result{
		Method:   localauth.MethodSudoPassword,
		Operator: "testoperator",
	}

	err = reportPrivilegedOutcome(
		context.Background(),
		5, // revision
		capturedNonce,
		configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED,
		reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT,
		authResult,
	)
	if err != nil {
		t.Fatalf("expected reportPrivilegedOutcome to succeed, got %v", err)
	}

	if !reportDeliveredCalled {
		t.Fatal("expected ReportPrivilegedDelivery to be called")
	}
	if !completeManualUpgradeCalled {
		t.Fatal("expected CompleteManualUpgrade to be called")
	}
	if dpopReportSig == "" {
		t.Fatal("expected DPoP signature on ReportPrivilegedDelivery request")
	}
	if dpopCompleteSig == "" {
		t.Fatal("expected DPoP signature on CompleteManualUpgrade request")
	}
}

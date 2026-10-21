package clientcore

import (
	"context"
	"path/filepath"
	"testing"

	flags "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	"google.golang.org/protobuf/proto"
)

func TestHostReceiptWithoutCurrentProtectedEvidenceIsRetainedWithoutSending(t *testing.T) {
	dir := t.TempDir()
	store, err := privileged.Open(filepath.Join(dir, "privileged.json"))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := runtimeconfig.New(runtimeconfig.FromFlags(&flags.Config{Interval: 3}), filepath.Join(dir, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	request := &configv1.ReportPrivilegedDeliveryRequest{ReceiptId: "saved-host-ack", ProtocolVersion: 2, State: configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED, Observation: &hostv1.DaemonObservation{OperationId: "restored-operation"}}
	payload, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Enqueue(privileged.Receipt{ID: request.ReceiptId, Kind: "privileged", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	// No RPC client is configured: a stale host receipt must be rejected before
	// reaching the transport, keeping its exact evidence for diagnosis.
	c := &Client{store: runtime, privilegedStore: store}
	if err = c.flushReceipts(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := store.State()
	if len(s.Outbox) != 0 || len(s.RejectedReceipts) != 1 || s.RejectedReceipts[0].ID != request.ReceiptId || !proto.Equal(request, decodeHostReceipt(t, s.RejectedReceipts[0].Payload)) {
		t.Fatal("invalidated host receipt was sent, discarded or rewritten")
	}
}

func decodeHostReceipt(t *testing.T, b []byte) *configv1.ReportPrivilegedDeliveryRequest {
	t.Helper()
	var r configv1.ReportPrivilegedDeliveryRequest
	if err := proto.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

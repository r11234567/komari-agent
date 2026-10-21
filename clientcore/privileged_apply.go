package clientcore

import (
	"connectrpc.com/connect"
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	commonv1 "github.com/r11234567/komari-proto/gen/go/komari/common/v1"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

func (c *Client) verifyPrivilegedRevision(r *configv1.PrivilegedRevision) error {
	return c.verifyV2Revision(r)
}

func (c *Client) recordPrivilegedRevision(ctx context.Context, r *configv1.PrivilegedRevision) error {
	c.privilegedMu.Lock()
	defer c.privilegedMu.Unlock()
	if err := c.verifyV2Revision(r); err != nil {
		return err
	}
	if r.GetInstallationBaseline() {
		return c.acceptBaseline(ctx, r)
	}
	state := c.privilegedStore.State()
	if r.Revision <= state.AppliedRevision {
		return c.flushReceipts(ctx)
	}
	if r.UpdateSequence < state.LastSequence {
		return errors.New("stale signed update sequence")
	}
	if err := c.privilegedStore.RecordPending(r); err != nil {
		return err
	}
	// Receipt means received only; it never changes approval or claims completion.
	if r.ReceivedAt == nil {
		id := fmt.Sprintf("received-%d", r.Revision)
		message := &configv1.ReportPrivilegedDeliveryRequest{AgentId: c.agentIDValue(), Revision: r.Revision, State: configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_NEEDS_CONFIRMATION, ProtocolVersion: 2, ReceiptId: id}
		payload, err := proto.Marshal(message)
		if err != nil {
			return err
		}
		if err = c.privilegedStore.Enqueue(privileged.Receipt{ID: id, Kind: "privileged", Payload: payload}); err != nil {
			return err
		}
	}
	hostApply := r.State == configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_APPLYING
	if r.State != configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_AWAITING_AGENT && !hostApply {
		return c.flushReceipts(ctx)
	}
	// A captured, still unexpired approval may already be superseded. Require an
	// online read immediately before granting anything; old signatures cannot revive it.
	currentCtx, cancel := context.WithTimeout(ctx, requestDeadline)
	defer cancel()
	request := connect.NewRequest(&configv1.GetPrivilegedDeliveryRequest{AgentId: c.agentIDValue()})
	c.authorize(request.Header())
	response, err := c.privileged.GetPrivilegedDelivery(currentCtx, request)
	if err != nil {
		return err
	}
	current := response.Msg.GetRevision()
	if err = c.verifyV2Revision(current); err != nil {
		return err
	}
	if current.Revision != r.Revision || current.ConfigHash != r.ConfigHash || current.ApprovalGeneration != r.ApprovalGeneration || current.State != r.State || current.UpdateSequence < r.UpdateSequence || !proto.Equal(current.Authorization, r.Authorization) {
		return errors.New("approval changed before daemon apply")
	}
	r = current
	if c.hostManifest == nil {
		return c.failPrivileged(ctx, r, errors.New("trusted installation manifest required; migrate this service"))
	}
	policy, err := hostops.ReadPolicy(c.hostManifest)
	if err != nil {
		return c.failPrivileged(ctx, r, err)
	}
	actual := capability.Detect(false).PrivilegeMode
	var operation *hostv1.HostOperation
	if hostApply {
		operation, err = c.checkedHostOperation(ctx, r)
		if err != nil {
			return err
		}
	} else {
		err = privileged.ValidateApproval(r, c.agentIDValue(), c.hostManifest.ServiceName, actual)
	}
	if err != nil {
		return c.failPrivileged(ctx, r, err)
	}
	if !runtimeconfig.PolicyAllows(privileged.SettingsFromProto(r.Privileged), policy) {
		return c.failPrivileged(ctx, r, errors.New("approved settings exceed protected local policy"))
	}
	settings := privileged.SettingsFromProto(r.Privileged)
	// Derive capabilities from the checked candidate and actual process identity.
	// GPU availability is independent from configuration acceptance.
	caps := capability.Detect(false)
	caps.RemoteControl.Available = settings.RemoteControlEnabled
	caps.RemoteControl.Limitation = ""
	caps.Webssh.Available = settings.RemoteControlEnabled && settings.WebSSHEnabled
	caps.Webssh.Limitation = ""
	caps.Execution.Available = settings.RemoteControlEnabled && settings.ExecutionEnabled
	caps.Execution.Limitation = ""
	caps.Gpu.Available = settings.EnableGPU
	caps.DetailedGpu.Available = settings.EnableGPU && c.store.Current().DetailedGPU
	helperInstalled, helperRunning, helperAuthorized := false, false, false
	if settings.RescueHelperEnabled {
		status, e := hostops.ReadHelperStatus(c.hostManifest)
		if e != nil || !status.Authorized || !status.LeaseReady {
			return errors.New("approved helper has not reached verified running/authorized/lease-ready status")
		}
		helperInstalled = policy.HelperInstalled
		helperRunning = true
		helperAuthorized = policy.HelperAuthorized
	}
	caps.RescueHelper.Available = settings.RescueHelperEnabled
	id := uuid.NewString()
	message := &configv1.ReportPrivilegedDeliveryRequest{AgentId: c.agentIDValue(), Revision: r.Revision, State: configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED, ProtocolVersion: 2, ReceiptId: id, ConfigHash: r.ConfigHash, ApprovalGeneration: r.ApprovalGeneration, Observation: &hostv1.DaemonObservation{Revision: r.Revision, ConfigHash: r.ConfigHash, ApprovalGeneration: r.ApprovalGeneration, ServiceId: c.hostManifest.ServiceName, StartupId: c.startupID, PrivilegeMode: actual, EffectiveCapabilities: caps, ObservedAt: timestamppb.Now()}}
	message.Observation.HelperInstalled = helperInstalled
	message.Observation.HelperRunning = helperRunning
	message.Observation.HelperAuthorized = helperAuthorized
	message.Observation.HelperLeaseReady = helperRunning && helperAuthorized
	if operation != nil {
		message.Observation.OperationId = operation.OperationId
	}
	payload, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	receipt := privileged.Receipt{ID: id, Kind: "privileged", Payload: payload}
	if operation != nil {
		err = c.privilegedStore.ApplyHostApproved(r, operation, actual, receipt)
	} else {
		err = c.privilegedStore.ApplyApproved(r, actual, receipt)
	}
	if err != nil {
		return err
	}
	return c.flushReceipts(ctx)
}
func (c *Client) failPrivileged(ctx context.Context, r *configv1.PrivilegedRevision, cause error) error {
	id := uuid.NewString()
	message := &configv1.ReportPrivilegedDeliveryRequest{AgentId: c.agentIDValue(), Revision: r.Revision, State: configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_FAILED, ProtocolVersion: 2, ReceiptId: id, ConfigHash: r.ConfigHash, ApprovalGeneration: r.ApprovalGeneration, Errors: []*commonv1.ErrorDetail{{Code: "LOCAL_POLICY_OR_IDENTITY_REJECTED", Message: cause.Error()}}, FinishedAt: timestamppb.Now()}
	payload, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	if err = c.privilegedStore.Enqueue(privileged.Receipt{ID: id, Kind: "privileged", Payload: payload}); err != nil {
		return err
	}
	if err = c.flushReceipts(ctx); err != nil {
		return err
	}
	return cause
}

func waitForCapability(ctx context.Context, allowed func() (bool, string)) bool {
	if ok, _ := allowed(); ok {
		return true
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

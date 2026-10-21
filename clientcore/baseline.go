package clientcore

import (
	"bytes"
	"connectrpc.com/connect"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/signing"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"log"
	"os"
	"path/filepath"
	"time"
)

func (c *Client) localBaseline() privileged.Settings {
	p := c.hostPolicy
	return privileged.Settings{RequiredPrivilegeMode: reportv1.PrivilegeMode(p.PrivilegeMode), RemoteControlEnabled: p.BaselineRemoteControl && !p.ForceDenyRemoteControl && p.AllowRemoteControl, WebSSHEnabled: p.BaselineWebSSH && p.AllowWebSSH, ExecutionEnabled: p.BaselineExecution && p.AllowExecution, EnableGPU: p.BaselineGPU && p.AllowGPU}
}
func (c *Client) initializeHost(parent context.Context) error {
	if c.hostManifest == nil || c.hostPolicy == nil || c.privilegedStore == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, configDeadline)
	defer cancel()
	actual := capability.Detect(false).PrivilegeMode
	if int32(actual) != c.hostPolicy.PrivilegeMode {
		return errors.New("daemon OS identity differs from protected installation policy")
	}
	var actions []hostv1.HostAction
	if hostops.HostActionsReady(c.hostManifest) {
		actions = []hostv1.HostAction{hostv1.HostAction_HOST_ACTION_SET_SERVICE_IDENTITY}
		if c.hostPolicy.AllowRescueHelper && len(c.hostTrust.ReleaseKeys) > 0 {
			actions = append(actions, hostv1.HostAction_HOST_ACTION_INSTALL_RESCUE_HELPER)
		}
		if c.hostPolicy.HelperInstalled {
			actions = append(actions, hostv1.HostAction_HOST_ACTION_REMOVE_RESCUE_HELPER)
		}
	}
	req := connect.NewRequest(&hostv1.NegotiateHostProtocolRequest{AgentId: c.agentIDValue(), ProtocolVersion: 2, ServiceId: c.hostManifest.ServiceName, StartupId: c.startupID, PrivilegeMode: actual, SupportedActions: actions, HostToolVersion: "3-linux-systemd-pam", SupportedRuntimeFields: []uint32{1, 3, 4, 5, 6, 7, 8, 19}})
	c.authorize(req.Header())
	if _, err := c.host.NegotiateHostProtocol(ctx, req); err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(c.privilegedStore.Path()), "bootstrap-request.pb")
	var proposal configv1.InitializeNodeConfigRequest
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// Existing local revisions are migration history, never a fresh install.
		if c.store.Current().Revision != 0 || c.privilegedStore.State().AppliedRevision != 0 || c.privilegedStore.State().PendingRevision != 0 {
			return c.flushReceipts(ctx)
		}
		runtime := c.store.Current()
		local := c.localBaseline()
		policyData, e := os.ReadFile(c.hostManifest.HostPolicyFile)
		if e != nil {
			return e
		}
		policyHash := sha256.Sum256(policyData)
		proposal = configv1.InitializeNodeConfigRequest{AgentId: c.agentIDValue(), ServiceId: c.hostManifest.ServiceName, PolicyHash: hex.EncodeToString(policyHash[:]), Privileged: local.Proto(), Runtime: &configv1.RuntimeConfig{MemoryIncludeCache: &runtime.MemoryIncludeCache, DetailedGpu: &runtime.DetailedGPU, IncludeNics: runtime.IncludeNics, ExcludeNics: runtime.ExcludeNics, IncludeMountpoints: runtime.IncludeMountpoints, ReportInterval: durationpb.New(runtime.ReportInterval), TrafficResetDay: &runtime.TrafficResetDay, GetIpAddrFromNic: &runtime.GetIPAddrFromNIC}}
		data, err = proto.MarshalOptions{Deterministic: true}.Marshal(&proposal)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err = hostops.AtomicWrite(path, data, 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if len(data) > 1<<20 {
			return errors.New("baseline request exceeds size limit")
		}
		if err = proto.Unmarshal(data, &proposal); err != nil {
			return err
		}
	}
	if proposal.AgentId != c.agentIDValue() || proposal.ServiceId != c.hostManifest.ServiceName {
		return errors.New("saved baseline request belongs to another installation")
	}
	call := connect.NewRequest(&proposal)
	c.authorize(call.Header())
	response, err := c.config.InitializeNodeConfig(ctx, call)
	if err != nil {
		return err
	}
	if !response.Msg.Initialized {
		return c.flushReceipts(ctx)
	}
	if response.Msg.Runtime == nil || response.Msg.Privileged == nil {
		return errors.New("incomplete initialization response")
	}
	// Persisted request is immutable across retries; server cannot use the
	// baseline channel to smuggle a later runtime or privileged configuration.
	if response.Msg.Runtime.Revision != 1 || !proto.Equal(response.Msg.Runtime.Runtime, proposal.Runtime) {
		return errors.New("runtime baseline differs from local installation")
	}
	if c.store.Current().Revision < 1 {
		ack := &configv1.AcknowledgeConfigRequest{AgentId: c.agentIDValue(), Revision: 1, Status: configv1.ConfigApplyStatus_CONFIG_APPLY_STATUS_APPLIED, FinishedAt: timestamppb.Now()}
		payload, e := proto.Marshal(ack)
		if e != nil {
			return e
		}
		if _, err = c.store.ApplyWithReceipt(response.Msg.Runtime, payload); err != nil {
			return err
		}
	}
	if c.privilegedStore.State().AppliedRevision <= 1 {
		if err = c.acceptBaseline(ctx, response.Msg.Privileged); err != nil {
			return err
		}
	}
	return c.flushReceipts(ctx)
}

func (c *Client) verifyV2Revision(r *configv1.PrivilegedRevision) error {
	identity, ok := c.identity()
	if !ok {
		return errors.New("enrolled signing identity required")
	}
	// Repeated state observations are idempotent. Their freshness is enforced by
	// revision/generation/sequence; generic nonce consumption must not burn a
	// candidate before it has been durably committed.
	verified, err := signing.New(identity, nil).Verify(r.GetSignature())
	if err != nil {
		return err
	}
	if r.ProtocolVersion != 2 || verified.InstructionType != "komari.config.v2.PrivilegedRevision" {
		return errors.New("v2 signed privileged revision required")
	}
	copy := proto.Clone(r).(*configv1.PrivilegedRevision)
	copy.Signature = nil
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(copy)
	if err != nil {
		return err
	}
	if !bytes.Equal(verified.Body, body) || r.AgentId != identity.AgentID || len(r.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("signed revision body or agent binding mismatch")
	}
	if r.Privileged == nil || len(r.Privileged.ProtoReflect().GetUnknown()) != 0 || r.ConfigHash != privileged.Hash(privileged.SettingsFromProto(r.Privileged)) {
		return errors.New("privileged settings hash or schema mismatch")
	}
	return nil
}
func (c *Client) acceptBaseline(ctx context.Context, r *configv1.PrivilegedRevision) error {
	if c.hostManifest == nil || c.hostPolicy == nil {
		return errors.New("protected local installation policy is required")
	}
	if c.privilegedStore.State().AppliedRevision >= 1 {
		return c.flushReceipts(ctx)
	}
	if err := c.verifyV2Revision(r); err != nil {
		return err
	}
	local := c.localBaseline()
	actual := capability.Detect(false).PrivilegeMode
	a := r.Authorization
	if a == nil || a.ServiceId != c.hostManifest.ServiceName || a.AgentId != c.agentIDValue() || a.Revision != 1 || a.ConfigHash != r.ConfigHash || a.ApprovalGeneration != 1 || a.TargetPrivilegeMode != actual {
		return errors.New("baseline authorization binding mismatch")
	}
	caps := capability.Detect(local.RemoteControlEnabled)
	caps.RemoteControl = &reportv1.CapabilityState{Available: local.RemoteControlEnabled}
	caps.Webssh = &reportv1.CapabilityState{Available: local.RemoteControlEnabled && local.WebSSHEnabled}
	caps.Execution = &reportv1.CapabilityState{Available: local.RemoteControlEnabled && local.ExecutionEnabled}
	caps.Gpu = &reportv1.CapabilityState{Available: local.EnableGPU}
	caps.DetailedGpu = &reportv1.CapabilityState{Available: local.EnableGPU && c.store.Current().DetailedGPU}
	caps.RescueHelper = &reportv1.CapabilityState{}
	receiptID := uuid.NewString()
	ack := &configv1.ReportPrivilegedDeliveryRequest{AgentId: c.agentIDValue(), Revision: 1, State: configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED, ProtocolVersion: 2, ReceiptId: receiptID, ConfigHash: r.ConfigHash, ApprovalGeneration: 1, Observation: &hostv1.DaemonObservation{Revision: 1, ConfigHash: r.ConfigHash, ApprovalGeneration: 1, ServiceId: c.hostManifest.ServiceName, StartupId: c.startupID, PrivilegeMode: actual, EffectiveCapabilities: caps, ObservedAt: timestamppb.Now()}}
	payload, err := proto.Marshal(ack)
	if err != nil {
		return err
	}
	if err = c.privilegedStore.AdoptBaseline(r, local, actual, privileged.Receipt{ID: receiptID, Kind: "privileged", Payload: payload}); err != nil {
		return err
	}
	return c.flushReceipts(ctx)
}
func (c *Client) flushReceipts(parent context.Context) error {
	c.receiptMu.Lock()
	defer c.receiptMu.Unlock()
	for payload := c.store.Receipt(); len(payload) > 0; payload = c.store.Receipt() {
		var message configv1.AcknowledgeConfigRequest
		if err := proto.Unmarshal(payload, &message); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(parent, requestDeadline)
		req := connect.NewRequest(&message)
		c.authorize(req.Header())
		response, err := c.config.AcknowledgeConfig(ctx, req)
		cancel()
		if err == nil && !response.Msg.Accepted {
			err = connect.NewError(connect.CodeFailedPrecondition, errors.New("runtime ACK rejected"))
		}
		if err != nil {
			code := connect.CodeOf(err)
			if code != connect.CodeAborted && code != connect.CodeFailedPrecondition && code != connect.CodeInvalidArgument {
				return err
			}
			log.Printf("Runtime receipt rejected: %v", err)
			if c.privilegedStore != nil {
				if e := c.privilegedStore.Enqueue(privileged.Receipt{ID: uuid.NewString(), Kind: "runtime-rejected", Payload: payload, Rejected: err.Error()}); e != nil {
					return e
				}
			}
		}
		if err := c.store.FinishReceipt(payload); err != nil {
			return err
		}
	}
	if c.privilegedStore == nil {
		return nil
	}
	var first error
	for _, entry := range c.privilegedStore.State().Outbox {
		ctx, cancel := context.WithTimeout(parent, requestDeadline)
		var err error
		switch entry.Kind {
		case "runtime-rejected":
			if e := c.privilegedStore.FinishReceipt(entry.ID, entry.Rejected); e != nil {
				cancel()
				return e
			}
			cancel()
			continue
		case "privileged":
			var message configv1.ReportPrivilegedDeliveryRequest
			err = proto.Unmarshal(entry.Payload, &message)
			if err == nil {
				req := connect.NewRequest(&message)
				c.authorize(req.Header())
				var response *connect.Response[configv1.ReportPrivilegedDeliveryResponse]
				response, err = c.privileged.ReportPrivilegedDelivery(ctx, req)
				if err == nil && !response.Msg.Accepted {
					err = errors.New("privileged receipt was not accepted")
				}
			}
		case "runtime":
			var message configv1.AcknowledgeConfigRequest
			err = proto.Unmarshal(entry.Payload, &message)
			if err == nil {
				req := connect.NewRequest(&message)
				c.authorize(req.Header())
				_, err = c.config.AcknowledgeConfig(ctx, req)
			}
		default:
			err = fmt.Errorf("unsupported outbox kind %s", entry.Kind)
		}
		cancel()
		if err == nil {
			if e := c.privilegedStore.FinishReceipt(entry.ID, ""); e != nil {
				return e
			}
			continue
		}
		if code := connect.CodeOf(err); code == connect.CodeAborted || code == connect.CodeFailedPrecondition || code == connect.CodeInvalidArgument {
			log.Printf("Receipt %s rejected and retained for diagnosis: %v", entry.ID, err)
			if e := c.privilegedStore.FinishReceipt(entry.ID, err.Error()); e != nil {
				return e
			}
			continue
		}
		if first == nil {
			first = err
		}
	}
	return first
}
func (c *Client) runReceiptOutbox(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if err := c.flushReceipts(ctx); err != nil {
			log.Printf("Receipt outbox retry pending: %v", err)
		}
		if c.hostManifest != nil && c.hostTrust != nil {
			if err := c.reconcileHostRecord(ctx); err != nil {
				log.Printf("Host result reconciliation pending: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Client) runHostInitialization(ctx context.Context) {
	var retry retryPolicy
	for ctx.Err() == nil {
		err := c.initializeHost(ctx)
		if err == nil {
			return
		}
		log.Printf("Host initialization retry pending: %v", err)
		if !retry.Wait(ctx, err) {
			return
		}
	}
}

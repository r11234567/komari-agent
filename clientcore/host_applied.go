package clientcore

import (
	"bytes"
	"context"
	"errors"
	"os"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/signing"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	"google.golang.org/protobuf/proto"
)

// A durable observation describes a particular local host result. An explicit
// OS restoration invalidates it, even if its original network ACK was lost.
// Keep the payload for diagnosis rather than reporting an identity we no
// longer run under. Ordinary same-identity receipts retain their old behavior.
var errSavedHostObservationInvalid = errors.New("saved host observation no longer describes the local host")

func (c *Client) validateSavedHostObservation(r *configv1.ReportPrivilegedDeliveryRequest) error {
	o := r.GetObservation()
	if o.GetOperationId() == "" {
		return nil
	}
	if c.hostManifest == nil || c.hostTrust == nil {
		return errSavedHostObservationInvalid
	}
	p, err := hostops.ReadPolicy(c.hostManifest)
	if err != nil {
		return err
	}
	if capability.Detect(false).PrivilegeMode != o.PrivilegeMode || p.PrivilegeMode != int32(o.PrivilegeMode) || p.HelperInstalled != o.HelperInstalled || p.HelperAuthorized != o.HelperAuthorized {
		return errSavedHostObservationInvalid
	}
	var record hostops.AppliedRecord
	if err = hostops.ReadJSON(hostops.AppliedPath(c.hostManifest), &record, true); err != nil {
		if os.IsNotExist(err) {
			return errSavedHostObservationInvalid
		}
		return err
	}
	var revision configv1.PrivilegedRevision
	var operation hostv1.HostOperation
	if err = proto.Unmarshal(record.Revision, &revision); err != nil {
		return err
	}
	if err = proto.Unmarshal(record.Operation, &operation); err != nil {
		return err
	}
	if record.Version != 2 || revision.Revision != o.Revision || revision.ConfigHash != o.ConfigHash || revision.ApprovalGeneration != o.ApprovalGeneration || operation.OperationId != o.OperationId {
		return errSavedHostObservationInvalid
	}
	return nil
}

func (c *Client) validatePersistedPrivileged() error {
	if c.privilegedStore == nil {
		return nil
	}
	state := c.privilegedStore.State()
	if state.AppliedRevision == 0 {
		if state.Active != (privileged.Settings{}) {
			return errors.New("unsigned non-empty privileged state cannot enter a trusted host profile")
		}
		return nil
	}
	var r configv1.PrivilegedRevision
	if err := proto.Unmarshal(state.ActiveSignedRevision, &r); err != nil {
		return err
	}
	id, ok := c.identity()
	if !ok {
		return errors.New("protected signing identity unavailable")
	}
	i, err := signing.New(id, nil).VerifyRecorded(r.Signature)
	if err != nil {
		return err
	}
	copy := proto.Clone(&r).(*configv1.PrivilegedRevision)
	copy.Signature = nil
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(copy)
	if err != nil {
		return err
	}
	if i.InstructionType != "komari.config.v2.PrivilegedRevision" || !bytes.Equal(i.Body, body) || r.AgentId != id.AgentID || r.GetAuthorization().GetServiceId() != c.hostManifest.ServiceName || r.Revision != state.AppliedRevision || r.ConfigHash != privileged.Hash(privileged.SettingsFromProto(r.Privileged)) || !privileged.Subset(state.Active, privileged.SettingsFromProto(r.Privileged)) {
		return errors.New("persisted active privileges do not match the protected signed snapshot")
	}
	return nil
}
func (c *Client) checkedHostOperation(ctx context.Context, r *configv1.PrivilegedRevision) (*hostv1.HostOperation, error) {
	if c.hostTrust == nil {
		return nil, errors.New("protected host trust required")
	}
	var record hostops.AppliedRecord
	if err := hostops.ReadJSON(hostops.AppliedPath(c.hostManifest), &record, true); err != nil {
		return nil, err
	}
	var local configv1.PrivilegedRevision
	var original hostv1.HostOperation
	if err := proto.Unmarshal(record.Revision, &local); err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(record.Operation, &original); err != nil {
		return nil, err
	}
	if record.Version != 2 || !proto.Equal(local.Authorization, r.Authorization) || !proto.Equal(original.Authorization, r.Authorization) || original.OperationId == "" {
		return nil, errors.New("protected host record differs from current approval")
	}
	req := connect.NewRequest(&hostv1.GetHostOperationRequest{AgentId: c.agentIDValue(), OperationId: original.OperationId})
	c.authorize(req.Header())
	resp, err := c.host.GetHostOperation(ctx, req)
	if err != nil {
		return nil, err
	}
	op := resp.Msg.Operation
	if err = hostops.VerifyOperation(c.hostTrust, op, r.Authorization, original.OperationId); err != nil {
		return nil, err
	}
	if op.Phase != hostv1.HostOperationPhase_HOST_OPERATION_PHASE_LOCAL_APPLIED {
		return nil, errors.New("host result has not been recorded as locally applied")
	}
	return op, nil
}
func (c *Client) reconcileHostRecord(ctx context.Context) error {
	var record hostops.AppliedRecord
	if err := hostops.ReadJSON(hostops.AppliedPath(c.hostManifest), &record, true); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var local configv1.PrivilegedRevision
	if err := proto.Unmarshal(record.Revision, &local); err != nil {
		return err
	}
	if local.Revision <= c.privilegedStore.State().AppliedRevision {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, requestDeadline)
	defer cancel()
	req := connect.NewRequest(&configv1.GetPrivilegedDeliveryRequest{AgentId: c.agentIDValue()})
	c.authorize(req.Header())
	resp, err := c.privileged.GetPrivilegedDelivery(ctx, req)
	if err != nil {
		return err
	}
	return c.recordPrivilegedRevision(ctx, resp.Msg.Revision)
}

package privileged

import (
	"errors"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"google.golang.org/protobuf/proto"
	"time"
)

// Subset permits local rollback/restrictions only when no capability is added.
func Subset(a, b Settings) bool {
	return (a.RequiredPrivilegeMode == b.RequiredPrivilegeMode || a.RequiredPrivilegeMode == 0) &&
		(!a.RemoteControlEnabled || b.RemoteControlEnabled) && (!a.WebSSHEnabled || b.WebSSHEnabled) &&
		(!a.ExecutionEnabled || b.ExecutionEnabled) && (!a.EnableGPU || b.EnableGPU) && (!a.RescueHelperEnabled || b.RescueHelperEnabled)
}

// ValidateApproval checks the complete binding after the transport verifies the
// signature and re-reads the current approval online. It never changes OS identity.
func ValidateApproval(r *configv1.PrivilegedRevision, agent, service string, actual reportv1.PrivilegeMode) error {
	a := r.GetAuthorization()
	if r.GetProtocolVersion() != 2 || r.GetInstallationBaseline() || r.GetState() != configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_AWAITING_AGENT || r.GetRevision() == 0 || r.GetApprovalGeneration() == 0 || r.GetSignature() == nil || a == nil {
		return errors.New("current signed v2 same-identity approval required")
	}
	if len(a.ProtoReflect().GetUnknown()) != 0 || a.AgentId != agent || r.AgentId != agent || a.ServiceId != service || service == "" || a.Revision != r.Revision || a.ConfigHash != r.ConfigHash || a.ApprovalGeneration != r.ApprovalGeneration || len(a.Actions) != 0 || a.TargetPrivilegeMode != actual || r.GetPrivileged().GetRequiredPrivilegeMode() != actual || a.Nonce == "" || a.ApprovedBy == "" {
		return errors.New("approval binding, actions or daemon identity mismatch")
	}
	if a.IssuedAt == nil || a.ExpiresAt == nil || a.IssuedAt.CheckValid() != nil || a.ExpiresAt.CheckValid() != nil || a.IssuedAt.AsTime().After(time.Now().Add(time.Minute)) || !time.Now().Before(a.ExpiresAt.AsTime()) || !a.ExpiresAt.AsTime().After(a.IssuedAt.AsTime()) {
		return errors.New("approval is expired or has invalid timestamps")
	}
	settings := SettingsFromProto(r.Privileged)
	if r.ConfigHash != Hash(settings) {
		return errors.New("approval settings hash mismatch")
	}
	if settings.RequiredPrivilegeMode != actual {
		return errors.New("daemon identity differs from approval")
	}
	return nil
}

// ApplyApproved atomically persists the effective snapshot and immutable ACK.
// Only the daemon transport calls this after signature/currentness/policy checks.
func (s *Store) ApplyApproved(r *configv1.PrivilegedRevision, actual reportv1.PrivilegeMode, receipt Receipt) error {
	if err := ValidateApproval(r, r.GetAgentId(), r.GetAuthorization().GetServiceId(), actual); err != nil {
		return err
	}
	return s.commitApproved(r, receipt)
}

// ApplyHostApproved is distinct from same-identity delivery. The transport must
// first validate protected local evidence, a current signed phase-3 operation,
// actual daemon identity and helper observations. It cannot execute OS actions.
func (s *Store) ApplyHostApproved(r *configv1.PrivilegedRevision, op *hostv1.HostOperation, actual reportv1.PrivilegeMode, receipt Receipt) error {
	if r.GetState() != configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_APPLYING || r.GetProtocolVersion() != 2 || op.GetPhase() != hostv1.HostOperationPhase_HOST_OPERATION_PHASE_LOCAL_APPLIED || op.GetOperationId() == "" || !proto.Equal(r.GetAuthorization(), op.GetAuthorization()) || r.GetPrivileged().GetRequiredPrivilegeMode() != actual || r.GetConfigHash() != Hash(SettingsFromProto(r.GetPrivileged())) {
		return errors.New("matching completed host operation and actual identity required")
	}
	return s.commitApproved(r, receipt)
}
func (s *Store) commitApproved(r *configv1.PrivilegedRevision, receipt Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Revision <= s.state.AppliedRevision || r.Revision < s.state.PendingRevision || r.UpdateSequence < s.state.LastSequence {
		return errors.New("stale privileged approval")
	}
	if len(s.state.Outbox) >= 1024 {
		return errors.New("receipt outbox is full")
	}
	encoded, err := proto.Marshal(r)
	if err != nil {
		return err
	}
	next := s.state.clone()
	previous := next.Active
	next.Previous = &previous
	next.PreviousRevision = next.AppliedRevision
	next.Active = SettingsFromProto(r.Privileged)
	next.AppliedRevision = r.Revision
	next.ActiveSignedRevision = encoded
	next.LastSequence = r.UpdateSequence
	next.Outbox = append(next.Outbox, receipt)
	next.clearPending()
	return s.commit(next)
}

// Effective restricts existing grants immediately on a signed withdrawal. An
// unapproved candidate can never add a capability.
func (s *Store) Effective() Settings {
	state := s.State()
	result := state.Active
	if p := state.Pending; p != nil {
		result.RemoteControlEnabled = result.RemoteControlEnabled && p.RemoteControlEnabled
		result.WebSSHEnabled = result.WebSSHEnabled && p.WebSSHEnabled
		result.ExecutionEnabled = result.ExecutionEnabled && p.ExecutionEnabled
		result.EnableGPU = result.EnableGPU && p.EnableGPU
		result.RescueHelperEnabled = result.RescueHelperEnabled && p.RescueHelperEnabled
	}
	return result
}

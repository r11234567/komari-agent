package privileged

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"google.golang.org/protobuf/proto"
	"time"
)

func SettingsFromProto(p *configv1.PrivilegedConfig) Settings { return settingsFromProto(p) }
func (s Settings) Proto() *configv1.PrivilegedConfig {
	return &configv1.PrivilegedConfig{RemoteControlEnabled: &s.RemoteControlEnabled, WebsshEnabled: &s.WebSSHEnabled, ExecutionEnabled: &s.ExecutionEnabled, EnableGpu: &s.EnableGPU, RescueHelperEnabled: &s.RescueHelperEnabled, RequiredPrivilegeMode: s.RequiredPrivilegeMode}
}
func Hash(s Settings) string {
	b := []byte("komari.privileged-settings.v1\x00")
	for _, v := range []bool{s.RemoteControlEnabled, s.WebSSHEnabled, s.ExecutionEnabled, s.EnableGPU, s.RescueHelperEnabled} {
		if v {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	b = binary.BigEndian.AppendUint32(b, uint32(s.RequiredPrivilegeMode))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type Receipt struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Payload  []byte `json:"payload"`
	Rejected string `json:"rejected,omitempty"`
}

func cloneReceipts(in []Receipt) []Receipt {
	out := append([]Receipt(nil), in...)
	for i := range out {
		out[i].Payload = append([]byte(nil), out[i].Payload...)
	}
	return out
}
func (s *Store) AdoptBaseline(r *configv1.PrivilegedRevision, local Settings, actual reportv1.PrivilegeMode, receipt Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !r.GetInstallationBaseline() || r.GetRevision() != 1 || r.GetProtocolVersion() != 2 || r.GetApprovalGeneration() != 1 {
		return errors.New("invalid initial baseline revision")
	}
	if local.RequiredPrivilegeMode != actual || local.RescueHelperEnabled || settingsFromProto(r.Privileged) != local || r.ConfigHash != Hash(local) {
		return errors.New("baseline exceeds protected installation authorization or actual identity")
	}
	if r.Authorization == nil || len(r.Authorization.Actions) != 0 || r.Authorization.ServiceId == "" {
		return errors.New("baseline cannot authorize host actions")
	}
	if s.state.AppliedRevision > 1 || s.state.PendingRevision > 1 {
		return errors.New("baseline cannot replace existing history")
	}
	if s.state.AppliedRevision == 1 && s.state.Active != local {
		return errors.New("baseline conflicts with active revision")
	}
	if len(s.state.Outbox) >= 1024 {
		return errors.New("receipt outbox is full")
	}
	encoded, err := proto.Marshal(r)
	if err != nil {
		return err
	}
	next := s.state.clone()
	next.Active = local
	next.AppliedRevision = 1
	next.ActiveSignedRevision = encoded
	next.Outbox = append(next.Outbox, receipt)
	next.clearPending()
	return s.commit(next)
}
func (s *Store) Enqueue(receipt Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.state.Outbox) >= 1024 {
		return errors.New("receipt outbox is full")
	}
	next := s.state.clone()
	for _, r := range next.Outbox {
		if r.ID == receipt.ID {
			return nil
		}
	}
	next.Outbox = append(next.Outbox, receipt)
	return s.commit(next)
}
func (s *Store) FinishReceipt(id, rejected string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.state.clone()
	var pending []Receipt
	for _, r := range next.Outbox {
		if r.ID != id {
			pending = append(pending, r)
			continue
		}
		if rejected != "" {
			r.Rejected = time.Now().UTC().Format(time.RFC3339) + ": " + rejected
			next.RejectedReceipts = append(next.RejectedReceipts, r)
		}
	}
	next.Outbox = pending
	if len(next.RejectedReceipts) > 128 {
		next.RejectedReceipts = next.RejectedReceipts[len(next.RejectedReceipts)-128:]
	}
	return s.commit(next)
}

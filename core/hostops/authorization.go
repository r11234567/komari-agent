package hostops

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/url"
	"path/filepath"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/signing"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
)

// Trust is pinned explicitly by a local administrator. Daemon enrollment TOFU
// keys must never silently become keys allowed to authorize root operations.
type Trust struct {
	Version     int                     `json:"version"`
	AgentID     string                  `json:"agent_id"`
	Endpoint    string                  `json:"endpoint"`
	ServiceID   string                  `json:"service_id"`
	ServiceUser string                  `json:"service_user"`
	PanelKeys   []credentials.PinnedKey `json:"panel_keys"`
	ReleaseKeys []credentials.PinnedKey `json:"release_keys"`
}

func TrustPath(m *Manifest) string {
	return filepath.Join(filepath.Dir(m.HostPolicyFile), m.ServiceName+".trust.json")
}
func AppliedPath(m *Manifest) string {
	return filepath.Join(filepath.Dir(m.HostPolicyFile), m.ServiceName+".applied.json")
}
func HelperStatusPath(m *Manifest) string {
	return filepath.Join("/run/komari", m.ServiceName+".helper.json")
}
func (t Trust) Identity() credentials.Identity {
	return credentials.Identity{AgentID: t.AgentID, Endpoint: t.Endpoint, ControlPlaneKeys: t.PanelKeys, PolicyAlgorithms: []int32{1}, PolicyMinimumSignatures: 1}
}
func ReadTrust(m *Manifest) (*Trust, error) {
	var t Trust
	if err := ReadJSON(TrustPath(m), &t, true); err != nil {
		return nil, err
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if t.ServiceID != m.ServiceName {
		return nil, errors.New("host trust belongs to another service")
	}
	return &t, nil
}
func (t Trust) Validate() error {
	u, err := url.Parse(t.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("host trust requires HTTPS (HTTP allowed only on loopback), with no userinfo, query or fragment")
	}
	if t.Version != 2 || t.AgentID == "" || !ValidService(t.ServiceID) || !ValidService(t.ServiceUser) || len(t.PanelKeys) == 0 {
		return errors.New("incomplete host trust")
	}
	for _, keys := range [][]credentials.PinnedKey{t.PanelKeys, t.ReleaseKeys} {
		for _, k := range keys {
			b, err := base64.StdEncoding.DecodeString(k.Value)
			if err != nil || len(b) != ed25519.PublicKeySize || k.KeyID == "" || k.Algorithm != 1 {
				return errors.New("host trust requires named Ed25519 public keys")
			}
		}
	}
	return nil
}

func verifyBody(t *Trust, envelope *securityv1.SignedEnvelope, message proto.Message, kind string) error {
	i, err := signing.New(t.Identity(), nil).Verify(envelope)
	if err != nil {
		return err
	}
	if i.InstructionType != kind || len(message.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("host signature type/schema mismatch")
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, i.Body) {
		return errors.New("host signature does not bind the full message")
	}
	return nil
}
func VerifyRevision(t *Trust, r *configv1.PrivilegedRevision) error {
	if err := VerifySignedRevision(t, r); err != nil {
		return err
	}
	a := r.Authorization
	if r.Revision == 0 || r.InstallationBaseline || a == nil || len(a.ProtoReflect().GetUnknown()) != 0 || a.AgentId != t.AgentID || a.ServiceId != t.ServiceID || a.Revision != r.Revision || a.ConfigHash != r.ConfigHash || a.ApprovalGeneration != r.ApprovalGeneration || a.ApprovalGeneration == 0 || a.Nonce == "" || a.ApprovedBy == "" || a.TargetPrivilegeMode != r.Privileged.RequiredPrivilegeMode {
		return errors.New("host revision authorization binding mismatch")
	}
	if a.IssuedAt == nil || a.ExpiresAt == nil || a.IssuedAt.CheckValid() != nil || a.ExpiresAt.CheckValid() != nil || a.IssuedAt.AsTime().After(time.Now().Add(time.Minute)) || !time.Now().Before(a.ExpiresAt.AsTime()) || !a.ExpiresAt.AsTime().After(a.IssuedAt.AsTime()) {
		return errors.New("host approval expired or invalid")
	}
	seen := map[hostv1.HostAction]bool{}
	for _, action := range a.Actions {
		if action < 1 || action > 3 || seen[action] {
			return errors.New("unknown or duplicate host action")
		}
		seen[action] = true
	}
	if seen[2] && seen[3] {
		return errors.New("conflicting helper actions")
	}
	return nil
}
func VerifySignedRevision(t *Trust, r *configv1.PrivilegedRevision) error {
	if r == nil {
		return errors.New("missing privileged revision")
	}
	c := proto.Clone(r).(*configv1.PrivilegedRevision)
	c.Signature = nil
	if err := verifyBody(t, r.Signature, c, "komari.config.v2.PrivilegedRevision"); err != nil {
		return err
	}
	if r.ProtocolVersion != 2 || r.AgentId != t.AgentID || r.Privileged == nil || len(r.Privileged.ProtoReflect().GetUnknown()) != 0 || r.ConfigHash != privileged.Hash(privileged.SettingsFromProto(r.Privileged)) {
		return errors.New("host revision authorization binding mismatch")
	}
	return nil
}
func VerifyOperation(t *Trust, op *hostv1.HostOperation, a *hostv1.HostAuthorization, id string) error {
	if op == nil {
		return errors.New("missing host operation")
	}
	c := proto.Clone(op).(*hostv1.HostOperation)
	c.Signature = nil
	if err := verifyBody(t, op.Signature, c, "komari.host.v1.HostOperation"); err != nil {
		return err
	}
	if op.OperationId != id || id == "" || !proto.Equal(a, op.Authorization) || op.LeaseExpiresAt == nil || op.LeaseExpiresAt.CheckValid() != nil || (op.Phase < 3 && !time.Now().Before(op.LeaseExpiresAt.AsTime())) || op.LeaseExpiresAt.AsTime().After(a.GetExpiresAt().AsTime()) {
		return errors.New("host execution lease binding mismatch or expiry")
	}
	return nil
}

// AppliedRecord is public, root-owned evidence. Only the daemon writes its own
// active snapshot; it independently checks the current server operation first.
type AppliedRecord struct {
	Version   int    `json:"version"`
	Revision  []byte `json:"revision"`
	Operation []byte `json:"operation"`
}
type HelperStatus struct {
	PID        int       `json:"pid"`
	StartTicks uint64    `json:"start_ticks"`
	Executable string    `json:"executable"`
	Authorized bool      `json:"authorized"`
	LeaseReady bool      `json:"lease_ready"`
	ObservedAt time.Time `json:"observed_at"`
}

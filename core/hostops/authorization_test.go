package hostops

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/privileged"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHostSignatureBindsEntireApprovalAndOperation(t *testing.T) {
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := &Trust{Version: 2, AgentID: "node", Endpoint: "https://panel.example", ServiceID: "agent", ServiceUser: "komari", PanelKeys: []credentials.PinnedKey{{Algorithm: 1, KeyID: "panel", Value: base64.StdEncoding.EncodeToString(public)}}}
	sign := func(kind string, m proto.Message) *securityv1.SignedEnvelope {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(m)
		p, _ := proto.Marshal(&securityv1.SignedInstruction{AgentId: "node", Nonce: "nonce", InstructionType: kind, Body: b, IssuedAt: timestamppb.Now(), ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))})
		return &securityv1.SignedEnvelope{Payload: p, Signatures: []*securityv1.Signature{{Algorithm: 1, KeyId: "panel", Value: ed25519.Sign(key, p)}}}
	}
	s := privileged.Settings{RequiredPrivilegeMode: 1}
	r := &configv1.PrivilegedRevision{AgentId: "node", Revision: 2, ProtocolVersion: 2, ApprovalGeneration: 1, ConfigHash: privileged.Hash(s), Privileged: s.Proto(), State: 2, Authorization: &hostv1.HostAuthorization{AgentId: "node", Revision: 2, ApprovalGeneration: 1, ConfigHash: privileged.Hash(s), ServiceId: "agent", Actions: []hostv1.HostAction{1}, TargetPrivilegeMode: 1, Nonce: "nonce", ApprovedBy: "admin", IssuedAt: timestamppb.Now(), ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}}
	r.Signature = sign("komari.config.v2.PrivilegedRevision", r)
	if err := VerifyRevision(trust, r); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*configv1.PrivilegedRevision){"service": func(c *configv1.PrivilegedRevision) { c.Authorization.ServiceId = "other" }, "nonce": func(c *configv1.PrivilegedRevision) { c.Authorization.Nonce = "other" }, "generation": func(c *configv1.PrivilegedRevision) { c.ApprovalGeneration++ }, "identity": func(c *configv1.PrivilegedRevision) { c.Authorization.TargetPrivilegeMode = 2 }, "actions": func(c *configv1.PrivilegedRevision) { c.Authorization.Actions = []hostv1.HostAction{2} }, "config": func(c *configv1.PrivilegedRevision) { c.ConfigHash = "other" }} {
		t.Run(name, func(t *testing.T) {
			c := proto.Clone(r).(*configv1.PrivilegedRevision)
			mutate(c)
			if VerifyRevision(trust, c) == nil {
				t.Fatal("tampered signed authority accepted")
			}
		})
	}
	op := &hostv1.HostOperation{OperationId: "op", Authorization: r.Authorization, Phase: 2, LeaseExpiresAt: r.Authorization.ExpiresAt}
	op.Signature = sign("komari.host.v1.HostOperation", op)
	if err := VerifyOperation(trust, op, r.Authorization, "op"); err != nil {
		t.Fatal(err)
	}
	copy := proto.Clone(op).(*hostv1.HostOperation)
	copy.Phase = 3
	if VerifyOperation(trust, copy, r.Authorization, "op") == nil {
		t.Fatal("forged local completion accepted")
	}
	if VerifyOperation(trust, op, r.Authorization, "other") == nil {
		t.Fatal("operation ID binding ignored")
	}
	// A daemon-supplied signing key is never sufficient for root trust.
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	op.Signature.Signatures[0].Value = ed25519.Sign(attacker, op.Signature.Payload)
	if VerifyOperation(trust, op, r.Authorization, "op") == nil {
		t.Fatal("untrusted daemon key accepted")
	}
}
func TestHelperReleaseRejectsTamperedBinaryPlatformVersionAndKey(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := &Trust{ReleaseKeys: []credentials.PinnedKey{{Algorithm: 1, KeyID: "publisher", Value: base64.StdEncoding.EncodeToString(pub)}}}
	binary := []byte("signed ELF fixture")
	hash := sha256.Sum256(binary)
	p := ReleasePayload{Schema: "komari.release.v1", Component: "komari-agent-rescue", Version: "v1", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: hex.EncodeToString(hash[:])}
	body, _ := json.Marshal(p)
	m := ReleaseManifest{Payload: body, KeyID: "publisher", Signature: ed25519.Sign(key, body)}
	if _, err := VerifyRelease(trust, m, binary); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRelease(trust, m, []byte("modified")); err == nil {
		t.Fatal("binary tampering accepted")
	}
	p.OS = "unsupported"
	body, _ = json.Marshal(p)
	m.Payload = body
	m.Signature = ed25519.Sign(key, body)
	if _, err := VerifyRelease(trust, m, binary); err == nil {
		t.Fatal("wrong platform accepted")
	}
	p.OS = runtime.GOOS
	body, _ = json.Marshal(p)
	m.Payload = body
	m.Signature = ed25519.Sign(key, body)
	m.KeyID = "daemon"
	if _, err := VerifyRelease(trust, m, binary); err == nil {
		t.Fatal("untrusted release key accepted")
	}
}

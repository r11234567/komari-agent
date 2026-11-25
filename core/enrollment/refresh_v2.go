package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/signing"
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
)

type refreshV2Request struct {
	Protocol     int     `json:"protocol"`
	AgentID      string  `json:"agent_id"`
	RefreshToken string  `json:"refresh_token"`
	RequestID    string  `json:"request_id"`
	Generation   *uint64 `json:"generation"`
	Timestamp    string  `json:"timestamp"`
	Nonce        string  `json:"nonce"`
}
type refreshV2Response struct {
	Protocol          int    `json:"protocol"`
	AgentID           string `json:"agent_id"`
	RequestID         string `json:"request_id"`
	Generation        uint64 `json:"generation"`
	CredentialsSHA256 string `json:"credentials_sha256"`
}

func signRefreshV2(identity credentials.Identity) (*securityv1.SignedEnvelope, error) {
	if identity.PendingRefresh == nil {
		return nil, errors.New("pending refresh missing")
	}
	if _, err := uuid.Parse(identity.PendingRefresh.RequestID); err != nil {
		return nil, errors.New("invalid pending refresh ID")
	}
	key, err := identity.SigningKey()
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(refreshV2Request{Protocol: 2, AgentID: identity.AgentID, RefreshToken: identity.RefreshToken, RequestID: identity.PendingRefresh.RequestID, Generation: identity.Generation, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: uuid.NewString()})
	if err != nil {
		return nil, err
	}
	return &securityv1.SignedEnvelope{Payload: payload, Signatures: []*securityv1.Signature{{Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519, Value: ed25519.Sign(key, payload), KeyId: identity.KeyID}}}, nil
}

func verifyRefreshV2Response(envelope *securityv1.SignedEnvelope, identity credentials.Identity, issued *enrollmentv1.AgentCredentials) (uint64, error) {
	rejected := errors.New("unbound or invalid versioned credential response")
	if envelope == nil || len(envelope.Payload) > 4096 || issued == nil || identity.PendingRefresh == nil {
		return 0, rejected
	}
	if _, err := signing.New(identity, nil).VerifyEnvelopeSignatures(envelope); err != nil {
		return 0, err
	}
	var proof refreshV2Response
	decoder := json.NewDecoder(bytes.NewReader(envelope.Payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return 0, rejected
	}
	if proof.Protocol != 2 || proof.AgentID != identity.AgentID || issued.AgentId != identity.AgentID || proof.RequestID != identity.PendingRefresh.RequestID || proof.Generation == 0 {
		return 0, rejected
	}
	if identity.Generation != nil && (*identity.Generation == ^uint64(0) || proof.Generation != *identity.Generation+1) {
		return 0, rejected
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(issued)
	if err != nil {
		return 0, rejected
	}
	digest := sha256.Sum256(raw)
	if proof.CredentialsSHA256 != hex.EncodeToString(digest[:]) || issued.AccessToken == "" || issued.RefreshToken == "" || issued.AccessToken == identity.AccessToken || issued.RefreshToken == identity.RefreshToken {
		return 0, rejected
	}
	if issued.AccessTokenExpiresAt == nil || issued.RefreshTokenExpiresAt == nil || issued.AccessTokenExpiresAt.CheckValid() != nil || issued.RefreshTokenExpiresAt.CheckValid() != nil || !time.Now().Before(issued.AccessTokenExpiresAt.AsTime()) || !time.Now().Before(issued.RefreshTokenExpiresAt.AsTime()) {
		return 0, rejected
	}
	return proof.Generation, nil
}

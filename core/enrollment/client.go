// Package enrollment drives the Agent side of the device authorization grant.
//
// The flow is poll-based, and that is not a fallback. An Agent on a private
// mesh with its public ports closed cannot receive an inbound callback, so a
// redirect-based grant would be impossible on exactly the hosts this targets.
// The Agent asks for a code, prints a link, and polls until a human approves
// in a browser.
package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1/enrollmentv1connect"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	requestTimeout = 30 * time.Second
	// minimumPollInterval bounds how fast the Agent polls even if the server
	// asks for something unreasonable, so a misconfigured panel cannot turn
	// every enrolling Agent into a load source.
	minimumPollInterval = 2 * time.Second
	defaultPollInterval = 5 * time.Second
	maximumPollInterval = 30 * time.Second
)

// Client talks to the enrollment service. It is used before the Agent has any
// credentials, so nothing here requires authentication except the refresh
// call, which authenticates with the refresh token itself.
type Client struct {
	service  enrollmentv1connect.EnrollmentServiceClient
	endpoint string
}

// Progress reports what the operator should do. It is a callback rather than
// direct printing so the same flow serves an interactive login and a scripted
// install that renders the prompt differently.
type Progress func(Instruction)

// Instruction is what a human needs in order to approve this Agent.
type Instruction struct {
	VerificationURI         string
	VerificationURIComplete string
	UserCode                string
	ExpiresAt               time.Time
}

// New builds a client for one control plane endpoint.
func New(endpoint string, httpClient connect.HTTPClient) (*Client, error) {
	baseURL, err := normalizeEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}
	return &Client{
		service:  enrollmentv1connect.NewEnrollmentServiceClient(httpClient, baseURL),
		endpoint: baseURL,
	}, nil
}

// Endpoint reports the normalized control plane URL this client enrolls with.
func (c *Client) Endpoint() string { return c.endpoint }

// Enroll runs the whole grant and returns a complete identity.
//
// Enroll runs the whole grant and returns a complete identity.
//
// The keypair is generated here and the private half never leaves this
// process, so the credentials the server issues are bound to a key only this
// machine holds.
func (c *Client) Enroll(ctx context.Context, scopes []string, progress Progress) (credentials.Identity, error) {
	return c.enroll(ctx, scopes, "", progress)
}

// Reauth re-authenticates an already-registered agent whose refresh token has
// expired. It reuses the existing keypair and agent ID so the panel presents
// this as a re-authorization of a known machine rather than a brand-new
// enrollment.
func (c *Client) Reauth(ctx context.Context, identity credentials.Identity, progress Progress) (credentials.Identity, error) {
	if identity.AgentID == "" {
		return identity, errors.New("no agent ID is stored; run komari-agent login")
	}
	next, err := c.enroll(ctx, identity.Scopes, identity.AgentID, progress)
	if err != nil {
		return identity, err
	}
	// Preserve the keypair and trust bundle: re-auth renews credentials, it
	// does not replace identity.
	next.PrivateKey = identity.PrivateKey
	next.PublicKey = identity.PublicKey
	next.KeyID = identity.KeyID
	next.ControlPlaneKeys = identity.ControlPlaneKeys
	next.PolicyAlgorithms = identity.PolicyAlgorithms
	next.PolicyRequireAll = identity.PolicyRequireAll
	next.PolicyMinimumSignatures = identity.PolicyMinimumSignatures
	next.EnrolledAt = identity.EnrolledAt
	return next, nil
}

func (c *Client) enroll(ctx context.Context, scopes []string, existingAgentID string, progress Progress) (credentials.Identity, error) {
	publicKey, privateKey, keyID, err := credentials.GenerateKeypair()
	if err != nil {
		return credentials.Identity{}, err
	}
	rawPublic, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return credentials.Identity{}, fmt.Errorf("encode agent public key: %w", err)
	}

	req := &enrollmentv1.BeginEnrollmentRequest{
		AgentPublicKey: &securityv1.PublicKey{
			Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
			Value:     rawPublic,
			KeyId:     keyID,
		},
		Device:          localDevice(),
		RequestedScopes: scopes,
	}
	if existingAgentID != "" {
		req.ExistingAgentId = &existingAgentID
	}
	begin, err := c.service.BeginEnrollment(ctx, connect.NewRequest(req))
	if err != nil {
		return credentials.Identity{}, fmt.Errorf("begin enrollment: %w", err)
	}

	instruction := Instruction{
		VerificationURI:         begin.Msg.GetVerificationUri(),
		VerificationURIComplete: begin.Msg.GetVerificationUriComplete(),
		UserCode:                begin.Msg.GetUserCode(),
	}
	if expires := begin.Msg.GetExpiresAt(); expires.IsValid() {
		instruction.ExpiresAt = expires.AsTime()
	}
	if progress != nil {
		progress(instruction)
	}

	interval := boundInterval(begin.Msg.GetPollInterval().AsDuration())
	deviceCode := begin.Msg.GetDeviceCode()
	if strings.TrimSpace(deviceCode) == "" {
		return credentials.Identity{}, errors.New("control plane did not issue a device code")
	}

	for {
		// Waiting before the first poll is deliberate: the human has not had
		// time to open the link yet, so an immediate poll only ever returns
		// pending.
		select {
		case <-ctx.Done():
			return credentials.Identity{}, ctx.Err()
		case <-time.After(interval):
		}

		poll, err := c.service.PollEnrollment(ctx, connect.NewRequest(&enrollmentv1.PollEnrollmentRequest{
			DeviceCode: deviceCode,
		}))
		if err != nil {
			return credentials.Identity{}, fmt.Errorf("poll enrollment: %w", err)
		}
		if next := poll.Msg.GetPollInterval().AsDuration(); next > 0 {
			interval = boundInterval(next)
		}

		switch poll.Msg.GetState() {
		case enrollmentv1.EnrollmentState_ENROLLMENT_STATE_PENDING:
			continue
		case enrollmentv1.EnrollmentState_ENROLLMENT_STATE_SLOW_DOWN:
			// The server is asking for room rather than refusing, so back off
			// instead of failing the enrollment.
			interval = boundInterval(interval * 2)
			continue
		case enrollmentv1.EnrollmentState_ENROLLMENT_STATE_APPROVED:
			issued := poll.Msg.GetCredentials()
			if issued == nil {
				return credentials.Identity{}, errors.New("control plane approved enrollment without issuing credentials")
			}
			return credentials.Identity{
				Endpoint:              c.endpoint,
				AgentID:               issued.GetAgentId(),
				PrivateKey:            privateKey,
				PublicKey:             publicKey,
				KeyID:                 keyID,
				AccessToken:           issued.GetAccessToken(),
				AccessTokenExpiresAt:  timeOrZero(issued.GetAccessTokenExpiresAt()),
				RefreshToken:          issued.GetRefreshToken(),
				RefreshTokenExpiresAt: timeOrZero(issued.GetRefreshTokenExpiresAt()),
				Scopes:                issued.GetScopes(),
				EnrolledAt:            time.Now().UTC(),
			}, nil
		case enrollmentv1.EnrollmentState_ENROLLMENT_STATE_DENIED:
			return credentials.Identity{}, errors.New("enrollment was denied in the control plane")
		case enrollmentv1.EnrollmentState_ENROLLMENT_STATE_EXPIRED:
			return credentials.Identity{}, errors.New("enrollment request expired before it was approved")
		default:
			if detail := poll.Msg.GetError(); detail != nil {
				return credentials.Identity{}, fmt.Errorf("enrollment failed: %s", detail.GetMessage())
			}
			return credentials.Identity{}, errors.New("control plane returned an unrecognized enrollment state")
		}
	}
}

// Refresh rotates the credential pair.
//
// The refresh token alone is not sufficient: the request carries a signature
// made with the enrolled key, so a leaked refresh token cannot mint new
// credentials on its own.
func (c *Client) Refresh(ctx context.Context, identity credentials.Identity) (credentials.Identity, error) {
	if strings.TrimSpace(identity.RefreshToken) == "" {
		return identity, errors.New("no refresh token is stored; run komari-agent login")
	}
	proof, err := signRefreshProof(identity)
	if err != nil {
		return identity, err
	}
	response, err := c.service.RefreshCredentials(ctx, connect.NewRequest(&enrollmentv1.RefreshCredentialsRequest{
		RefreshToken: identity.RefreshToken,
		Proof:        proof,
	}))
	if err != nil {
		return identity, fmt.Errorf("refresh credentials: %w", err)
	}
	// If the panel signed its response, verify it before accepting the new
	// credentials. A response without a proof is accepted on its own: not all
	// panel versions sign yet, and refusing a valid rotation because the proof
	// is absent would lock out more agents than the verification protects.
	// Once panels universally sign, this can be tightened to require a proof.
	if envelope := response.Msg.GetProof(); envelope != nil && len(identity.ControlPlaneKeys) > 0 {
		if err := verifyResponseEnvelope(envelope, identity); err != nil {
			return identity, fmt.Errorf("refresh response signature rejected: %w", err)
		}
	}
	issued := response.Msg.GetCredentials()
	if issued == nil {
		return identity, errors.New("control plane returned no credentials")
	}
	next := identity
	if id := issued.GetAgentId(); id != "" {
		next.AgentID = id
	}
	next.AccessToken = issued.GetAccessToken()
	next.AccessTokenExpiresAt = timeOrZero(issued.GetAccessTokenExpiresAt())
	if token := issued.GetRefreshToken(); token != "" {
		next.RefreshToken = token
		next.RefreshTokenExpiresAt = timeOrZero(issued.GetRefreshTokenExpiresAt())
	}
	if scopes := issued.GetScopes(); len(scopes) > 0 {
		next.Scopes = scopes
	}
	return next, nil
}

// FetchTrustBundle retrieves the control-plane signing keys and policy.
func (c *Client) FetchTrustBundle(ctx context.Context, agentID string) ([]credentials.PinnedKey, []int32, bool, uint32, error) {
	response, err := c.service.GetTrustBundle(ctx, connect.NewRequest(&enrollmentv1.GetTrustBundleRequest{
		AgentId: agentID,
	}))
	if err != nil {
		return nil, nil, false, 0, fmt.Errorf("fetch trust bundle: %w", err)
	}
	keys := make([]credentials.PinnedKey, 0, len(response.Msg.GetSigningKeys()))
	for _, key := range response.Msg.GetSigningKeys() {
		pinned := credentials.PinnedKey{
			Algorithm: int32(key.GetAlgorithm()),
			Value:     base64.StdEncoding.EncodeToString(key.GetValue()),
			KeyID:     key.GetKeyId(),
			NotBefore: timeOrZero(key.GetNotBefore()),
		}
		if expiry := key.GetNotAfter(); expiry.IsValid() {
			at := expiry.AsTime()
			pinned.NotAfter = &at
		}
		keys = append(keys, pinned)
	}
	policy := response.Msg.GetPolicy()
	algorithms := make([]int32, 0, len(policy.GetAcceptedAlgorithms()))
	for _, algorithm := range policy.GetAcceptedAlgorithms() {
		algorithms = append(algorithms, int32(algorithm))
	}
	return keys, algorithms, policy.GetRequireAll(), policy.GetMinimumSignatures(), nil
}

// verifyResponseEnvelope checks that a SignedEnvelope from the panel verifies
// against at least one of the pinned control-plane keys. It is intentionally
// simpler than the full signing.Verifier: refresh responses carry no nonce or
// agent-binding fields, so replay and binding checks are omitted here; the
// request proof already binds the exchange to this agent and this token.
func verifyResponseEnvelope(envelope *securityv1.SignedEnvelope, identity credentials.Identity) error {
	payload := envelope.GetPayload()
	if len(payload) == 0 {
		return errors.New("signed response envelope has no payload")
	}
	for _, sig := range envelope.GetSignatures() {
		alg := sig.GetAlgorithm()
		if alg != securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519 {
			// Only Ed25519 is implemented; other algorithms are skipped rather
			// than failed so a dual-signed envelope from a newer panel still
			// verifies against the Ed25519 key an older agent understands.
			continue
		}
		for _, pinned := range identity.ControlPlaneKeys {
			if int32(alg) != pinned.Algorithm {
				continue
			}
			if sig.GetKeyId() != "" && pinned.KeyID != "" && sig.GetKeyId() != pinned.KeyID {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(pinned.Value)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				continue
			}
			if ed25519.Verify(ed25519.PublicKey(raw), payload, sig.GetValue()) {
				return nil
			}
		}
	}
	return errors.New("no pinned control-plane key verified the refresh response signature")
}


//
// The operator typed the panel's domain by hand, so first contact is where
// trust is established. Showing the fingerprint is what lets a later
// substitution be noticed rather than silently accepted.
func Fingerprint(key credentials.PinnedKey) string {
	raw, err := base64.StdEncoding.DecodeString(key.Value)
	if err != nil {
		return "unreadable"
	}
	digest := sha256.Sum256(raw)
	return base64.RawStdEncoding.EncodeToString(digest[:])
}

// signRefreshProof signs the refresh token with the enrolled key.
func signRefreshProof(identity credentials.Identity) (*securityv1.SignedEnvelope, error) {
	key, err := identity.SigningKey()
	if err != nil {
		return nil, err
	}
	// The payload binds the agent, the token being exchanged and a timestamp,
	// so a captured proof is not reusable for a different agent or
	// indefinitely.
	payload := []byte(strings.Join([]string{
		"komari-refresh-v1",
		identity.AgentID,
		identity.RefreshToken,
		time.Now().UTC().Format(time.RFC3339),
	}, "\n"))
	signature := ed25519.Sign(key, payload)
	return &securityv1.SignedEnvelope{
		Payload: payload,
		Signatures: []*securityv1.Signature{{
			Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
			Value:     signature,
			KeyId:     identity.KeyID,
		}},
	}, nil
}

func localDevice() *enrollmentv1.DeviceIdentity {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return &enrollmentv1.DeviceIdentity{
		Hostname:        hostname,
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
		Fingerprint:     hostFingerprint(hostname),
	}
}

// hostFingerprint is a stable identifier used to recognize a re-enrollment of
// the same machine. It is derived from machine-id where available so that a
// hostname change does not look like a different host.
func hostFingerprint(hostname string) string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(path); err == nil {
			if value := strings.TrimSpace(string(data)); value != "" {
				digest := sha256.Sum256([]byte(value))
				return base64.RawURLEncoding.EncodeToString(digest[:16])
			}
		}
	}
	digest := sha256.Sum256([]byte(hostname + "|" + runtime.GOOS + "|" + runtime.GOARCH))
	return base64.RawURLEncoding.EncodeToString(digest[:16])
}

func normalizeEndpoint(endpoint string) (string, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "", errors.New("a control plane endpoint is required")
	}
	if !strings.Contains(trimmed, "://") {
		// An operator typing a bare domain means the panel, and defaulting to
		// HTTPS is the safe reading of an ambiguous input.
		trimmed = "https://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid control plane endpoint %q: %w", endpoint, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("control plane endpoint must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("control plane endpoint %q has no host", endpoint)
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func boundInterval(value time.Duration) time.Duration {
	if value <= 0 {
		return defaultPollInterval
	}
	if value < minimumPollInterval {
		return minimumPollInterval
	}
	if value > maximumPollInterval {
		return maximumPollInterval
	}
	return value
}

func timeOrZero(value *timestamppb.Timestamp) time.Time {
	if value == nil || !value.IsValid() {
		return time.Time{}
	}
	return value.AsTime().UTC()
}

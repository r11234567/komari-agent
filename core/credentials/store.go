// Package credentials owns the Agent's enrolled identity on disk.
//
// An enrolled Agent holds three things: a keypair it generated itself, a
// short-lived access token, and a long-lived refresh token. The keypair is
// what makes the tokens more than bearer secrets: a stolen access token alone
// does not let an attacker refresh, because refreshing is proved with the key.
//
// Everything here is written with the narrowest permissions the platform
// offers and never logged. The public half is safe to print; the private half
// and both tokens are not, so this package deliberately exposes no String or
// MarshalJSON that could put them into a log line by accident.
package credentials

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	fileMode      = 0o600
	directoryMode = 0o700
	// refreshSkew is how long before expiry a refresh is attempted. An access
	// token that expires mid-request would otherwise surface as an
	// authentication failure that looks like a revoked credential.
	refreshSkew = 5 * time.Minute
)

// Identity is the persisted enrollment. Field names are stable because this
// file is read by a newer Agent after an upgrade.
type Identity struct {
	// Endpoint is the control plane this identity belongs to. It is recorded
	// so an Agent pointed at a different panel does not silently present
	// credentials minted elsewhere.
	Endpoint string `json:"endpoint"`
	AgentID  string `json:"agent_id"`

	// PrivateKey and PublicKey are the Agent's own Ed25519 keypair, base64
	// standard encoding. The private key never leaves this file.
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	KeyID      string `json:"key_id"`

	AccessToken           string    `json:"access_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	Scopes                []string  `json:"scopes,omitempty"`

	// ControlPlaneKeys are the signing keys this Agent will accept for signed
	// instructions, pinned on first contact. Trust here is established on
	// first use: the operator typed the panel's domain by hand, so recording
	// what answered is what lets a later substitution be detected.
	ControlPlaneKeys []PinnedKey `json:"control_plane_keys,omitempty"`
	// PolicyRequireAll and PolicyMinimumSignatures mirror the delivered
	// verification policy so an offline Agent still enforces the last one it
	// was told about rather than falling back to something weaker.
	PolicyAlgorithms        []int32 `json:"policy_algorithms,omitempty"`
	PolicyRequireAll        bool    `json:"policy_require_all,omitempty"`
	PolicyMinimumSignatures uint32  `json:"policy_minimum_signatures,omitempty"`

	EnrolledAt time.Time `json:"enrolled_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PinnedKey is one accepted control-plane signing key.
type PinnedKey struct {
	Algorithm int32      `json:"algorithm"`
	Value     string     `json:"value"`
	KeyID     string     `json:"key_id"`
	NotBefore time.Time  `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
}

// Store serializes access to the identity file.
type Store struct {
	mu       sync.RWMutex
	path     string
	identity *Identity
}

// DefaultPath follows the same convention as the runtime config snapshot, so
// an operator finds both files in one place.
func DefaultPath() string {
	directory, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(directory) == "" {
		return ".komari-credentials.json"
	}
	return filepath.Join(directory, "komari-agent", "credentials.json")
}

// Open loads the identity file, returning a Store with no identity when the
// file does not exist. A missing file is the normal state before enrollment,
// so it is not an error.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	store := &Store{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	var identity Identity
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, fmt.Errorf("decode credentials: %w", err)
	}
	store.identity = &identity
	return store, nil
}

// Path reports where this store persists, for operator-facing messages.
func (s *Store) Path() string { return s.path }

// Enrolled reports whether a usable identity is present.
func (s *Store) Enrolled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.identity != nil && s.identity.AgentID != "" && s.identity.RefreshToken != ""
}

// Identity returns a copy. Callers cannot mutate stored state by accident.
func (s *Store) Identity() (Identity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.identity == nil {
		return Identity{}, false
	}
	return *s.identity.clone(), true
}

// GenerateKeypair creates the Agent's own keypair for a new enrollment.
//
// The key is generated locally and the private half is never transmitted,
// which is what lets the control plane bind credentials to this specific
// machine rather than to whoever holds a token.
func GenerateKeypair() (publicKey, privateKey, keyID string, err error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate agent key: %w", err)
	}
	digest := sha256.Sum256(public)
	return base64.StdEncoding.EncodeToString(public),
		base64.StdEncoding.EncodeToString(private),
		base64.RawURLEncoding.EncodeToString(digest[:16]),
		nil
}

// SigningKey decodes the stored private key for signing.
func (identity Identity) SigningKey() (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(identity.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode agent private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("stored agent private key has an unexpected size")
	}
	return ed25519.PrivateKey(raw), nil
}

// Save writes a complete identity, replacing whatever was stored.
func (s *Store) Save(identity Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity.UpdatedAt = time.Now().UTC()
	if identity.EnrolledAt.IsZero() {
		identity.EnrolledAt = identity.UpdatedAt
	}
	if err := s.persist(&identity); err != nil {
		return err
	}
	s.identity = identity.clone()
	return nil
}

// UpdateCredentials records a rotated credential pair, leaving the keypair and
// pinned trust untouched.
func (s *Store) UpdateCredentials(agentID, accessToken string, accessExpiry time.Time, refreshToken string, refreshExpiry time.Time, scopes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.identity == nil {
		return errors.New("agent is not enrolled")
	}
	next := s.identity.clone()
	if agentID != "" {
		next.AgentID = agentID
	}
	next.AccessToken = accessToken
	next.AccessTokenExpiresAt = accessExpiry
	// An empty refresh token means the server chose not to rotate it, which is
	// valid: keeping the existing one is better than clearing the only way
	// back to an authenticated state.
	if refreshToken != "" {
		next.RefreshToken = refreshToken
		next.RefreshTokenExpiresAt = refreshExpiry
	}
	if len(scopes) > 0 {
		next.Scopes = append([]string(nil), scopes...)
	}
	next.UpdatedAt = time.Now().UTC()
	if err := s.persist(next); err != nil {
		return err
	}
	s.identity = next
	return nil
}

// PinTrustBundle records the accepted signing keys and verification policy.
func (s *Store) PinTrustBundle(keys []PinnedKey, algorithms []int32, requireAll bool, minimum uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.identity == nil {
		return errors.New("agent is not enrolled")
	}
	next := s.identity.clone()
	next.ControlPlaneKeys = append([]PinnedKey(nil), keys...)
	next.PolicyAlgorithms = append([]int32(nil), algorithms...)
	next.PolicyRequireAll = requireAll
	next.PolicyMinimumSignatures = minimum
	next.UpdatedAt = time.Now().UTC()
	if err := s.persist(next); err != nil {
		return err
	}
	s.identity = next
	return nil
}

// Clear removes the stored identity, for an explicit logout.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove credentials: %w", err)
	}
	s.identity = nil
	return nil
}

// NeedsRefresh reports whether the access token is expired or close enough to
// expiry that it should be rotated before the next request.
func (identity Identity) NeedsRefresh(now time.Time) bool {
	if identity.AccessToken == "" {
		return true
	}
	if identity.AccessTokenExpiresAt.IsZero() {
		// A server that declines to state an expiry is taken at its word
		// rather than being refreshed on every call.
		return false
	}
	return now.Add(refreshSkew).After(identity.AccessTokenExpiresAt)
}

// RefreshExpired reports whether re-enrollment is the only way back. This is
// the condition that requires a human, and the one komari-refresh explains.
func (identity Identity) RefreshExpired(now time.Time) bool {
	if identity.RefreshToken == "" {
		return true
	}
	if identity.RefreshTokenExpiresAt.IsZero() {
		return false
	}
	return now.After(identity.RefreshTokenExpiresAt)
}

// persist writes atomically: a crash mid-write must not leave a truncated
// identity, because that would cost the operator a re-enrollment on every
// host it happened to.
func (s *Store) persist(identity *Identity) error {
	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return fmt.Errorf("create credentials directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".komari-credentials-*")
	if err != nil {
		return fmt.Errorf("create credentials temp file: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(fileMode); err != nil {
		temporary.Close()
		return fmt.Errorf("restrict credentials permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write credentials: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("flush credentials: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close credentials: %w", err)
	}
	if err := os.Rename(name, s.path); err != nil {
		return fmt.Errorf("replace credentials: %w", err)
	}
	return nil
}

func (identity *Identity) clone() *Identity {
	if identity == nil {
		return nil
	}
	copied := *identity
	copied.Scopes = append([]string(nil), identity.Scopes...)
	copied.PolicyAlgorithms = append([]int32(nil), identity.PolicyAlgorithms...)
	copied.ControlPlaneKeys = append([]PinnedKey(nil), identity.ControlPlaneKeys...)
	return &copied
}

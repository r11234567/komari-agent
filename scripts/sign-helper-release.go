//go:build ignore

// Called by release CI. The private key is read only from an environment secret
// and is never included in logs, arguments, artifacts or the generated manifest.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/komari-monitor/komari-agent/core/hostops"
)

type publisherKey struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// The private key is provisioned once, independently of release runs and node
// enrollment. Check it against the reviewed publisher public key before signing.
func loadSigningKey(encoded, id, publicPath string) (ed25519.PrivateKey, error) {
	if encoded == "" {
		return nil, fmt.Errorf("repository secret KOMARI_RELEASE_SIGNING_KEY is not configured")
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("KOMARI_RELEASE_SIGNING_KEY must contain a base64 Ed25519 private key (64 bytes)")
	}
	if id == "" {
		return nil, fmt.Errorf("repository variable KOMARI_RELEASE_SIGNING_KEY_ID is not configured")
	}
	b, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, fmt.Errorf("read publisher public key: %w", err)
	}
	var publisher publisherKey
	if err := json.Unmarshal(b, &publisher); err != nil {
		return nil, fmt.Errorf("decode publisher public key: %w", err)
	}
	public, err := base64.StdEncoding.DecodeString(publisher.PublicKey)
	if err != nil || publisher.Algorithm != "Ed25519" || publisher.KeyID != id || len(public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("publisher public key metadata does not match the configured signing identity")
	}
	// Validate both halves, including keys with a correct public suffix but an
	// unrelated seed. Such malformed keys would otherwise emit invalid signatures.
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(derived, key) || !bytes.Equal(derived[ed25519.SeedSize:], public) {
		return nil, fmt.Errorf("release signing private key does not match the pinned publisher public key")
	}
	return ed25519.PrivateKey(key), nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	checkOnly := len(os.Args) == 2 && os.Args[1] == "--check"
	if !checkOnly && len(os.Args) != 5 {
		return fmt.Errorf("usage: sign-helper-release.go --check | BINARY VERSION OS ARCH")
	}
	id := os.Getenv("KOMARI_RELEASE_SIGNING_KEY_ID")
	key, err := loadSigningKey(os.Getenv("KOMARI_RELEASE_SIGNING_KEY"), id, "docs/release-signing-key.json")
	if err != nil {
		return err
	}
	if checkOnly {
		fmt.Println("Publisher signing configuration matches the pinned public key:", id)
		return nil
	}
	for _, value := range os.Args[2:] {
		if value == "" {
			return fmt.Errorf("release version, OS and architecture must not be empty")
		}
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	hash := sha256.Sum256(b)
	p, err := json.Marshal(hostops.ReleasePayload{Schema: "komari.release.v1", Component: "komari-agent-rescue", Version: os.Args[2], OS: os.Args[3], Arch: os.Args[4], SHA256: hex.EncodeToString(hash[:])})
	if err != nil {
		return err
	}
	out, err := json.Marshal(hostops.ReleaseManifest{Payload: p, KeyID: id, Signature: ed25519.Sign(key, p)})
	if err != nil {
		return err
	}
	return os.WriteFile(os.Args[1]+".release.json", append(out, '\n'), 0o644)
}

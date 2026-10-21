//go:build ignore

// Called by release CI. The private key is read only from an environment secret
// and is never included in logs, arguments, artifacts or the generated manifest.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 5 {
		return fmt.Errorf("usage: sign-helper-release.go BINARY VERSION OS ARCH")
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("KOMARI_RELEASE_SIGNING_KEY"))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("KOMARI_RELEASE_SIGNING_KEY must contain a base64 Ed25519 private key")
	}
	id := os.Getenv("KOMARI_RELEASE_SIGNING_KEY_ID")
	if id == "" {
		return fmt.Errorf("KOMARI_RELEASE_SIGNING_KEY_ID is required")
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

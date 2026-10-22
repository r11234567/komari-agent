//go:build ignore

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
)

func TestSigningConfigurationRejectsMissingOrMismatchedAuthority(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "publisher.json")
	metadata, err := json.Marshal(publisherKey{"test-publisher", "Ed25519", base64.StdEncoding.EncodeToString(public)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, metadata, 0600); err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(private)
	malformed := append([]byte(nil), private...)
	copy(malformed[:ed25519.SeedSize], other[:ed25519.SeedSize])
	for _, tc := range []struct{ name, key, id, path string }{
		{"missing secret", "", "test-publisher", path},
		{"invalid encoding", "not-base64", "test-publisher", path},
		{"seed instead of private key", base64.StdEncoding.EncodeToString(private[:ed25519.SeedSize]), "test-publisher", path},
		{"missing key ID", encoded, "", path},
		{"wrong key ID", encoded, "different", path},
		{"wrong private key", base64.StdEncoding.EncodeToString(other), "test-publisher", path},
		{"inconsistent key halves", base64.StdEncoding.EncodeToString(malformed), "test-publisher", path},
		{"missing public metadata", encoded, "test-publisher", path + ".missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadSigningKey(tc.key, tc.id, tc.path)
			if err == nil {
				t.Fatal("invalid signing configuration accepted")
			}
			if strings.Contains(err.Error(), encoded) || (tc.key != "" && strings.Contains(err.Error(), tc.key)) {
				t.Fatal("private key included in error")
			}
		})
	}
	if _, err := loadSigningKey(encoded, "test-publisher", path); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseSignerRoundTripAndPreflight(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	if err := os.Mkdir("docs", 0700); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(publisherKey{"test-publisher", "Ed25519", base64.StdEncoding.EncodeToString(public)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("docs/release-signing-key.json", metadata, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMARI_RELEASE_SIGNING_KEY", base64.StdEncoding.EncodeToString(private))
	t.Setenv("KOMARI_RELEASE_SIGNING_KEY_ID", "test-publisher")
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"sign-helper-release.go", "--check"}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("helper.release.json"); !os.IsNotExist(err) {
		t.Fatal("preflight created a release manifest")
	}
	binary := []byte("test release artifact")
	if err := os.WriteFile("helper", binary, 0600); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"sign-helper-release.go", "helper", "1.2.85", runtime.GOOS, runtime.GOARCH}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("helper.release.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest hostops.ReleaseManifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	trust := &hostops.Trust{ReleaseKeys: []credentials.PinnedKey{{Algorithm: 1, KeyID: "test-publisher", Value: base64.StdEncoding.EncodeToString(public)}}}
	payload, err := hostops.VerifyRelease(trust, manifest, binary)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Version != "1.2.85" {
		t.Fatalf("unexpected release version: %s", payload.Version)
	}
	if _, err := hostops.VerifyRelease(trust, manifest, []byte("tampered")); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	manifest.Payload = append(manifest.Payload, ' ')
	if _, err := hostops.VerifyRelease(trust, manifest, binary); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}

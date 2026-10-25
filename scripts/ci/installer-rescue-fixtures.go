//go:build ignore

// Isolated synthetic signing identity for disposable installer CI only. It is
// never used for a release and no private key is written or printed.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Geteuid() != 0 || len(os.Args) != 3 || !strings.HasPrefix(os.Args[2], "komari-installer-") {
		panic("disposable root installer CI only")
	}
	fixture, service := os.Args[1], os.Args[2]
	public, private, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	trustPath := filepath.Join("/etc/komari/services", service+".trust.json")
	data, err := os.ReadFile(trustPath)
	must(err)
	var trust map[string]any
	must(json.Unmarshal(data, &trust))
	trust["release_keys"] = []any{map[string]any{"algorithm": 1, "key_id": "isolated-installer-publisher", "value": base64.StdEncoding.EncodeToString(public)}}
	data, err = json.Marshal(trust)
	must(err)
	must(os.WriteFile(trustPath, data, 0o644))
	for _, name := range []string{"komari-agent-rescue", "komari-agent-rescue-bad"} {
		data, err := os.ReadFile(filepath.Join(fixture, name))
		must(err)
		hash := sha256.Sum256(data)
		payload, err := json.Marshal(struct {
			Schema    string `json:"schema"`
			Component string `json:"component"`
			Version   string `json:"version"`
			OS        string `json:"os"`
			Arch      string `json:"arch"`
			SHA256    string `json:"sha256"`
		}{"komari.release.v1", "komari-agent-rescue", "fixture", runtime.GOOS, runtime.GOARCH, hex.EncodeToString(hash[:])})
		must(err)
		metadata, err := json.Marshal(map[string]any{"payload": payload, "key_id": "isolated-installer-publisher", "signature": ed25519.Sign(private, payload)})
		must(err)
		must(os.WriteFile(filepath.Join(fixture, name+".release.json"), metadata, 0o644))
	}
	fmt.Println("Prepared isolated synthetic installer release signatures")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

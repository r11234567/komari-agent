package hostcmd

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"runtime"
	"testing"
)

func testRelease(t *testing.T, key ed25519.PrivateKey, data []byte) hostops.ReleaseManifest {
	t.Helper()
	hash := sha256.Sum256(data)
	payload, err := json.Marshal(hostops.ReleasePayload{Schema: "komari.release.v1", Component: "komari-agent-rescue", Version: "ci-stage6", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: hex.EncodeToString(hash[:])})
	if err != nil {
		t.Fatal(err)
	}
	return hostops.ReleaseManifest{Payload: payload, KeyID: "stage6", Signature: ed25519.Sign(key, payload)}
}

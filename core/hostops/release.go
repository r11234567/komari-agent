package hostops

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"runtime"
	"time"
)

// ReleaseManifest is detached from the panel approval. The publisher signs
// canonical payload bytes, not a file name or a user-provided download URL.
type ReleaseManifest struct {
	Payload   []byte `json:"payload"`
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}
type ReleasePayload struct {
	Schema    string `json:"schema"`
	Component string `json:"component"`
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
}

func VerifyRelease(t *Trust, m ReleaseManifest, binary []byte) (ReleasePayload, error) {
	var p ReleasePayload
	ok := false
	for _, k := range t.ReleaseKeys {
		key, err := base64.StdEncoding.DecodeString(k.Value)
		if err == nil && len(key) == ed25519.PublicKeySize && k.Algorithm == 1 && k.KeyID == m.KeyID && !k.NotBefore.After(time.Now()) && (k.NotAfter == nil || time.Now().Before(*k.NotAfter)) && ed25519.Verify(key, m.Payload, m.Signature) {
			ok = true
		}
	}
	if !ok {
		return p, errors.New("helper release signature is not trusted")
	}
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return p, err
	}
	canonical, err := json.Marshal(p)
	if err != nil || string(canonical) != string(m.Payload) || p.Schema != "komari.release.v1" || p.Component != "komari-agent-rescue" || p.Version == "" || p.OS != runtime.GOOS || p.Arch != runtime.GOARCH {
		return p, errors.New("helper release platform, component or canonical schema mismatch")
	}
	hash := sha256.Sum256(binary)
	if p.SHA256 != hex.EncodeToString(hash[:]) {
		return p, errors.New("helper release SHA-256 mismatch")
	}
	return p, nil
}

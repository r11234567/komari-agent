package trafficwatch

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNFDumpPreservesDirectionIPv6AndUnknown(t *testing.T) {
	local := map[netip.Addr]bool{netip.MustParseAddr("192.0.2.1"): true, netip.MustParseAddr("2001:db8::1"): true}
	const times = "2026-11-26 09:30:06.604,2026-11-26 09:30:07.604,"
	input := times + "2001:db8:abcd:ef00:1234:2345:3456:4567,2001:db8::1,1234567\n" +
		times + "192.0.2.1,203.0.113.8,999\n" + times + "192.0.2.2,192.0.2.3,100\n"
	out, err := readFlows(strings.NewReader(input), time.Now(), local)
	if err != nil || out.totals() != (Traffic{RX: 1234567, TX: 999}) || out.Unknown != 100 {
		t.Fatalf("decoded %#v: %v", out, err)
	}
	if n := out.RX[netip.MustParseAddr("2001:db8:abcd:ef00:1234:2345:3456:4567")]; n != 1234567 {
		t.Fatal("lost full IPv6 address")
	}
}

func TestXrayPolicyRejectsUserStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray-policy.json")
	config := XrayConfig{PolicyFile: path}
	for _, user := range []string{"false", "true"} {
		body := `{"stats":{},"policy":{"system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true},"levels":{"0":{"statsUserOnline":` + user + `}}}}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := config.checkPolicy(); (err != nil) != (user == "true") {
			t.Fatalf("statsUserOnline=%s: %v", user, err)
		}
	}
}

func TestPruneKeepsUnexpiredSnapshotAndIgnoresOtherFiles(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	write := func(name string, expires time.Time) string {
		t.Helper()
		path := filepath.Join(dir, name)
		body, err := json.Marshal(snapshot{ExpiresAt: expires})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	expired := write("event-"+uuid.NewString()+".json", now)
	active := write("event-"+uuid.NewString()+".json", now.Add(time.Minute))
	other := write("event-unrelated.json", now)
	if err := pruneArchive(dir, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(expired); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired snapshot was retained: %v", err)
	}
	for _, path := range []string{active, other} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}
